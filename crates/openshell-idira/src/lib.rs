// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hardened, read-only client for an IDIRA/Conjur-compatible secrets service.
//!
//! This crate deliberately contains no `OpenShell` provider or proxy logic. It
//! authenticates the gateway and resolves one pre-provisioned variable. The
//! caller owns refresh cadence, credential storage, endpoint binding, and
//! sandbox delivery.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use reqwest::{Client, Response, StatusCode, Url, redirect};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

const MAX_AUTH_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SECRET_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_AUTH_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Configuration for one IDIRA deployment and gateway identity.
#[derive(Clone, Debug)]
pub struct IdiraClientConfig {
    pub base_url: String,
    pub account: String,
    pub login: String,
    pub api_key_path: PathBuf,
    pub ca_cert_path: Option<PathBuf>,
    pub timeout: Duration,
    pub auth_token_ttl: Duration,
}

/// Redacted failures returned by [`IdiraClient`].
#[derive(Debug, Error)]
pub enum IdiraError {
    #[error("invalid IDIRA configuration: {0}")]
    InvalidConfig(String),

    #[error("failed to read IDIRA client material: {0}")]
    Io(#[source] std::io::Error),

    #[error("IDIRA authentication was rejected")]
    AuthenticationRejected,

    #[error("IDIRA denied access to the requested secret")]
    Forbidden,

    #[error("the requested IDIRA secret was not found")]
    NotFound,

    #[error("IDIRA is temporarily unavailable")]
    Unavailable,

    #[error("IDIRA returned an invalid response: {0}")]
    InvalidResponse(&'static str),
}

#[derive(Clone)]
pub struct IdiraClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for IdiraClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdiraClient")
            .field("base_url", &self.inner.base_url)
            .field("account", &self.inner.account)
            .field("login", &self.inner.login)
            .finish_non_exhaustive()
    }
}

struct Inner {
    client: Client,
    base_url: Url,
    account: String,
    login: String,
    api_key_path: PathBuf,
    auth_token_ttl: Duration,
    cached_token: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    value: String,
    expires_at: Instant,
}

enum FetchAttemptError {
    Unauthorized,
    Public(IdiraError),
}

impl IdiraClient {
    /// Construct a reusable client. Authentication remains lazy so startup does
    /// not require the remote service to be available.
    pub fn new(config: IdiraClientConfig) -> Result<Self, IdiraError> {
        let base_url = validate_base_url(&config.base_url)?;
        require_nonempty("account", &config.account)?;
        require_nonempty("login", &config.login)?;
        if config.api_key_path.as_os_str().is_empty() {
            return Err(IdiraError::InvalidConfig(
                "api_key_path must not be empty".to_string(),
            ));
        }
        if config.timeout.is_zero() {
            return Err(IdiraError::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }
        if config.auth_token_ttl.is_zero() {
            return Err(IdiraError::InvalidConfig(
                "auth_token_ttl must be greater than zero".to_string(),
            ));
        }
        if config.auth_token_ttl > MAX_AUTH_TOKEN_TTL {
            return Err(IdiraError::InvalidConfig(
                "auth_token_ttl must not exceed 24 hours".to_string(),
            ));
        }

        let mut builder = Client::builder()
            .timeout(config.timeout)
            .redirect(redirect::Policy::none())
            .user_agent("openshell-idira-poc");
        if let Some(ca_cert_path) = config.ca_cert_path {
            let pem = std::fs::read(ca_cert_path)
                .map_err(|error| client_material_io_error("ca_certificate", error))?;
            let certificate = reqwest::Certificate::from_pem(&pem).map_err(|_| {
                warn!(
                    target: "openshell_idira",
                    operation = "parse_client_material",
                    material = "ca_certificate",
                    category = "invalid_pem",
                    "IDIRA client material is invalid"
                );
                IdiraError::InvalidConfig("ca_cert_path is not valid PEM".to_string())
            })?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().map_err(|error| {
            record_transport_diagnostic("build_client", "configure_transport", &error);
            IdiraError::InvalidConfig("failed to construct HTTP client".to_string())
        })?;

        Ok(Self {
            inner: Arc::new(Inner {
                client,
                base_url,
                account: config.account,
                login: config.login,
                api_key_path: config.api_key_path,
                auth_token_ttl: config.auth_token_ttl,
                cached_token: Mutex::new(None),
            }),
        })
    }

    /// Fetch one pre-provisioned secret. A rejected cached token is invalidated
    /// and authentication is retried exactly once.
    pub async fn fetch_secret(&self, reference: &str) -> Result<String, IdiraError> {
        require_nonempty("secret reference", reference)?;
        let first_token = self.access_token().await?;
        match self.fetch_once(reference, &first_token).await {
            Ok(value) => Ok(value),
            Err(FetchAttemptError::Public(error)) => Err(error),
            Err(FetchAttemptError::Unauthorized) => {
                self.invalidate_token(&first_token).await;
                let retry_token = self.access_token().await?;
                match self.fetch_once(reference, &retry_token).await {
                    Ok(value) => Ok(value),
                    Err(FetchAttemptError::Unauthorized) => {
                        self.invalidate_token(&retry_token).await;
                        Err(IdiraError::AuthenticationRejected)
                    }
                    Err(FetchAttemptError::Public(error)) => Err(error),
                }
            }
        }
    }

    async fn access_token(&self) -> Result<String, IdiraError> {
        let mut cached = self.inner.cached_token.lock().await;
        if let Some(token) = cached.as_ref()
            && Instant::now() < token.expires_at
        {
            return Ok(token.value.clone());
        }

        let api_key = tokio::fs::read_to_string(&self.inner.api_key_path)
            .await
            .map_err(|error| client_material_io_error("api_key", error))?;
        let api_key = api_key.trim_end_matches(['\r', '\n']);
        if api_key.is_empty() {
            return Err(IdiraError::InvalidConfig(
                "api_key_path contains an empty API key".to_string(),
            ));
        }

        let response = self
            .inner
            .client
            .post(self.endpoint(&[
                "authn",
                &self.inner.account,
                &self.inner.login,
                "authenticate",
            ])?)
            .header(ACCEPT_ENCODING, "base64")
            .header(CONTENT_TYPE, "text/plain")
            .body(api_key.to_owned())
            .send()
            .await
            .map_err(|error| transport_unavailable("authenticate", "send_request", &error))?;

        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(IdiraError::AuthenticationRejected);
        }
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(IdiraError::Unavailable);
        }
        if !status.is_success() {
            return Err(IdiraError::InvalidResponse(
                "unexpected authentication status",
            ));
        }

        let token_bytes = read_bounded(response, MAX_AUTH_RESPONSE_BYTES, "authenticate").await?;
        let token = String::from_utf8(token_bytes)
            .map_err(|_| IdiraError::InvalidResponse("authentication token is not UTF-8"))?;
        let token = token.trim_matches(|character: char| character.is_ascii_whitespace());
        if token.is_empty() {
            return Err(IdiraError::InvalidResponse("authentication token is empty"));
        }

        let token = token.to_string();
        let cache_ttl = self
            .inner
            .auth_token_ttl
            .saturating_sub(self.inner.auth_token_ttl / 10);
        let expires_at = Instant::now().checked_add(cache_ttl).ok_or_else(|| {
            IdiraError::InvalidConfig("auth_token_ttl exceeds the platform clock".to_string())
        })?;
        *cached = Some(CachedToken {
            value: token.clone(),
            expires_at,
        });
        Ok(token)
    }

    async fn invalidate_token(&self, rejected: &str) {
        let mut cached = self.inner.cached_token.lock().await;
        if cached.as_ref().is_some_and(|token| token.value == rejected) {
            *cached = None;
        }
    }

    async fn fetch_once(
        &self,
        reference: &str,
        access_token: &str,
    ) -> Result<String, FetchAttemptError> {
        let mut authorization = HeaderValue::from_str(&format!("Token token=\"{access_token}\""))
            .map_err(|_| {
            FetchAttemptError::Public(IdiraError::InvalidResponse(
                "authentication token is not a valid header value",
            ))
        })?;
        authorization.set_sensitive(true);

        let response = self
            .inner
            .client
            .get(
                self.endpoint(&["secrets", &self.inner.account, "variable", reference])
                    .map_err(FetchAttemptError::Public)?,
            )
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(|error| {
                FetchAttemptError::Public(transport_unavailable(
                    "fetch_secret",
                    "send_request",
                    &error,
                ))
            })?;

        match response.status() {
            StatusCode::OK => {
                let bytes = read_bounded(response, MAX_SECRET_RESPONSE_BYTES, "fetch_secret")
                    .await
                    .map_err(FetchAttemptError::Public)?;
                if bytes.is_empty() {
                    return Err(FetchAttemptError::Public(IdiraError::InvalidResponse(
                        "secret value is empty",
                    )));
                }
                String::from_utf8(bytes).map_err(|_| {
                    FetchAttemptError::Public(IdiraError::InvalidResponse(
                        "secret value is not UTF-8",
                    ))
                })
            }
            StatusCode::UNAUTHORIZED => Err(FetchAttemptError::Unauthorized),
            StatusCode::FORBIDDEN => Err(FetchAttemptError::Public(IdiraError::Forbidden)),
            StatusCode::NOT_FOUND => Err(FetchAttemptError::Public(IdiraError::NotFound)),
            StatusCode::TOO_MANY_REQUESTS => {
                Err(FetchAttemptError::Public(IdiraError::Unavailable))
            }
            status if status.is_server_error() => {
                Err(FetchAttemptError::Public(IdiraError::Unavailable))
            }
            _ => Err(FetchAttemptError::Public(IdiraError::InvalidResponse(
                "unexpected secret response status",
            ))),
        }
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, IdiraError> {
        let mut url = self.inner.base_url.clone();
        {
            let mut path = url.path_segments_mut().map_err(|()| {
                IdiraError::InvalidConfig("base_url cannot accept path segments".to_string())
            })?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }
}

fn validate_base_url(value: &str) -> Result<Url, IdiraError> {
    let url = Url::parse(value)
        .map_err(|_| IdiraError::InvalidConfig("base_url must be absolute".to_string()))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(IdiraError::InvalidConfig(
            "base_url must not contain user information".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(IdiraError::InvalidConfig(
            "base_url must not contain a query or fragment".to_string(),
        ));
    }
    match url.scheme() {
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(IdiraError::InvalidConfig(
                "base_url must use HTTPS except for loopback tests".to_string(),
            ));
        }
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn require_nonempty(name: &str, value: &str) -> Result<(), IdiraError> {
    if value.is_empty() {
        return Err(IdiraError::InvalidConfig(format!(
            "{name} must not be empty"
        )));
    }
    Ok(())
}

fn client_material_io_error(material: &'static str, error: std::io::Error) -> IdiraError {
    let kind = io_error_category(error.kind());
    warn!(
        target: "openshell_idira",
        operation = "read_client_material",
        material,
        category = kind,
        "IDIRA client material read failed"
    );

    // Keep the public error useful without carrying the original OS message,
    // which can contain filesystem paths on some platforms.
    IdiraError::Io(std::io::Error::new(
        error.kind(),
        format!("{material} read failed ({kind})"),
    ))
}

fn io_error_category(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::InvalidData => "invalid_data",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        std::io::ErrorKind::IsADirectory => "is_a_directory",
        std::io::ErrorKind::Interrupted => "interrupted",
        std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    }
}

fn transport_unavailable(
    operation: &'static str,
    phase: &'static str,
    error: &reqwest::Error,
) -> IdiraError {
    record_transport_diagnostic(operation, phase, error);
    IdiraError::Unavailable
}

fn record_transport_diagnostic(
    operation: &'static str,
    phase: &'static str,
    error: &reqwest::Error,
) {
    warn!(
        target: "openshell_idira",
        operation,
        phase,
        category = transport_error_category(error),
        "IDIRA transport failed"
    );
}

fn transport_error_category(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_builder() {
        "builder"
    } else if error.is_request() {
        "request"
    } else if error.is_status() {
        "status"
    } else {
        "other"
    }
}

async fn read_bounded(
    mut response: Response,
    limit: usize,
    operation: &'static str,
) -> Result<Vec<u8>, IdiraError> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
    {
        return Err(IdiraError::InvalidResponse("response body is too large"));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_unavailable(operation, "read_response_body", &error))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(IdiraError::InvalidResponse("response body is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use tempfile::NamedTempFile;
    use tokio::sync::Barrier;
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn api_key_file(value: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create API key file");
        std::fs::write(file.path(), value).expect("write API key file");
        file
    }

    fn config(server: &MockServer, api_key: &NamedTempFile) -> IdiraClientConfig {
        IdiraClientConfig {
            base_url: server.uri(),
            account: "myorg".to_string(),
            login: "host/openshell-gateway".to_string(),
            api_key_path: api_key.path().to_path_buf(),
            ca_cert_path: None,
            timeout: Duration::from_secs(5),
            auth_token_ttl: Duration::from_secs(300),
        }
    }

    async fn mount_auth(server: &MockServer, token: &'static str) {
        Mock::given(method("POST"))
            .and(path("/authn/myorg/host%2Fopenshell-gateway/authenticate"))
            .and(header("accept-encoding", "base64"))
            .and(header("content-type", "text/plain"))
            .and(body_string("api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(token))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn validates_transport_and_base_url_shape() {
        let api_key = api_key_file("api-key");
        let base = IdiraClientConfig {
            base_url: "http://idira.example.com".to_string(),
            account: "account".to_string(),
            login: "login".to_string(),
            api_key_path: api_key.path().to_path_buf(),
            ca_cert_path: None,
            timeout: Duration::from_secs(1),
            auth_token_ttl: Duration::from_secs(1),
        };
        assert!(matches!(
            IdiraClient::new(base.clone()),
            Err(IdiraError::InvalidConfig(_))
        ));
        for invalid in [
            "https://user:password@idira.example.com",
            "https://idira.example.com?token=secret",
            "https://idira.example.com#fragment",
        ] {
            let mut config = base.clone();
            config.base_url = invalid.to_string();
            assert!(matches!(
                IdiraClient::new(config),
                Err(IdiraError::InvalidConfig(_))
            ));
        }
        let mut excessive_ttl = base;
        excessive_ttl.base_url = "https://idira.example.com".to_string();
        excessive_ttl.auth_token_ttl = MAX_AUTH_TOKEN_TTL + Duration::from_secs(1);
        assert!(matches!(
            IdiraClient::new(excessive_ttl),
            Err(IdiraError::InvalidConfig(_))
        ));
    }

    #[test]
    fn ca_file_errors_report_only_safe_material_and_io_categories() {
        let api_key = api_key_file("api-key");
        let directory = tempfile::tempdir().expect("create temporary directory");
        let missing_ca = directory.path().join("sensitive-ca-filename.pem");
        let config = IdiraClientConfig {
            base_url: "https://idira.example.com".to_string(),
            account: "account".to_string(),
            login: "login".to_string(),
            api_key_path: api_key.path().to_path_buf(),
            ca_cert_path: Some(missing_ca.clone()),
            timeout: Duration::from_secs(1),
            auth_token_ttl: Duration::from_secs(1),
        };

        let error = IdiraClient::new(config).expect_err("missing CA file should fail");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("ca_certificate read failed (not_found)"));
        assert!(!display.contains("sensitive-ca-filename"));
        assert!(!debug.contains("sensitive-ca-filename"));
        assert!(!display.contains(&missing_ca.display().to_string()));
        assert!(!debug.contains(&missing_ca.display().to_string()));
    }

    #[tokio::test]
    async fn api_key_file_errors_report_only_safe_material_and_io_categories() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let missing_key = directory.path().join("sensitive-api-key-filename");
        let client = IdiraClient::new(IdiraClientConfig {
            base_url: "http://127.0.0.1:1".to_string(),
            account: "account".to_string(),
            login: "login".to_string(),
            api_key_path: missing_key.clone(),
            ca_cert_path: None,
            timeout: Duration::from_secs(1),
            auth_token_ttl: Duration::from_secs(1),
        })
        .expect("client construction should not read the API key");

        let error = client
            .fetch_secret("sensitive-reference")
            .await
            .expect_err("missing API key file should fail before transport");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("api_key read failed (not_found)"));
        for sensitive in [
            "sensitive-api-key-filename",
            "sensitive-reference",
            &missing_key.display().to_string(),
        ] {
            assert!(!display.contains(sensitive));
            assert!(!debug.contains(sensitive));
        }
    }

    #[tokio::test]
    async fn transport_timeouts_remain_redacted_and_retryable() {
        let server = MockServer::start().await;
        let api_key = api_key_file("sensitive-api-key-value");
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_string("SENSITIVE-TOKEN"),
            )
            .mount(&server)
            .await;

        let transport_error = Client::builder()
            .timeout(Duration::from_millis(5))
            .build()
            .expect("HTTP client")
            .post(server.uri())
            .send()
            .await
            .expect_err("delayed response should exceed the request timeout");
        assert_eq!(transport_error_category(&transport_error), "timeout");

        let mut config = config(&server, &api_key);
        config.timeout = Duration::from_millis(5);
        let client = IdiraClient::new(config).expect("client");

        let error = client
            .fetch_secret("sensitive-reference")
            .await
            .expect_err("authentication request should time out");
        assert!(matches!(error, IdiraError::Unavailable));
        let rendered = format!("{error:?} {error}");
        for sensitive in [
            "sensitive-api-key-value",
            "SENSITIVE-TOKEN",
            "sensitive-reference",
            &server.uri(),
        ] {
            assert!(!rendered.contains(sensitive));
        }
    }

    #[tokio::test]
    async fn authenticates_and_preserves_secret_exactly() {
        let server = MockServer::start().await;
        let api_key = api_key_file("api-key\n");
        mount_auth(&server, "BASE64TOKEN\n").await;
        Mock::given(method("GET"))
            .and(path("/secrets/myorg/variable/prod%2Fanthropic%2Fapi-key"))
            .and(header("authorization", "Token token=\"BASE64TOKEN\""))
            .respond_with(ResponseTemplate::new(200).set_body_string("  value with space  \n"))
            .expect(1)
            .mount(&server)
            .await;

        let client = IdiraClient::new(config(&server, &api_key)).expect("client");
        let value = client
            .fetch_secret("prod/anthropic/api-key")
            .await
            .expect("secret");
        assert_eq!(value, "  value with space  \n");
    }

    #[tokio::test]
    async fn shares_one_authentication_across_concurrent_fetches() {
        let server = MockServer::start().await;
        let api_key = api_key_file("api-key");
        mount_auth(&server, "TOKEN").await;
        Mock::given(method("GET"))
            .and(path("/secrets/myorg/variable/shared"))
            .and(header("authorization", "Token token=\"TOKEN\""))
            .respond_with(ResponseTemplate::new(200).set_body_string("value"))
            .expect(8)
            .mount(&server)
            .await;

        let client = IdiraClient::new(config(&server, &api_key)).expect("client");
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let client = client.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                client.fetch_secret("shared").await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.expect("task").expect("secret"), "value");
        }
    }

    #[derive(Clone)]
    struct RotatingAuth {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Respond for RotatingAuth {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_string(if call == 0 { "OLD" } else { "NEW" })
        }
    }

    #[tokio::test]
    async fn retries_once_after_rejected_cached_token() {
        let server = MockServer::start().await;
        let api_key = api_key_file("api-key");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/authn/myorg/host%2Fopenshell-gateway/authenticate"))
            .respond_with(RotatingAuth {
                calls: calls.clone(),
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/secrets/myorg/variable/value"))
            .and(header("authorization", "Token token=\"OLD\""))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/secrets/myorg/variable/value"))
            .and(header("authorization", "Token token=\"NEW\""))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;

        let client = IdiraClient::new(config(&server, &api_key)).expect("client");
        assert_eq!(
            client.fetch_secret("value").await.expect("secret"),
            "secret"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn maps_secret_statuses_without_response_bodies() {
        for (status, expected) in [(403, "forbidden"), (404, "not-found"), (500, "unavailable")] {
            let server = MockServer::start().await;
            let api_key = api_key_file("api-key");
            mount_auth(&server, "TOKEN").await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_string("sensitive backend body"),
                )
                .mount(&server)
                .await;
            let error = IdiraClient::new(config(&server, &api_key))
                .expect("client")
                .fetch_secret("value")
                .await
                .expect_err("status should fail");
            match (expected, error) {
                ("forbidden", IdiraError::Forbidden)
                | ("not-found", IdiraError::NotFound)
                | ("unavailable", IdiraError::Unavailable) => {}
                (_, other) => panic!("unexpected error: {other}"),
            }
        }
    }

    #[tokio::test]
    async fn rejects_empty_and_oversized_responses() {
        let server = MockServer::start().await;
        let api_key = api_key_file("api-key");
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        let error = IdiraClient::new(config(&server, &api_key))
            .expect("client")
            .fetch_secret("value")
            .await
            .expect_err("empty token should fail");
        assert!(matches!(error, IdiraError::InvalidResponse(_)));

        let server = MockServer::start().await;
        mount_auth(&server, "TOKEN").await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::new()))
            .mount(&server)
            .await;
        let error = IdiraClient::new(config(&server, &api_key))
            .expect("client")
            .fetch_secret("value")
            .await
            .expect_err("empty secret should fail");
        assert!(matches!(error, IdiraError::InvalidResponse(_)));

        let server = MockServer::start().await;
        mount_auth(&server, "TOKEN").await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b'x';
                MAX_SECRET_RESPONSE_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;
        let error = IdiraClient::new(config(&server, &api_key))
            .expect("client")
            .fetch_secret("value")
            .await
            .expect_err("oversized secret should fail");
        assert!(matches!(error, IdiraError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn does_not_follow_authentication_redirects() {
        let server = MockServer::start().await;
        let api_key = api_key_file("api-key");
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "/credential-capture"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/credential-capture"))
            .respond_with(ResponseTemplate::new(200).set_body_string("TOKEN"))
            .expect(0)
            .mount(&server)
            .await;
        let error = IdiraClient::new(config(&server, &api_key))
            .expect("client")
            .fetch_secret("value")
            .await
            .expect_err("redirect should not be followed");
        assert!(matches!(error, IdiraError::InvalidResponse(_)));
    }
}
