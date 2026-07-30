#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use percent_encoding::percent_decode;
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::lookup_host;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_HTTP_REQUEST_BYTES: usize = 512 * 1024;
pub const MAX_HTTP_RESPONSE_BYTES: usize = 512 * 1024;
const MIN_BEARER_BYTES: usize = 8;
const MAX_BEARER_BYTES: usize = 8 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "DELETE")]
    Delete,
}

impl HttpMethod {
    fn as_reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Patch => reqwest::Method::PATCH,
            Self::Delete => reqwest::Method::DELETE,
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        })
    }
}

impl FromStr for HttpMethod {
    type Err = BrokerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            _ => Err(BrokerError::UnsupportedMethod),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpContentType {
    Json,
    Text,
    Form,
}

impl HttpContentType {
    fn as_header(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Text => "text/plain; charset=utf-8",
            Self::Form => "application/x-www-form-urlencoded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HttpConstraint {
    pub host: String,
    pub port: u16,
    pub methods: Vec<HttpMethod>,
    pub path_prefix: String,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}

impl HttpConstraint {
    pub fn validate(&self) -> Result<(), BrokerError> {
        let normalized_host = normalize_host(&self.host)?;
        if normalized_host != self.host || self.port == 0 {
            return Err(BrokerError::InvalidConstraint);
        }
        if self.methods.is_empty()
            || self.methods.len() > 5
            || self.methods.iter().collect::<BTreeSet<_>>().len() != self.methods.len()
        {
            return Err(BrokerError::InvalidConstraint);
        }
        if !valid_path_prefix(&self.path_prefix) {
            return Err(BrokerError::InvalidConstraint);
        }
        if self.max_request_bytes == 0
            || self.max_request_bytes > MAX_HTTP_REQUEST_BYTES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_HTTP_RESPONSE_BYTES
        {
            return Err(BrokerError::InvalidConstraint);
        }
        Ok(())
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub body: Vec<u8>,
    pub content_type: Option<HttpContentType>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("url", &self.url)
            .field("method", &self.method)
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .field("content_type", &self.content_type)
            .finish()
    }
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .finish()
    }
}

pub struct PreparedHttpRequest {
    url: Url,
    method: HttpMethod,
    body: Zeroizing<Vec<u8>>,
    content_type: Option<HttpContentType>,
    constraint: HttpConstraint,
    credential: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PreparedHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedHttpRequest")
            .field("url", &self.url)
            .field("method", &self.method)
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .field("content_type", &self.content_type)
            .field("constraint", &self.constraint)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum BrokerError {
    #[error("HTTP broker constraint is invalid")]
    InvalidConstraint,
    #[error("URL is invalid")]
    InvalidUrl,
    #[error("only HTTPS URLs are allowed")]
    InsecureScheme,
    #[error("URL credentials are forbidden")]
    EmbeddedCredentials,
    #[error("URL fragments are forbidden")]
    FragmentDenied,
    #[error("target host or port is not allowed")]
    OriginDenied,
    #[error("HTTP method is not supported")]
    UnsupportedMethod,
    #[error("HTTP method is not allowed")]
    MethodDenied,
    #[error("URL path is not allowed")]
    PathDenied,
    #[error("HTTP request body is not allowed")]
    BodyDenied,
    #[error("HTTP request is too large")]
    RequestTooLarge,
    #[error("bearer credential is invalid")]
    InvalidCredential,
    #[error("target resolution failed")]
    ResolutionFailed,
    #[error("target resolves to a non-public address")]
    PrivateAddressDenied,
    #[error("HTTP request failed")]
    NetworkFailure,
    #[error("HTTP redirect was denied with status {0}")]
    RedirectDenied(u16),
    #[error("HTTP provider rejected the request with status {0}")]
    ProviderRejected(u16),
    #[error("HTTP response content type is not allowed")]
    ResponseTypeDenied,
    #[error("HTTP response is too large")]
    ResponseTooLarge,
    #[error("HTTP response is not valid UTF-8")]
    InvalidResponseEncoding,
    #[error("HTTP response may contain the credential")]
    CredentialEchoDenied,
}

pub fn normalize_constraint(mut constraint: HttpConstraint) -> Result<HttpConstraint, BrokerError> {
    constraint.host = normalize_host(&constraint.host)?;
    constraint.methods.sort_unstable();
    constraint.methods.dedup();
    constraint.validate()?;
    Ok(constraint)
}

pub fn validate_http_request(
    request: &HttpRequest,
    constraint: &HttpConstraint,
) -> Result<Url, BrokerError> {
    constraint.validate()?;
    if request.url.trim() != request.url || request.url.contains('\\') {
        return Err(BrokerError::InvalidUrl);
    }
    let url = Url::parse(&request.url).map_err(|_| BrokerError::InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(BrokerError::InsecureScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BrokerError::EmbeddedCredentials);
    }
    if url.fragment().is_some() {
        return Err(BrokerError::FragmentDenied);
    }
    if url.host_str() != Some(constraint.host.as_str())
        || url.port_or_known_default() != Some(constraint.port)
    {
        return Err(BrokerError::OriginDenied);
    }
    if !constraint.methods.contains(&request.method) {
        return Err(BrokerError::MethodDenied);
    }
    if !path_is_allowed(url.path(), &constraint.path_prefix) || has_dangerous_path_segment(&url) {
        return Err(BrokerError::PathDenied);
    }
    if request.body.len() > constraint.max_request_bytes {
        return Err(BrokerError::RequestTooLarge);
    }
    if request.body.is_empty() && request.content_type.is_some()
        || !request.body.is_empty() && request.content_type.is_none()
        || matches!(request.method, HttpMethod::Get | HttpMethod::Delete)
            && !request.body.is_empty()
    {
        return Err(BrokerError::BodyDenied);
    }
    Ok(url)
}

pub fn prepare_bearer_request(
    mut request: HttpRequest,
    constraint: HttpConstraint,
    credential: Vec<u8>,
) -> Result<PreparedHttpRequest, BrokerError> {
    let credential = Zeroizing::new(credential);
    let url = validate_http_request(&request, &constraint)?;
    if !valid_bearer_credential(&credential) {
        return Err(BrokerError::InvalidCredential);
    }
    Ok(PreparedHttpRequest {
        url,
        method: request.method,
        body: Zeroizing::new(std::mem::take(&mut request.body)),
        content_type: request.content_type,
        constraint,
        credential,
    })
}

pub async fn execute(request: PreparedHttpRequest) -> Result<HttpResponse, BrokerError> {
    tokio::time::timeout(REQUEST_TIMEOUT, async move {
        let host = request
            .url
            .host_str()
            .ok_or(BrokerError::InvalidUrl)?
            .to_owned();
        let addresses = resolve_public_addresses(&host, request.constraint.port).await?;
        execute_with_addresses(request, &host, &addresses).await
    })
    .await
    .map_err(|_| BrokerError::NetworkFailure)?
}

async fn execute_with_addresses(
    request: PreparedHttpRequest,
    host: &str,
    addresses: &[SocketAddr],
) -> Result<HttpResponse, BrokerError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .resolve_to_addrs(host, addresses)
        .build()
        .map_err(|_| BrokerError::NetworkFailure)?;
    execute_with_client(request, client).await
}

async fn execute_with_client(
    request: PreparedHttpRequest,
    client: reqwest::Client,
) -> Result<HttpResponse, BrokerError> {
    let mut authorization = Zeroizing::new(Vec::with_capacity(7 + request.credential.len()));
    authorization.extend_from_slice(b"Bearer ");
    authorization.extend_from_slice(&request.credential);
    let mut authorization_header =
        HeaderValue::from_bytes(&authorization).map_err(|_| BrokerError::InvalidCredential)?;
    authorization_header.set_sensitive(true);

    let mut builder = client
        .request(request.method.as_reqwest(), request.url.clone())
        .header(AUTHORIZATION, authorization_header);
    if let Some(content_type) = request.content_type {
        builder = builder.header(CONTENT_TYPE, content_type.as_header());
    }
    if !request.body.is_empty() {
        builder = builder.body(request.body.to_vec());
    }

    let mut response = builder
        .send()
        .await
        .map_err(|_| BrokerError::NetworkFailure)?;
    let status = response.status();
    if status.is_redirection() {
        return Err(BrokerError::RedirectDenied(status.as_u16()));
    }
    if !status.is_success() {
        return Err(BrokerError::ProviderRejected(status.as_u16()));
    }

    let content_type = accepted_content_type(response.headers().get(CONTENT_TYPE))?;
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > request.constraint.max_response_bytes)
    {
        return Err(BrokerError::ResponseTooLarge);
    }

    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrokerError::NetworkFailure)?
    {
        if body.len().saturating_add(chunk.len()) > request.constraint.max_response_bytes {
            return Err(BrokerError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    if !body.is_empty() && content_type.is_none() {
        return Err(BrokerError::ResponseTypeDenied);
    }
    if response_contains_credential(&body, &request.credential) {
        return Err(BrokerError::CredentialEchoDenied);
    }
    let text =
        String::from_utf8(body.to_vec()).map_err(|_| BrokerError::InvalidResponseEncoding)?;
    Ok(HttpResponse {
        status: status.as_u16(),
        content_type,
        body: text,
    })
}

fn normalize_host(host: &str) -> Result<String, BrokerError> {
    if host.trim() != host || host.is_empty() || host.contains(['/', '\\', '@', '#', '?']) {
        return Err(BrokerError::InvalidConstraint);
    }
    let candidate = format!("https://{host}/");
    let url = Url::parse(&candidate).map_err(|_| BrokerError::InvalidConstraint)?;
    url.host_str()
        .map(str::to_owned)
        .ok_or(BrokerError::InvalidConstraint)
}

fn valid_path_prefix(prefix: &str) -> bool {
    prefix.starts_with('/')
        && !prefix.contains(['?', '#', '\\', '%'])
        && !prefix
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
}

fn path_is_allowed(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| prefix.ends_with('/') || suffix.starts_with('/'))
}

fn has_dangerous_path_segment(url: &Url) -> bool {
    url.path().split('/').any(|segment| {
        let decoded = percent_decode(segment.as_bytes()).collect::<Vec<_>>();
        decoded == b"."
            || decoded == b".."
            || decoded
                .iter()
                .any(|byte| matches!(byte, b'/' | b'\\' | 0..=31 | 127))
    })
}

fn valid_bearer_credential(credential: &[u8]) -> bool {
    (MIN_BEARER_BYTES..=MAX_BEARER_BYTES).contains(&credential.len())
        && credential.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

fn accepted_content_type(value: Option<&HeaderValue>) -> Result<Option<String>, BrokerError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| BrokerError::ResponseTypeDenied)?;
    let media_type = raw
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let allowed = media_type == "application/json"
        || media_type.starts_with("application/") && media_type.ends_with("+json")
        || media_type.starts_with("text/");
    if !allowed || media_type.len() > 127 {
        return Err(BrokerError::ResponseTypeDenied);
    }
    Ok(Some(media_type))
}

fn response_contains_credential(body: &[u8], credential: &[u8]) -> bool {
    let mut patterns = Zeroizing::new(Vec::<Vec<u8>>::new());
    patterns.push(credential.to_vec());
    patterns.push(
        base64::engine::general_purpose::STANDARD
            .encode(credential)
            .into_bytes(),
    );
    patterns.push(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(credential)
            .into_bytes(),
    );
    let mut json_escaped = Vec::with_capacity(credential.len());
    for byte in credential {
        if *byte == b'/' {
            json_escaped.push(b'\\');
        }
        json_escaped.push(*byte);
    }
    patterns.push(json_escaped);

    if patterns.iter().any(|pattern| contains_bytes(body, pattern)) {
        return true;
    }
    let decoded = Zeroizing::new(percent_decode(body).collect::<Vec<_>>());
    if patterns
        .iter()
        .any(|pattern| contains_bytes(&decoded, pattern))
    {
        return true;
    }
    let json_decoded = decode_json_ascii_escapes(body);
    patterns
        .iter()
        .any(|pattern| contains_bytes(&json_decoded, pattern))
}

fn decode_json_ascii_escapes(body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(body.len()));
    let mut index = 0;
    while index < body.len() {
        if body[index] == b'\\' && body.get(index + 1) == Some(&b'/') {
            decoded.push(b'/');
            index += 2;
            continue;
        }
        if body[index] == b'\\'
            && body.get(index + 1) == Some(&b'u')
            && body.get(index + 2..index + 4) == Some(b"00")
            && let Some(encoded) = body.get(index + 4..index + 6)
            && let (Some(high), Some(low)) = (hex_value(encoded[0]), hex_value(encoded[1]))
        {
            decoded.push((high << 4) | low);
            index += 6;
            continue;
        }
        decoded.push(body[index]);
        index += 1;
    }
    decoded
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

async fn resolve_public_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, BrokerError> {
    let mut addresses = lookup_host((host, port))
        .await
        .map_err(|_| BrokerError::ResolutionFailed)?
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(BrokerError::ResolutionFailed);
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(BrokerError::PrivateAddressDenied);
    }
    Ok(addresses)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !matches!(
        octets,
        [0 | 10 | 127 | 224..=255, ..]
            | [100, 64..=127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0 | 2, ..]
            | [192, 88, 99, ..]
            | [192, 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, ..]
            | [203, 0, 113, ..]
    )
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    // Reject locally scoped and IANA special-purpose ranges conservatively.
    if segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xffc0 == 0xfec0
        || segments[0] == 0x2001 && segments[1] & 0xfe00 == 0
        || segments[0] == 0x2001 && segments[1] == 0x0db8
        || segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0
        || segments[0] == 0x2002
        || segments[0] == 0x3fff && segments[1] & 0xf000 == 0
    {
        return false;
    }
    let octets = address.octets();
    if octets[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        return is_public_ipv4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    segments[0] & 0xe000 == 0x2000
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };

    fn openai() -> HttpConstraint {
        HttpConstraint {
            host: "api.openai.com".into(),
            port: 443,
            methods: vec![HttpMethod::Post],
            path_prefix: "/v1".into(),
            max_request_bytes: 16 * 1024,
            max_response_bytes: 1024 * 1024 / 2,
        }
    }

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            url: url.into(),
            method: HttpMethod::Post,
            body: br#"{"model":"gpt"}"#.to_vec(),
            content_type: Some(HttpContentType::Json),
        }
    }

    #[test]
    fn accepts_exact_https_origin_method_and_path() {
        assert!(
            validate_http_request(&request("https://api.openai.com/v1/responses"), &openai())
                .is_ok()
        );
    }

    #[test]
    fn rejects_cross_origin_port_and_insecure_targets() {
        assert_eq!(
            validate_http_request(&request("https://example.com/v1/responses"), &openai()),
            Err(BrokerError::OriginDenied)
        );
        assert_eq!(
            validate_http_request(
                &request("https://api.openai.com:8443/v1/responses"),
                &openai()
            ),
            Err(BrokerError::OriginDenied)
        );
        assert_eq!(
            validate_http_request(&request("http://api.openai.com/v1/responses"), &openai()),
            Err(BrokerError::InsecureScheme)
        );
    }

    #[test]
    fn path_prefix_uses_segment_boundaries() {
        assert_eq!(
            validate_http_request(&request("https://api.openai.com/v11/responses"), &openai()),
            Err(BrokerError::PathDenied)
        );
        assert_eq!(
            validate_http_request(
                &request("https://api.openai.com/v1/%2e%2e/admin"),
                &openai()
            ),
            Err(BrokerError::PathDenied)
        );
        assert_eq!(
            validate_http_request(&request("https://api.openai.com/v1/a%2fb"), &openai()),
            Err(BrokerError::PathDenied)
        );
    }

    #[test]
    fn validates_body_shape_and_limits() {
        let mut get = request("https://api.openai.com/v1/models");
        get.method = HttpMethod::Get;
        let mut constraint = openai();
        constraint.methods.push(HttpMethod::Get);
        assert_eq!(
            validate_http_request(&get, &constraint),
            Err(BrokerError::BodyDenied)
        );
        get.body.clear();
        get.content_type = None;
        assert!(validate_http_request(&get, &constraint).is_ok());
        let mut too_large = request("https://api.openai.com/v1/responses");
        too_large.body = vec![0; constraint.max_request_bytes + 1];
        assert_eq!(
            validate_http_request(&too_large, &constraint),
            Err(BrokerError::RequestTooLarge)
        );
    }

    #[test]
    fn prepared_request_debug_is_redacted() {
        let prepared = prepare_bearer_request(
            request("https://api.openai.com/v1/responses"),
            openai(),
            b"secret-token".to_vec(),
        )
        .unwrap();
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("model"));
    }

    #[test]
    fn response_firewall_blocks_raw_encoded_and_escaped_credentials() {
        let credential = b"secret/token";
        assert!(response_contains_credential(b"secret/token", credential));
        assert!(response_contains_credential(b"secret%2Ftoken", credential));
        assert!(response_contains_credential(b"secret\\/token", credential));
        assert!(response_contains_credential(
            b"\\u0073\\u0065\\u0063\\u0072\\u0065\\u0074\\u002Ftoken",
            credential
        ));
        let encoded = base64::engine::general_purpose::STANDARD.encode(credential);
        assert!(response_contains_credential(encoded.as_bytes(), credential));
        assert!(!response_contains_credential(b"safe response", credential));
    }

    #[test]
    fn accepts_only_bounded_b64token_credentials() {
        assert!(valid_bearer_credential(b"abcd-1234._~+/="));
        assert!(!valid_bearer_credential(b"short"));
        assert!(!valid_bearer_credential(b"contains space"));
        assert!(!valid_bearer_credential(b"contains\nnewline"));
    }

    #[test]
    fn public_address_filter_is_fail_closed() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001::1",
            "2001:db8::1",
            "2002:c0a8::1",
            "3fff::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn normalizes_unicode_hosts_and_constraint_methods() {
        let mut constraint = openai();
        constraint.host = "BÜCHER.example".into();
        constraint.methods.push(HttpMethod::Post);
        let normalized = normalize_constraint(constraint).unwrap();
        assert_eq!(normalized.host, "xn--bcher-kva.example");
        assert_eq!(normalized.methods, vec![HttpMethod::Post]);
    }

    #[tokio::test]
    async fn local_tls_round_trip_sends_bearer_and_returns_safe_json() {
        let credential = b"local-test-token";
        let (address, server) = tls_server(br#"{"ok":true}"#, credential).await;
        let request = local_request(address, credential);
        let response = execute_with_client(request, local_test_client("localhost", address))
            .await
            .expect("broker response");
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type.as_deref(), Some("application/json"));
        assert_eq!(response.body, r#"{"ok":true}"#);
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn local_tls_round_trip_blocks_provider_credential_echo() {
        let credential = b"echo-test-token";
        let (address, server) = tls_server(credential, credential).await;
        let request = local_request(address, credential);
        assert_eq!(
            execute_with_client(request, local_test_client("localhost", address)).await,
            Err(BrokerError::CredentialEchoDenied)
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn local_tls_round_trip_suppresses_rejected_response_payloads() {
        let credential = b"rejected-test-token";
        let (address, server) = tls_server_response(
            "302 Found",
            "text/plain",
            "Location: https://attacker.example/leak\r\n",
            credential,
            credential,
        )
        .await;
        assert_eq!(
            execute_with_client(
                local_request(address, credential),
                local_test_client("localhost", address)
            )
            .await,
            Err(BrokerError::RedirectDenied(302))
        );
        server.await.expect("redirect server");

        let (address, server) =
            tls_server_response("401 Unauthorized", "text/plain", "", credential, credential).await;
        assert_eq!(
            execute_with_client(
                local_request(address, credential),
                local_test_client("localhost", address)
            )
            .await,
            Err(BrokerError::ProviderRejected(401))
        );
        server.await.expect("provider server");

        let (address, server) = tls_server_response(
            "200 OK",
            "application/octet-stream",
            "",
            b"binary",
            credential,
        )
        .await;
        assert_eq!(
            execute_with_client(
                local_request(address, credential),
                local_test_client("localhost", address)
            )
            .await,
            Err(BrokerError::ResponseTypeDenied)
        );
        server.await.expect("binary server");
    }

    #[tokio::test]
    async fn local_tls_round_trip_rejects_oversized_responses() {
        let credential = b"bounded-test-token";
        let response_body = vec![b'x'; 128];
        let (address, server) = tls_server(&response_body, credential).await;
        let mut request = local_request(address, credential);
        request.constraint.max_response_bytes = 64;
        assert_eq!(
            execute_with_client(request, local_test_client("localhost", address)).await,
            Err(BrokerError::ResponseTooLarge)
        );
        server.await.expect("oversized server");
    }

    fn local_request(address: SocketAddr, credential: &[u8]) -> PreparedHttpRequest {
        prepare_bearer_request(
            HttpRequest {
                url: format!("https://localhost:{}/v1/status", address.port()),
                method: HttpMethod::Get,
                body: Vec::new(),
                content_type: None,
            },
            HttpConstraint {
                host: "localhost".into(),
                port: address.port(),
                methods: vec![HttpMethod::Get],
                path_prefix: "/v1".into(),
                max_request_bytes: 1024,
                max_response_bytes: 4096,
            },
            credential.to_vec(),
        )
        .expect("prepare")
    }

    fn local_test_client(host: &str, address: SocketAddr) -> reqwest::Client {
        reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_danger_accept_invalid_certs(true)
            .resolve_to_addrs(host, &[address])
            .build()
            .expect("test client")
    }

    async fn tls_server(
        response_body: &[u8],
        expected_credential: &[u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        tls_server_response(
            "200 OK",
            "application/json",
            "",
            response_body,
            expected_credential,
        )
        .await
    }

    async fn tls_server_response(
        status: &str,
        content_type: &str,
        extra_headers: &str,
        response_body: &[u8],
        expected_credential: &[u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let body = response_body.to_vec();
        let status = status.to_owned();
        let content_type = content_type.to_owned();
        let extra_headers = extra_headers.to_owned();
        let expected_authorization = [b"bearer ".as_slice(), expected_credential].concat();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut stream = acceptor.accept(stream).await.expect("TLS accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("request read");
                assert_ne!(read, 0, "request ended before headers");
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() <= 16 * 1024, "request headers too large");
            }
            let expected_header = [b"authorization: ".as_slice(), &expected_authorization].concat();
            let lower = request
                .iter()
                .map(u8::to_ascii_lowercase)
                .collect::<Vec<_>>();
            assert!(contains_bytes(&lower, &expected_header));
            let mut response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
        (address, task)
    }
}
