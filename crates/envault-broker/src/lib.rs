#![forbid(unsafe_code)]

use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConstraint {
    pub host: String,
    pub methods: Vec<String>,
    pub path_prefix: String,
    pub max_response_bytes: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum BrokerError {
    #[error("URL is invalid")]
    InvalidUrl,
    #[error("only HTTPS URLs are allowed")]
    InsecureScheme,
    #[error("URL credentials are forbidden")]
    EmbeddedCredentials,
    #[error("target host is not allowed")]
    HostDenied,
    #[error("HTTP method is not allowed")]
    MethodDenied,
    #[error("URL path is not allowed")]
    PathDenied,
}

pub fn validate_http_target(
    target: &str,
    method: &str,
    constraint: &HttpConstraint,
) -> Result<Url, BrokerError> {
    let url = Url::parse(target).map_err(|_| BrokerError::InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(BrokerError::InsecureScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BrokerError::EmbeddedCredentials);
    }
    if url.host_str() != Some(constraint.host.as_str()) {
        return Err(BrokerError::HostDenied);
    }
    if !constraint.methods.iter().any(|allowed| allowed == method) {
        return Err(BrokerError::MethodDenied);
    }
    if !url.path().starts_with(&constraint.path_prefix) {
        return Err(BrokerError::PathDenied);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn openai() -> HttpConstraint {
        HttpConstraint {
            host: "api.openai.com".into(),
            methods: vec!["POST".into()],
            path_prefix: "/v1/".into(),
            max_response_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn accepts_exact_https_origin_and_path() {
        assert!(
            validate_http_target("https://api.openai.com/v1/responses", "POST", &openai()).is_ok()
        );
    }

    #[test]
    fn rejects_cross_origin_and_insecure_targets() {
        assert_eq!(
            validate_http_target("https://example.com/v1/responses", "POST", &openai()),
            Err(BrokerError::HostDenied)
        );
        assert_eq!(
            validate_http_target("http://api.openai.com/v1/responses", "POST", &openai()),
            Err(BrokerError::InsecureScheme)
        );
    }
}
