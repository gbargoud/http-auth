// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Basic` authentication scheme as in
//! [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).

use std::convert::TryFrom;

use crate::ChallengeRef;

#[cfg(feature = "server")]
use crate::errors::AuthError;

const PREFIX: &str = "Basic ";

/// Encodes the given credentials.
///
/// This can be used to preemptively send `Basic` authentication, without
/// sending an unauthenticated request and waiting for a `401 Unauthorized`
/// response.
///
/// The caller should use the returned string as an `Authorization` or
/// `Proxy-Authorization` header value.
///
/// The caller is responsible for `username` and `password` being in the
/// correct format. Servers may expect arguments to be in Unicode
/// Normalization Form C as noted in [RFC 7617 section
/// 2.1](https://datatracker.ietf.org/doc/html/rfc7617#section-2.1).
///
/// ```rust
/// assert_eq!(
///     http_auth::basic::encode_credentials("Aladdin", "open sesame"),
///     "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
/// );
pub fn encode_credentials(username: &str, password: &str) -> String {
    use base64::Engine as _;
    let user_pass = format!("{}:{}", username, password);
    let mut value = String::with_capacity(PREFIX.len() + base64_encoded_len(user_pass.len()));
    value.push_str(PREFIX);
    base64::engine::general_purpose::STANDARD.encode_string(&user_pass[..], &mut value);
    value
}

/// Returns the base64-encoded length for the given input length, including padding.
fn base64_encoded_len(input_len: usize) -> usize {
    (input_len + 2) / 3 * 4
}

/// Represents the username and password retrieved from Basic auth
#[cfg(feature = "server")]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[cfg(feature = "server")]
impl From<(&str, &str)> for Credentials {
    fn from((username, password): (&str, &str)) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

/// Decode the credentials from the header
///
/// These are the credentials added to the `Authorization` or `Proxy-Authorization` header value by
/// the client.
///
/// This is a reversal of `encode_credentials`.
#[cfg(feature = "server")]
pub fn decode_credentials(header_value: &str) -> Result<Credentials, AuthError> {
    use base64::Engine as _;
    let encoded = header_value
        .strip_prefix(PREFIX)
        .ok_or(AuthError::IncorrectScheme)?
        .trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AuthError::MalformedRequest)?;
    let decoded = String::from_utf8(decoded).map_err(|_| AuthError::MalformedRequest)?;
    decoded
        .split_once(":")
        .map(Credentials::from)
        .ok_or(AuthError::MalformedRequest)
}

/// Client for a `Basic` challenge, as in
/// [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).
///
/// This implementation always uses `UTF-8`. Thus it doesn't use or store the
/// `charset` parameter, which the RFC only allows to be set to `UTF-8` anyway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicClient {
    realm: Box<str>,
}

impl BasicClient {
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Responds to the challenge with the supplied parameters.
    ///
    /// This is functionally identical to [`encode_credentials`]; no parameters
    /// of the `BasicClient` are needed to produce the credentials.
    #[inline]
    pub fn respond(&self, username: &str, password: &str) -> String {
        encode_credentials(username, password)
    }
}

/// Server side support for a `Basic` challenge, as in
/// [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).
#[cfg(feature = "server")]
pub struct BasicServer {
    realm: Box<str>,
}

#[cfg(feature = "server")]
impl BasicServer {
    /// Creates a new client for issuing challenges and verifying responses.
    pub fn new(realm: String) -> Self {
        Self {
            realm: realm.into(),
        }
    }

    /// Issues the challenge for the given client
    ///
    /// This should be included by the server in the `WWW-Authenticate` header of a 401 response or
    /// the `Proxy-Authenticate` header in a 407 response.
    #[inline]
    pub fn challenge(&self) -> String {
        format!("{}realm={}", PREFIX, self.realm)
    }

    /// Parses the password
    #[inline]
    pub fn parse_response(&self, response: &str) -> Result<Credentials, AuthError> {
        decode_credentials(response)
    }
}

impl TryFrom<&ChallengeRef<'_>> for BasicClient {
    type Error = String;

    fn try_from(value: &ChallengeRef<'_>) -> Result<Self, Self::Error> {
        if !value.scheme.eq_ignore_ascii_case("Basic") {
            return Err(format!(
                "BasicClient doesn't support challenge scheme {:?}",
                value.scheme
            ));
        }
        let mut realm = None;
        for (k, v) in &value.params {
            if k.eq_ignore_ascii_case("realm") {
                realm = Some(v.to_unescaped());
            }
        }
        let realm = realm.ok_or("missing required parameter realm")?;
        Ok(BasicClient {
            realm: realm.into_boxed_str(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChallengeParser;

    #[test]
    fn basic_respond() {
        // Example from https://datatracker.ietf.org/doc/html/rfc7617#section-2
        let ctx = BasicClient {
            realm: "WallyWorld".into(),
        };
        assert_eq!(
            ctx.respond("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );

        // Example from https://datatracker.ietf.org/doc/html/rfc7617#section-2.1
        // Note that this crate *always* uses UTF-8, not just when the server requests it.
        let ctx = BasicClient {
            realm: "foo".into(),
        };
        assert_eq!(ctx.respond("test", "123\u{A3}"), "Basic dGVzdDoxMjPCow==");
    }

    #[test]
    #[cfg(feature = "server")]
    fn basic_round_trip() {
        let server = BasicServer {
            realm: "foo".into(),
        };
        let challenge = server.challenge();
        let mut challenge_parser = ChallengeParser::new(challenge.as_str());
        let challenge_ref = challenge_parser
            .next()
            .expect("Missing ChallengeRef")
            .expect("Malformed ChallengeRef");
        let client = BasicClient::try_from(&challenge_ref).expect("Challenge should be basic");
        assert_eq!(client.realm, server.realm);

        let response = client.respond("AzureDiamond", "hunter2");
        let credentials = server
            .parse_response(response.as_str())
            .expect("Failed to parse credentials");
        assert_eq!(credentials.username, "AzureDiamond", "username");
        assert_eq!(credentials.password, "hunter2", "password");
    }

    #[test]
    #[cfg(feature = "server")]
    fn fail_to_parse() {
        let server = BasicServer {
            realm: "foo".into(),
        };

        assert!(server.parse_response("Does not start with Basic").is_err());
        assert!(server
            .parse_response("Basic Invalid Base64 encoded string")
            .is_err());
        use base64::Engine as _;
        let mut buf = String::new();
        base64::engine::general_purpose::STANDARD
            .encode_string("not username colon password", &mut buf);
        assert!(server.parse_response(&buf).is_err());
    }
}
