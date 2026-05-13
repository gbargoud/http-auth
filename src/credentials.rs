// Copyright (C) 2026 George Bargoud <george@bargoud.nyc> & Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::digest::Algorithm;
use crate::errors::AuthError;

/// The user that a given set of Credentials are for.
///
/// For digest auth, this may be hashed.
#[derive(Clone, PartialEq, Debug)]
pub enum User {
    Username(String),
    #[cfg(feature = "digest-scheme")]
    UserHash(String, Algorithm),
}

/// The credentials received from the user that can be used for verification
pub trait Credentials {
    /// The user that these credentials are for.
    fn get_user(&self) -> User;

    /// Whether these credentials match the given plaintext username and password
    /// 
    /// This is required for implementations that store passwords in plaintext but doing so is
    /// highly discouraged so the method is marked as deprecated so your IDEs and compilers yell at
    /// you.
    #[deprecated]
    fn equals_plaintext(&self, username: &str, password: &str) -> Result<(), AuthError>;

    /// Whether these credentials match the given digest which was made with the given algorithm.
    ///
    /// This function allows servers to store the digest in their database in the place of plaintext
    /// passwords and then use that for authentication.
    ///
    /// The digest should be a hash of "username:realm:password" where realm is the realm that was
    /// sent in the HTTP auth request.
    ///
    /// The algorithm is the one that was used to calculate the digest. If using digest auth, then
    /// this must match the algorithm in the request.
    #[cfg(feature = "digest-scheme")]
    fn equals_digest(&self, digest: &str, algorithm: &Algorithm) -> Result<(), AuthError>;
}
