// Copyright (C) 2026 George Bargoud <george@bargoud.nyc> & Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0


/// The errors that can occur when parsing the response server side
#[derive(Debug)]
pub enum AuthError {
    /// The parser used did not match the scheme
    IncorrectScheme,
    /// The request was malformed in some way
    MalformedRequest,
    /// The password was not correct for the user.
    IncorrectPassword,
}
