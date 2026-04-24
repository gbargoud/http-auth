/// The errors that can occur when parsing the response server side
#[derive(Debug)]
pub enum AuthError {
    /// The parser used did not match the scheme
    IncorrectScheme,
    /// The request was malformed in some way
    MalformedRequest,
}