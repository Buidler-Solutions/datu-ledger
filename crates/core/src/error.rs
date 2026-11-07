use std::fmt;

#[derive(Debug)]
pub enum Error {
    Encoding(String),
    Crypto(String),
    InvalidEntry(String),
    Chain(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding(m) => write!(f, "encoding error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::InvalidEntry(m) => write!(f, "invalid entry: {m}"),
            Error::Chain(m) => write!(f, "chain violation: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Encoding(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
