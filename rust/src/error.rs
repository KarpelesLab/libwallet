use std::fmt;

#[derive(Debug)]
pub enum Error {
    Sql(graphitesql::Error),
    Io(std::io::Error),
    /// Environment/config problem (bad data dir, non-UTF8 path, ...).
    Env(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sql(e) => write!(f, "sql error: {e:?}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Env(s) => write!(f, "env error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<graphitesql::Error> for Error {
    fn from(e: graphitesql::Error) -> Self {
        Error::Sql(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
