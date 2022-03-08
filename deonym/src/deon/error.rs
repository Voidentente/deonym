use std::fmt;

pub enum DeonError {
    RsaCryptoError(String),
    RsaPkcs8Error(String),
    MissingSkError(String),
    MalformedError(String),
}

impl fmt::Debug for DeonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeonError::RsaCryptoError(e) => {
                write!(f, "{}", e)
            }
            DeonError::RsaPkcs8Error(e) => {
                write!(f, "{}", e)
            }
            DeonError::MissingSkError(e) => {
                write!(f, "{}", e)
            }
            DeonError::MalformedError(e) => {
                write!(f, "{}", e)
            }
        }
    }
}

impl fmt::Display for DeonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeonError::RsaCryptoError(e) => {
                write!(f, "{}", e)
            }
            DeonError::RsaPkcs8Error(e) => {
                write!(f, "{}", e)
            }
            DeonError::MissingSkError(e) => {
                write!(f, "{}", e)
            }
            DeonError::MalformedError(e) => {
                write!(f, "{}", e)
            }
        }
    }
}
