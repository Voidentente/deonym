use std::fmt;

pub enum DeonError {
    RsaCrypto(String),
    RsaPkcs8(String),
    NoSecretKey(String),
    Malformed(String),
}

impl fmt::Debug for DeonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeonError::RsaCrypto(e) => {
                write!(f, "{}", e)
            }
            DeonError::RsaPkcs8(e) => {
                write!(f, "{}", e)
            }
            DeonError::NoSecretKey(e) => {
                write!(f, "{}", e)
            }
            DeonError::Malformed(e) => {
                write!(f, "{}", e)
            }
        }
    }
}

impl fmt::Display for DeonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeonError::RsaCrypto(e) => {
                write!(f, "{}", e)
            }
            DeonError::RsaPkcs8(e) => {
                write!(f, "{}", e)
            }
            DeonError::NoSecretKey(e) => {
                write!(f, "{}", e)
            }
            DeonError::Malformed(e) => {
                write!(f, "{}", e)
            }
        }
    }
}
