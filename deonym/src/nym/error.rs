use std::fmt;

pub enum NymError {
    MalformedError(String),
    ErrorResponse(String),
}

impl fmt::Debug for NymError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NymError::MalformedError(e) => {
                write!(f, "{}", e)
            }
            NymError::ErrorResponse(e) => {
                write!(f, "{}", e)
            }
        }
    }
}

impl fmt::Display for NymError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NymError::MalformedError(e) => {
                write!(f, "{}", e)
            }
            NymError::ErrorResponse(e) => {
                write!(f, "{}", e)
            }
        }
    }
}
