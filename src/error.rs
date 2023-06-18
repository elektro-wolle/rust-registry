use core::fmt;

use actix_web::{HttpResponse, HttpResponseBuilder};
use actix_web::error::{PayloadError, ResponseError};
use actix_web::http::header::ContentType;
use actix_web::http::StatusCode;
use diesel::r2d2;
use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AppError {
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppErrors {
    pub errors: Vec<AppError>,
}

#[derive(Debug)]
pub struct RegistryError {
    pub message: String,
    pub status_code: StatusCode,
    pub error_code: String,
}

impl RegistryError {
    pub fn new(status_code: StatusCode, error_code: &str, message: &String) -> Self {
        Self {
            message: message.to_string(),
            status_code,
            error_code: error_code.to_string(),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ResponseError for RegistryError {
    //error_response and status_code are the provided methods for ResponseError Trait

    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse {
        let errors = AppErrors {
            errors: vec![AppError {
                code: self.error_code.to_string(),
                message: self.message.to_string(),
                detail: None,
            }],
        };
        debug!("error: {:?}", errors);
        let mut http_response_builder = HttpResponseBuilder::new(self.status_code);
        let mut resp = http_response_builder.insert_header(ContentType::json());
        resp = resp.insert_header(("Docker-Distribution-Api-Version", "registry/2.0"));
        if self.status_code == StatusCode::UNAUTHORIZED {
            resp = resp.insert_header(("WWW-Authenticate", "BASIC realm=\"registry\""));
        }
        resp.json(errors)
    }
}

impl From<::actix_web::Error> for RegistryError {
    fn from(error: ::actix_web::Error) -> RegistryError {
        debug!("error: {:?}", error);
        RegistryError {
            message: format!("error: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<PayloadError> for RegistryError {
    fn from(error: PayloadError) -> RegistryError {
        debug!("error: {:?}", error);
        RegistryError {
            message: format!("error reading stream: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<r2d2::Error> for RegistryError {
    fn from(error: r2d2::Error) -> RegistryError {
        debug!("error: {:?}", error);
        RegistryError {
            message: format!("error opening db: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<diesel::result::Error> for RegistryError {
    fn from(error: diesel::result::Error) -> RegistryError {
        debug!("error: {:?}", error);
        RegistryError {
            message: format!("error querying db: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(err: std::io::Error) -> Self {
        RegistryError {
            message: format!("error: {:?}", err),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(error: serde_json::Error) -> RegistryError {
        RegistryError {
            message: format!("json error: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

pub fn map_to_not_found(err: std::io::Error) -> RegistryError {
    if err.kind() == std::io::ErrorKind::NotFound {
        RegistryError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("file not found: {:?}", err),
        )
    } else {
        RegistryError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            &format!("file error: {:?}", err),
        )
    }
}
