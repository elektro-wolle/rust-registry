use core::fmt;

use actix_web::{HttpResponse, HttpResponseBuilder};
use actix_web::error::{PayloadError, ResponseError};
use actix_web::http::header::ContentType;
use actix_web::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AppError {
    pub code: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppErrors {
    pub errors: Vec<AppError>,
}

#[derive(Debug)]
pub struct MyError {
    pub message: String,
    pub status_code: StatusCode,
    pub error_code: String,
}

impl MyError {
    pub fn new(status_code: StatusCode, error_code: &str, message: &String) -> MyError {
        MyError {
            message: message.to_string(),
            status_code,
            error_code: error_code.to_string(),
        }
    }
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ResponseError for MyError {
    //error_response and status_code are the provided methods for ResponseError Trait

    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse {
        let errors = AppErrors {
            errors: vec![AppError {
                code: self.error_code.to_string(),
                message: self.message.to_string(),
            }],
        };
        println!("error: {:?}", errors);
        HttpResponseBuilder::new(self.status_code)
            .insert_header(ContentType::json())
            .json(errors)
    }
}

impl From<::actix_web::Error> for MyError {
    fn from(error: ::actix_web::Error) -> MyError {
        println!("error: {:?}", error);
        MyError {
            message: format!("error: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<PayloadError> for MyError {
    fn from(error: PayloadError) -> MyError {
        println!("error: {:?}", error);
        MyError {
            message: format!("error reading stream: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<std::io::Error> for MyError {
    fn from(err: std::io::Error) -> Self {
        MyError {
            message: format!("error: {:?}", err),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}

impl From<serde_json::Error> for MyError {
    fn from(error: serde_json::Error) -> MyError {
        MyError {
            message: format!("json error: {:?}", error),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "INTERNAL_SERVER_ERROR".to_string(),
        }
    }
}
