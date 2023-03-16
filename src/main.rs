use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fs::{self, File};
use std::future::Future;
use std::future::IntoFuture;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::{StreamExt, TryFutureExt, TryStreamExt};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::body::HttpBody;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::rt::{self};
use hyper::service::{make_service_fn, service_fn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::*;

#[derive(Debug, Clone)]
struct Registry {
    config: Arc<HashMap<String, Value>>,
    storage_path: Arc<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestV2 {
    config: Option<Config>,
    layers: Vec<Layer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Layer {
    digest: String,
    size: u64,
}

impl Registry {
    fn new(config: HashMap<String, Value>, storage_path: PathBuf) -> Self {
        Registry {
            config: Arc::new(config),
            storage_path: Arc::new(storage_path),
        }
    }

    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let (parts, body) = req.into_parts();
        let mut body_content = hyper::body::to_bytes(body).await;

        match (parts.method, parts.uri.path()) {
            (Method::GET, "/v2/") => {
                let response_body = json!({
                    "versions": ["2"]
                });
                let response = Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(response_body.to_string()))
                    .unwrap();
                return Ok(response);
            }
            (Method::GET, "/v2/_catalog") => {
                let storage_path = self.storage_path.clone();
                let mut repositories = Vec::new();
                if let Ok(read_dir) = fs::read_dir(storage_path.as_path()) {
                    for path in read_dir {
                        if let Ok(path) = path {
                            if let Ok(file_type) = path.file_type() {
                                if file_type.is_dir() {
                                    if let Ok(repo_name) = path.file_name().into_string() {
                                        repositories.push(repo_name);
                                    }
                                }
                            }
                        }
                    }
                }
                let response_body = json!({
                    "repositories": repositories
                });
                let response = Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(response_body.to_string()))
                    .unwrap();
                return Ok(response);
            }
            (Method::GET, path) if path.starts_with("/v2/") => {
                let (repo_name, tag) = parse_repo_name_and_tag(path.trim_start_matches("/v2/"));
                let manifest_path = self.storage_path.join(repo_name).join(format!("manifests/{}.json", tag));
                if let Ok(file) = File::open(manifest_path) {
                    let mut buf_reader = io::BufReader::new(file);
                    let mut contents = String::new();
                    if let Ok(_) = buf_reader.read_to_string(&mut contents)
                    {
                        let manifest: ManifestV2 = serde_json::from_str(&contents).unwrap();
                        let response = Response::builder()
                            .status(200)
                            .header(CONTENT_TYPE, "application/json")
                            .header("Docker-Content-Digest", manifest.config.unwrap().digest)
                            .body(Body::from(contents))
                            .unwrap();
                        return Ok(response);
                    }
                }
                let response_body = json!({
                "errors": [
                    {
                        "code": "MANIFEST_UNKNOWN",
                        "message": "manifest unknown",
                    },
                ]
            });
                let response = Response::builder()
                    .status(404)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(response_body.to_string()))
                    .unwrap();
                return Ok(response);
            }
            (Method::POST, path) if path.starts_with("/v2/") && path.ends_with("/blobs/uploads/") => {
                let (repo_name, _) = parse_repo_name_and_tag(&path.trim_end_matches("/blobs/uploads/").trim_start_matches("/v2/"));
                let uuid = Uuid::new_v4();
                let upload_path = self.storage_path.join(repo_name).join(format!("blobs/uploads/{}", uuid));
                let mut file = match std::fs::File::create(&upload_path) {
                    Ok(file) => file,
                    Err(err) => {
                        eprintln!("Failed to create file {}: {}", upload_path.display(), err);
                        return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
                    }
                };
                if let Err(err) = file.write_all(&(body_content.unwrap())) {
                    eprintln!("Failed to write to file {}: {}", upload_path.display(), err);
                    return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
                }
                let response = Response::builder()
                    .status(202)
                    .header("Location", format!("/v2/{}/blobs/uploads/{}", repo_name, uuid))
                    .body(Body::empty())
                    .unwrap();
                Ok(response)
            },
            (Method::PUT, path) if path.starts_with("/v2/") => {
                println!("Upload blob: {}", path);
                let (repo_name, tag) = parse_repo_name_and_tag(path.trim_start_matches("/v2/"));
                let blob_path = self.storage_path.join(repo_name).join(format!("blobs/{}.dat", tag));
                println!("Uploading blob: {} to: {:?}", path, &blob_path);
                if let Ok(mut file) = File::create(blob_path) {
                    if let Err(e) = file.write_all(&(body_content.unwrap())) {
                        return Ok(Response::new(Body::from(format!("Error writing blob: {}", e))));
                    }
                    let response = Response::builder()
                        .status(201)
                        .header(CONTENT_TYPE, "application/json")
                        .header(CONTENT_LENGTH, "0")
                        .body(Body::empty())
                        .unwrap();
                    return Ok(response);
                }
                println!("Failed uploading blob: {}", path);
                let response_body = json!({
                "errors": [
                    {
                        "code": "BLOB_UNKNOWN",
                        "message": "blob unknown",
                    },
                ]
            });
                let response = Response::builder()
                    .status(404)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(response_body.to_string()))
                    .unwrap();
                return Ok(response);
            }
            // handle post request to /v2/<repo>/manifests/<tag>



            _ => {
                let response_body = json!({
                "errors": [
                    {
                        "code": "UNSUPPORTED",
                        "message": "Unsupported operation",
                    },
                ]
            });
                let response = Response::builder()
                    .status(404)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(response_body.to_string()))
                    .unwrap();
                return Ok(response);
            }
        }
    }
}

fn parse_repo_name_and_tag(path: &str) -> (&str, &str) {
    let parts: Vec<&str> = path.split("/").collect();
    let repo_name = parts[0];
    let tag = if parts.len() > 1 { parts[1] } else { "latest" };
    (repo_name, tag)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config: HashMap<String, Value> = serde_json::from_reader(File::open("config.json").unwrap()).unwrap();
    let storage_path: PathBuf = PathBuf::from(config.get("storage_path").unwrap().as_str().unwrap());
    let registry = Registry::new(config, storage_path);
    let arc_registry = Arc::new(registry);
    // let addr = ([0, 0, 0, 0], 8000).into();

    // let make_svc = make_service_fn(|_| {
    //     let reg = arc_registry.clone();
    //     async move {
    //         Ok::<_, hyper::Error>(service_fn(move |req| {
    //             reg.handle_request(req)
    //         }))
    //     }
    // });

    let make_svc = make_service_fn(move |_| {
        let reg = arc_registry.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let reg = reg.clone();
                async move {
                    println!("{} {}", req.method(), req.uri());
                    reg.handle_request(req).await
                }
            }))
        }
    });

    let addrV6 = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 8000, 0, 0);

    let server = Server::bind(&addrV6.into())
        .serve(make_svc)
        .map_err(|e| eprintln!("server error: {:?}", e));
    println!("Listening on http://{}", addrV6);
    server.await;

    Ok(())
}

