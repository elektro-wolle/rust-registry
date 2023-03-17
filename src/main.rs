use std::cmp::max;
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::TryFutureExt;
use hyper::{Body, Method, Request, Response, Server};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::http::request::Parts;
use hyper::service::{make_service_fn, service_fn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::*;

#[derive(Debug, Clone)]
struct Registry {
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
    fn new(storage_path: PathBuf) -> Self {
        Registry {
            storage_path: Arc::new(storage_path),
        }
    }


    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let (parts, body) = req.into_parts();
        let body_content = hyper::body::to_bytes(body).await;

        match (&parts.method, &parts.uri.path()) {
            (&Method::GET, &"/v2/") => { Self::handle_get_v2() }
            (&Method::GET, &"/v2/_catalog") => { self.handle_v2_catalog() }
            (&Method::GET, path) if path.starts_with("/v2/") => { self.handle_get(path) }
            (&Method::POST, path) if path.starts_with("/v2/") && path.ends_with("/blobs/uploads/") => { self.handle_post(path) }
            (&Method::PATCH, path) if path.starts_with("/v2/") && path.contains("/blobs/uploads/") => { self.handle_patch(&parts, &body_content, path) }
            (&Method::HEAD, path) if path.starts_with("/v2/") && path.contains("/blobs/") => { self.handle_head(path) }
            (&Method::PUT, path)  if path.starts_with("/v2/") => { self.handle_put(&parts, &body_content, path) }
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
                Ok(response)
            }
        }
    }

    fn handle_put(&self, parts: &Parts, body_content: &Result<hyper::body::Bytes, hyper::Error>, path: &str) -> Result<Response<Body>, hyper::Error> {
        match parts.uri.query() {
            None => {
                println!("Upload blob: {}", path);
                let (repo_name, tag) = parse_repo_name_and_tag(path.trim_start_matches("/v2/"));
                let blob_path = self.storage_path.join(repo_name).join(format!("{}.json", tag));
                println!("Uploading blob: {} to: {:?}", path, &blob_path);
                let mut dir_builder = DirBuilder::new();
                dir_builder.recursive(true).create(blob_path.parent().unwrap()).unwrap();
                if let Ok(mut file) = File::create(blob_path) {
                    if let Err(e) = file.write_all(&(body_content.as_ref().unwrap())) {
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
            Some(q) => {
                let (repo_name, uuid) = parse_repo_name_and_uuid(path.trim_start_matches("/v2/"));
                let upload_path = self.storage_path.join(&repo_name).join(format!("blobs/uploads/{}", uuid));

                let query = url::form_urlencoded::parse(q.as_bytes());
                println!("got query: {:?}", q);
                for (key, value) in query {
                    if key == "digest" {
                        let digest = value;
                        let path_to_file = self.storage_path.join(&repo_name).join(format!("blobs/{}", digest));
                        println!("rename {} to {}", upload_path.display(), path_to_file.display());
                        fs::rename(&upload_path, path_to_file).unwrap();

                        // let mut hasher = Sha256::new();
                        // hasher.input(body_content.as_ref().unwrap());
                        // let hash = hasher.result();
                        // let hash = general_purpose::URL_SAFE_NO_PAD.encode(orig);
                        // let hash = format!("sha256:{}", hash);
                        let response = Response::builder()
                            .status(201)
                            .header("Location", format!("/v2/{}/blobs/{}", &repo_name, digest))
                            .body(Body::empty())
                            .unwrap();
                        return Ok(response);

                        // if hash != digest {
                        //     eprintln!("Digest mismatch: {} != {}", hash, digest);
                        //     return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
                        // }
                    }
                }
            }
        }
        let response = Response::builder()
            .status(202)
            .header("Range", format!("0-{}", body_content.as_ref().unwrap().len()))
            .header("Content-Length", "0")
            .body(Body::empty())
            .unwrap();
        Ok(response)
    }

    fn handle_head(&self, path: &str) -> Result<Response<Body>, hyper::Error> {
        let (repo_name, digest) = parse_repo_name_and_digest(path.trim_start_matches("/v2/"));
        let blob_path = self.storage_path.join(repo_name).join(format!("blobs/{}", digest));
        if blob_path.exists() {
            let response = Response::builder()
                .status(200)
                .header("Content-Length", format!("{}", blob_path.metadata().unwrap().len()))
                .header("Docker-Content-Digest", digest)
                .body(Body::empty())
                .unwrap();
            Ok(response)
        } else {
            let response = Response::builder()
                .status(404)
                .body(Body::empty())
                .unwrap();
            Ok(response)
        }
    }

    fn handle_patch(&self, parts: &Parts, body_content: &Result<hyper::body::Bytes, hyper::Error>, path: &str) -> Result<Response<Body>, hyper::Error> {
        let (repo_name, uuid) = parse_repo_name_and_uuid(path.trim_start_matches("/v2/"));
        let upload_path = self.storage_path.join(repo_name).join(format!("blobs/uploads/{}", uuid));
        let mut dir_builder = DirBuilder::new();
        println!("creating dir: {}", upload_path.parent().unwrap().display());
        println!("headers: {:#?} size: {}", parts.headers, body_content.as_ref().unwrap().len());
        dir_builder.recursive(true).create(upload_path.parent().unwrap()).unwrap();
        println!("writing to file {}", upload_path.display());

        let mut file = match fs::OpenOptions::new().append(true).open(&upload_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file {}: {}", upload_path.display(), err);
                return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
            }
        };
        if let Err(err) = file.write_all(body_content.as_ref().unwrap()) {
            eprintln!("Failed to write to file {}: {}", upload_path.display(), err);

            return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
        }
        let response = Response::builder()
            .status(202)
            .header("Range", format!("0-{}", body_content.as_ref().unwrap().len()))
            .header("Content-Length", "0")
            .header("Docker-Upload-UUID", uuid)
            .body(Body::empty())
            .unwrap();
        Ok(response)
    }

    fn handle_post(&self, path: &str) -> Result<Response<Body>, hyper::Error> {
        let repo_name = path.trim_end_matches("/blobs/uploads/").trim_start_matches("/v2/");
        let uuid = Uuid::new_v4();
        let upload_path = self.storage_path.join(&repo_name).join(format!("blobs/uploads/{}", uuid));

        let mut dir_builder = DirBuilder::new();
        dir_builder.recursive(true).create(upload_path.parent().unwrap()).unwrap();

        match File::create(&upload_path) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("Failed to create file {}: {}", upload_path.display(), err);
                return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
            }
        };
        let response = Response::builder()
            .status(202)
            .header("Location", format!("/v2/{}/blobs/uploads/{}", &repo_name, uuid))
            .body(Body::empty())
            .unwrap();
        Ok(response)
    }

    fn handle_get(&self, path: &str) -> Result<Response<Body>, hyper::Error> {
        let (repo_name, tag) = parse_repo_name_and_tag(path.trim_start_matches("/v2/"));
        if !tag.starts_with("sha256:") {
            let manifest_path = self.storage_path.join(&repo_name).join(format!("{}.json", tag));
            println!("manifest_path: {}", manifest_path.display());
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
        } else {
            let manifest_path = self.storage_path.join(&repo_name).join(format!("{}", tag));
            println!("manifest_path: {}", manifest_path.display());
            if let Ok(file) = File::open(manifest_path) {
                let mut buf_reader = io::BufReader::new(file);
                let mut contents = String::new();
                if let Ok(_) = buf_reader.read_to_string(&mut contents)
                {
                    let response = Response::builder()
                        .status(200)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(contents))
                        .unwrap();
                    return Ok(response);
                }
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
        Ok(response)
    }

    fn handle_v2_catalog(&self) -> Result<Response<Body>, hyper::Error> {
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
        Ok(response)
    }

    fn handle_get_v2() -> Result<Response<Body>, hyper::Error> {
        let response_body = json!({
                    "versions": ["2"]
                });
        let response = Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(response_body.to_string()))
            .unwrap();
        Ok(response)
    }
}

fn parse_repo_name_and_tag(path: &str) -> (String, String) {
    let parts: Vec<&str> = path.split('/').collect();
    let repo_name = parts[0..(max(1, parts.len() - 1))].join("/");
    let tag = if parts.len() > 1 { parts[parts.len() - 1] } else { "latest" };
    println!("repo_name: {}, tag: {}", repo_name, tag);
    (repo_name, tag.to_string())
}

fn parse_repo_name_and_uuid(path: &str) -> (String, String) {
    let parts: Vec<_> = path.split('/').collect();
    let repo_name = parts[0..(max(1, parts.len() - 3))].join("/");
    let uuid = parts[parts.len() - 1].to_string();
    println!("repo_name: {}, uuid: {}", repo_name, uuid);
    (repo_name, uuid)
}

fn parse_repo_name_and_digest(path: &str) -> (String, String) {
    let parts: Vec<_> = path.split('/').collect();
    let repo_name = parts[0..(max(1, parts.len() - 2))].join("/");
    let digest = parts[parts.len() - 1].to_string();
    println!("repo_name: {}, digest: {}", repo_name, digest);
    (repo_name, digest)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config: HashMap<String, Value> = serde_json::from_reader(File::open("config.json").unwrap()).unwrap();
    let storage_path: PathBuf = PathBuf::from(config.get("storage_path").unwrap().as_str().unwrap());
    let registry = Registry::new(storage_path);
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
                    println!("{} {}", req.method(), req.uri().path_and_query().unwrap());
                    reg.handle_request(req).await
                }
            }))
        }
    });

    let listen_address = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 8000, 0, 0);

    let server = Server::bind(&listen_address.into())
        .serve(make_svc)
        .map_err(|e| eprintln!("server error: {:?}", e));
    println!("Listening on http://{}", listen_address);
    match server.await {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("server error: {:?}", e);
            Err(Box::new(e))
        }
    }.expect("TODO: panic message");

    Ok(())
}

