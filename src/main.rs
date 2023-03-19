use std::collections::HashMap;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::{App, Error, get, head, http::header, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, middleware, patch, post, put, Result, web};
use actix_web::error::ErrorBadRequest;
use actix_web::http::header::ContentType;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use futures_util::StreamExt;
use hyper::header::CONTENT_LENGTH;
use path_clean::PathClean;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::*;

use crate::error::*;

mod error;

#[derive(Debug, Clone)]
struct Registry {
    storage_path: Arc<PathBuf>,
}

struct AppState {
    registry: Arc<Registry>,
}

impl AppState {
    fn get_upload_path(&self, path: &String) -> PathBuf {
        // canonicalize() will remove any "." and ".." from the path
        let sub_path = PathBuf::from(format!("/{}", path)).clean();
        let target_path = format!("{}/{}", self.registry.storage_path.display(), sub_path.display());
        // second clean() to ensure that the path is clean
        PathBuf::from(target_path).clean()
    }
    fn get_layer_path(&self, path: &String) -> PathBuf {
        self.get_upload_path(path)
    }
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


    //
    // fn handle_put(&self, parts: &Parts, body_content: &Result<hyper::body::Bytes, hyper::Error>, path: &str) -> Result<Response<Body>, hyper::Error> {
    //     match parts.uri.query() {
    //         None => {
    //             println!("Upload blob: {}", path);
    //             let (repo_name, tag) = parse_repo_name_and_tag(path.trim_start_matches("/v2/"));
    //             let blob_path = self.storage_path.join(repo_name).join(format!("{}.json", tag));
    //             println!("Uploading blob: {} to: {:?}", path, &blob_path);
    //             let mut dir_builder = DirBuilder::new();
    //             dir_builder.recursive(true).create(blob_path.parent().unwrap()).unwrap();
    //             if let Ok(mut file) = File::create(blob_path) {
    //                 if let Err(e) = file.write_all(&(body_content.as_ref().unwrap())) {
    //                     return Ok(Response::new(Body::from(format!("Error writing blob: {}", e))));
    //                 }
    //                 let response = Response::builder()
    //                     .status(201)
    //                     .header(CONTENT_TYPE, "application/json")
    //                     .header(CONTENT_LENGTH, "0")
    //                     .body(Body::empty())
    //                     .unwrap();
    //                 return Ok(response);
    //             }
    //             println!("Failed uploading blob: {}", path);
    //             let response_body = json!({
    //                         "errors": [
    //                             {
    //                                 "code": "BLOB_UNKNOWN",
    //                                 "message": "blob unknown",
    //                             },
    //                         ]
    //                     });
    //             let response = Response::builder()
    //                 .status(404)
    //                 .header(CONTENT_TYPE, "application/json")
    //                 .body(Body::from(response_body.to_string()))
    //                 .unwrap();
    //             return Ok(response);
    //         }
    //         Some(q) => {
    //             let (repo_name, uuid) = parse_repo_name_and_uuid(path.trim_start_matches("/v2/"));
    //             let upload_path = self.storage_path.join(&repo_name).join(format!("blobs/uploads/{}", uuid));
    //
    //             let query = url::form_urlencoded::parse(q.as_bytes());
    //             println!("got query: {:?}", q);
    //             for (key, value) in query {
    //                 if key == "digest" {
    //                     let digest = value;
    //                     let path_to_file = self.storage_path.join(&repo_name).join(format!("blobs/{}", digest));
    //                     println!("rename {} to {}", upload_path.display(), path_to_file.display());
    //                     fs::rename(&upload_path, path_to_file).unwrap();
    //
    //                     // let mut hasher = Sha256::new();
    //                     // hasher.input(body_content.as_ref().unwrap());
    //                     // let hash = hasher.result();
    //                     // let hash = general_purpose::URL_SAFE_NO_PAD.encode(orig);
    //                     // let hash = format!("sha256:{}", hash);
    //                     let response = Response::builder()
    //                         .status(201)
    //                         .header("Location", format!("/v2/{}/blobs/{}", &repo_name, digest))
    //                         .body(Body::empty())
    //                         .unwrap();
    //                     return Ok(response);
    //
    //                     // if hash != digest {
    //                     //     eprintln!("Digest mismatch: {} != {}", hash, digest);
    //                     //     return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
    //                     // }
    //                 }
    //             }
    //         }
    //     }
    //     let response = Response::builder()
    //         .status(202)
    //         .header("Range", format!("0-{}", body_content.as_ref().unwrap().len()))
    //         .header("Content-Length", "0")
    //         .body(Body::empty())
    //         .unwrap();
    //     Ok(response)
    // }
    //
    // fn handle_head(&self, path: &str) -> Result<Response<Body>, hyper::Error> {
    //     let (repo_name, digest) = parse_repo_name_and_digest(path.trim_start_matches("/v2/"));
    //     let blob_path = self.storage_path.join(repo_name).join(format!("blobs/{}", digest));
    //     if blob_path.exists() {
    //         let response = Response::builder()
    //             .status(200)
    //             .header("Content-Length", format!("{}", blob_path.metadata().unwrap().len()))
    //             .header("Docker-Content-Digest", digest)
    //             .body(Body::empty())
    //             .unwrap();
    //         Ok(response)
    //     } else {
    //         let response = Response::builder()
    //             .status(404)
    //             .body(Body::empty())
    //             .unwrap();
    //         Ok(response)
    //     }
    // }
    //
    // fn handle_patch(&self, parts: &Parts, body_content: &Result<hyper::body::Bytes, hyper::Error>, path: &str) -> Result<Response<Body>, hyper::Error> {
    //     let (repo_name, uuid) = parse_repo_name_and_uuid(path.trim_start_matches("/v2/"));
    //     let upload_path = self.storage_path.join(repo_name).join(format!("blobs/uploads/{}", uuid));
    //     let mut dir_builder = DirBuilder::new();
    //     println!("creating dir: {}", upload_path.parent().unwrap().display());
    //     println!("headers: {:#?} size: {}", parts.headers, body_content.as_ref().unwrap().len());
    //     dir_builder.recursive(true).create(upload_path.parent().unwrap()).unwrap();
    //     println!("writing to file {}", upload_path.display());
    //
    //     let mut file = match fs::OpenOptions::new().append(true).open(&upload_path) {
    //         Ok(file) => file,
    //         Err(err) => {
    //             eprintln!("Failed to open file {}: {}", upload_path.display(), err);
    //             return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
    //         }
    //     };
    //     if let Err(err) = file.write_all(body_content.as_ref().unwrap()) {
    //         eprintln!("Failed to write to file {}: {}", upload_path.display(), err);
    //
    //         return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
    //     }
    //     let response = Response::builder()
    //         .status(202)
    //         .header("Range", format!("0-{}", body_content.as_ref().unwrap().len()))
    //         .header("Content-Length", "0")
    //         .header("Docker-Upload-UUID", uuid)
    //         .body(Body::empty())
    //         .unwrap();
    //     Ok(response)
    // }
    //
    // fn handle_post(&self, path: &str) -> Result<Response<Body>, hyper::Error> {
    //     let repo_name = path.trim_end_matches("/blobs/uploads/").trim_start_matches("/v2/");
    //     let uuid = Uuid::new_v4();
    //     let upload_path = self.storage_path.join(&repo_name).join(format!("blobs/uploads/{}", uuid));
    //
    //     let mut dir_builder = DirBuilder::new();
    //     dir_builder.recursive(true).create(upload_path.parent().unwrap()).unwrap();
    //
    //     match File::create(&upload_path) {
    //         Ok(_) => {}
    //         Err(err) => {
    //             eprintln!("Failed to create file {}: {}", upload_path.display(), err);
    //             return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
    //         }
    //     };
    //     let response = Response::builder()
    //         .status(202)
    //         .header("Location", format!("/v2/{}/blobs/uploads/{}", &repo_name, uuid))
    //         .body(Body::empty())
    //         .unwrap();
    //     Ok(response)
    // }
    //
}

#[derive(Deserialize, Serialize)]
struct VersionInfo {
    versions: Vec<String>,
}
// Result<HttpResponse, Error>

#[get("/v2")]
async fn handle_get_v2() -> Result<HttpResponse, Error> {
    Ok(
        HttpResponseBuilder::new(StatusCode::OK)
            .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
            .json(VersionInfo {
                versions: vec!["registry/2.0".to_string()]
            })
    )
}

#[derive(Deserialize, Serialize)]
struct RepositoryInfo {
    repositories: Vec<String>,
}


#[get("/v2/_catalog")]
async fn handle_v2_catalog(data: Data<AppState>) -> Result<Json<RepositoryInfo>, Error> {
    let storage_path = data.registry.storage_path.clone();
    let mut repositories = Vec::new();
    if let Ok(read_dir) = fs::read_dir(storage_path.as_path()) {
        for path in read_dir.flatten() {
            if let Ok(file_type) = path.file_type() {
                if file_type.is_dir() {
                    if let Ok(repo_name) = path.file_name().into_string() {
                        repositories.push(repo_name);
                    }
                }
            }
        }
    }
    Ok(Json(RepositoryInfo {
        repositories
    }))
}

#[post("/v2/{repo_name:.*}/blobs/uploads")]
async fn handle_post(data: Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let uuid = Uuid::new_v4();
    let upload_path = data.get_upload_path(&format!("{}/blobs/uploads/{}", repo_name, uuid));

    let mut dir_builder = DirBuilder::new();
    dir_builder.recursive(true)
        .create(
            upload_path.parent().unwrap()
        ).map_err(|e| { ErrorBadRequest(format!("failed to create dir {:?}", e)) })?;

    File::create(&upload_path).map(|_| {
        HttpResponseBuilder::new(StatusCode::ACCEPTED)
            .insert_header((header::LOCATION, format!("/v2/{}/blobs/uploads/{}", &repo_name, uuid)))
            .finish()
    }).map_err(|err| {
        MyError {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: "UNKNOWN".to_string(),
            message: format!("Failed to create file {:?}: {:?}", upload_path, err),
        }
    })
}

#[patch("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_patch(data: Data<AppState>, req: HttpRequest, mut payload: web::Payload) -> Result<HttpResponse, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let uuid = req.match_info().get("uuid").ok_or(ErrorBadRequest("uuid not present"))?;
    let upload_path = data.get_upload_path(&format!("{}/blobs/uploads/{}", repo_name, uuid));
    let mut dir_builder = DirBuilder::new();

    let mut body_content = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|payload_error| { ErrorBadRequest(format!("Unable to read stream: {:?}", payload_error)) })?;
        body_content.extend_from_slice(&chunk);
    }

    println!("creating dir: {:?}", upload_path.parent());
    println!("headers: size: {}", body_content.as_ref().len());
    dir_builder.recursive(true).create(upload_path.parent().unwrap()).unwrap();
    println!("writing to file {:?}", upload_path);

    let mut file = fs::OpenOptions::new().append(true).open(&upload_path)
        .map_err(|err| MyError::new(StatusCode::INTERNAL_SERVER_ERROR,
                                    "UNKNOWN",
                                    &format!("Failed to create file {}: {}", upload_path.display(), err)))?;

    file.write_all(body_content.as_ref())
        .map_err(|err| MyError::new(StatusCode::INTERNAL_SERVER_ERROR,
                                    "UNKNOWN",
                                    &format!("Failed to write to file {}: {}", upload_path.display(), err)))?;

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((header::RANGE, format!("0-{}", body_content.as_ref().len())))
        .insert_header(("Docker-Upload-UUID", uuid))
        .finish())
}


#[get("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_get_manifest_by_tag(data: Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let file = get_manifest_file(data, req).map_err(|err| {
        MyError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("Failed to get manifest file: {}", err),
        )
    })?;

    let reader = io::BufReader::new(file);
    let manifest: ManifestV2 = serde_json::from_reader(reader).map_err(|err| {
        MyError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("Failed to parse manifest: {}", err),
        )
    })?;

    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(ContentType::json())
        .json(manifest))
}

#[head("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_head_manifest_by_tag(data: Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let file = get_manifest_file(data, req).map_err(|err| {
        MyError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("Failed to get manifest file: {}", err),
        )
    })?;
    let metadata = file.metadata().map_err(|err| {
        MyError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("Failed to get metadata for manifest: {}", err),
        )
    })?;
    if metadata.len() == 0 || metadata.is_dir() {
        return Err(MyError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("Manifest {:?} not found", file),
        ));
    }
    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header((CONTENT_LENGTH, metadata.len())).finish()
    )
}

fn get_manifest_file(data: Data<AppState>, req: HttpRequest) -> Result<File, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let tag = req.match_info().get("tag").ok_or(ErrorBadRequest("tag not present"))?;
    let manifest_path = data.get_layer_path(&format!("{}/manifests/{}.json", repo_name, tag));
    println!("manifest_path: {}", manifest_path.display());
    let file = File::open(manifest_path)
        .map_err(|err| {
            MyError::new(
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
                &format!("manifest unknown: {} unknown for {}: {:?}", tag, repo_name, err),
            )
        })?;
    Ok(file)
}

#[get("/v2/{repo_name:.*}/{sha}")]
async fn handle_get_layer_by_hash(data: Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let sha = req.match_info().get("sha").ok_or(ErrorBadRequest("layer not present"))?;
    let layer_path = data.get_layer_path(&format!("{}/{}", repo_name, sha));
    let file = actix_files::NamedFile::open_async(&layer_path).await;

    let f = file.map_err(|err| MyError::new(
        StatusCode::NOT_FOUND,
        "LAYER_UNKNOWN",
        &format!("file {} for {} not found: {:?}", sha, repo_name, err),
    ))?;
    if f.metadata().is_dir() {
        return Err(MyError::new(
            StatusCode::NOT_FOUND,
            "LAYER_UNKNOWN",
            &format!("file {} for {} not found: is a directory", sha, repo_name),
        ));
    }
    println!("streaming layer_path: {}", layer_path.display());
    Ok(f.into_response(&req))
}

#[head("/v2/{repo_name:.*}/blobs/{sha}")]
async fn handle_head_layer_by_hash(data: Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let sha = req.match_info().get("sha").ok_or(ErrorBadRequest("sha not present"))?;
    let layer_path = data.get_layer_path(&format!("{}/blobs/{}", repo_name, sha));
    println!("head: layer_path: {}", layer_path.display());

    let file = actix_files::NamedFile::open_async(&layer_path).await;

    let f = file.map_err(|err| MyError::new(
        StatusCode::NOT_FOUND,
        "LAYER_UNKNOWN",
        &format!("file {} for {} not found: {:?}", sha, repo_name, err),
    ))?;
    if f.metadata().is_dir() {
        return Err(MyError::new(
            StatusCode::NOT_FOUND,
            "LAYER_UNKNOWN",
            &format!("file {} for {} not found: is a directory", sha, repo_name),
        ));
    }
    println!("streaming layer_path: {}", layer_path.display());
    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .finish())
}

#[derive(serde::Deserialize)]
struct DigestParam {
    digest: String,
}

#[put("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_put_with_digest(data: Data<AppState>,
                                digest_param: web::Query<DigestParam>,
                                req: HttpRequest) -> Result<HttpResponse, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let uuid = req.match_info().get("uuid").ok_or(ErrorBadRequest("uuid not present"))?;

    let layer_path = format!("{}/blobs/{}", repo_name, digest_param.digest);
    let upload_path = data.get_upload_path(&format!("{}/blobs/uploads/{}", repo_name, uuid));
    let path_to_file = data.get_layer_path(&layer_path);
    println!("Moving upload_path: {} to path_to_file: {}", upload_path.display(), path_to_file.display());
    fs::rename(upload_path, path_to_file).unwrap();

    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header((header::LOCATION, format!("/v2/{}", &layer_path)))
        .finish())
}


#[put("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_put_manifest_by_tag(data: Data<AppState>, req: HttpRequest, mut payload: web::Payload) -> Result<HttpResponse, MyError> {
    let repo_name = req.match_info().get("repo_name").ok_or(ErrorBadRequest("repo_name not present"))?;
    let tag = req.match_info().get("tag").ok_or(ErrorBadRequest("tag not present"))?;
    let manifest_path = data.get_layer_path(&format!("{}/manifests/{}.json", repo_name, tag));
    println!("manifest_path: {}", manifest_path.display());

    let mut dir_builder = DirBuilder::new();
    dir_builder.recursive(true).create(manifest_path.parent().ok_or(ErrorBadRequest("manifest_path has no parent"))?).map_err(|err| MyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        &format!("Error creating manifest dir: {:?}", err),
    ))?;

    let mut manifest_file = File::create(&manifest_path).map_err(|err| MyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        &format!("Error creating manifest file: {:?}", err),
    ))?;

    let mut body_content = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|payload_error| { ErrorBadRequest(format!("Unable to read stream: {:?}", payload_error)) })?;
        body_content.extend_from_slice(&chunk);
    }

    manifest_file.write_all(&body_content).map_err(|err| MyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        &format!("Error writing blob: {:?}", err),
    ))?;
    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header((header::LOCATION, format!("/v2/{}/manifests/{}", repo_name, tag)))
        .finish())
}


// println!("Upload blob: {}", path);
// let (repo_name, tag) = parse_repo_name_and_tag(path.trim_start_matches("/v2/"));
// let blob_path = self.storage_path.join(repo_name).join(format!("{}.json", tag));
// println!("Uploading blob: {} to: {:?}", path, &blob_path);
// let mut dir_builder = DirBuilder::new();
// dir_builder.recursive(true).create(blob_path.parent().unwrap()).unwrap();
// if let Ok(mut file) = File::create(blob_path) {
//     if let Err(e) = file.write_all(&(body_content.as_ref().unwrap())) {
//         return Ok(Response::new(Body::from(format!("Error writing blob: {}", e))));
//     }
//     let response = Response::builder()
//         .status(201)
//         .header(CONTENT_TYPE, "application/json")
//         .header(CONTENT_LENGTH, "0")
//         .body(Body::empty())
//         .unwrap();
//     return Ok(response);
// }
// println!("Failed uploading blob: {}", path);
// let response_body = json!({
//             "errors": [
//                 {
//                     "code": "BLOB_UNKNOWN",
//                     "message": "blob unknown",
//                 },
//             ]
//         });
// let response = Response::builder()
//     .status(404)
//     .header(CONTENT_TYPE, "application/json")
//     .body(Body::from(response_body.to_string()))
//     .unwrap();
// return Ok(response);


//         (&Method::GET, path) if path.starts_with("/v2/") => { self.handle_get(path) }
//         (&Method::HEAD, path) if path.starts_with("/v2/") && path.contains("/blobs/") => { self.handle_head(path) }
//         (&Method::PUT, path)  if path.starts_with("/v2/") => { self.handle_put(&parts, &body_content, path) }

async fn handle_default(req: HttpRequest) -> HttpResponse {
    println!("default: {:#?}", req);
    let errors = AppErrors {
        errors: vec![
            AppError {
                code: "UNSUPPORTED".to_string(),
                message: "Unsupported operation".to_string(),
            }
        ]
    };
    HttpResponseBuilder::new(StatusCode::NOT_FOUND).json(errors)
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let config: HashMap<String, Value> = serde_json::from_reader(File::open("config.json").unwrap()).unwrap();
    let storage_path: PathBuf = PathBuf::from(config.get("storage_path").unwrap().as_str().unwrap());
    let registry = Registry::new(storage_path);
    let arc_registry = Arc::new(registry);
    // let addr = ([0, 0, 0, 0], 8000).into();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState {
                registry: arc_registry.clone(),
            }))
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::Logger::default())
            .service(handle_get_v2)
            .service(handle_v2_catalog)
            .service(handle_post)
            .service(handle_patch)
            .service(handle_head_manifest_by_tag)
            .service(handle_get_manifest_by_tag)
            .service(handle_get_layer_by_hash)
            .service(handle_head_layer_by_hash)
            .service(handle_put_with_digest)
            .service(handle_put_manifest_by_tag)
            .default_service(web::route().to(handle_default))
    })
        .bind(("::0", 8080))?
        .run()
        .await
}

