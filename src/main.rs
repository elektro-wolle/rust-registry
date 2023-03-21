use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::BufReader;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::{App, Error, get, head, http::header, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, middleware, patch, post, put, Result, web};
use actix_web::dev::ServiceRequest;
use actix_web::error::ErrorBadRequest;
use actix_web::http::header::CONTENT_LENGTH;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Payload};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use futures_util::StreamExt;
use log::{debug, info, trace};
use path_clean::PathClean;
use ring::digest::{Context, SHA256};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use serde::{Deserialize, Serialize};
use uuid::*;

use crate::error::*;
#[cfg(feature = "ldap")]
use crate::ldap::*;

mod ldap;
mod error;

#[derive(Debug, Clone, Deserialize)]
struct Registry {
    storage_path: String,
    #[serde(default = "default_http_port")]
    port: u16,
    tls_config: Option<TlsConfig>,
    #[cfg(feature = "ldap")]
    ldap_config: Option<LdapConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct TlsConfig {
    cert: String,
    key: String,
    #[serde(default = "default_https_port")]
    port: u16,
}

fn default_http_port() -> u16 {
    8080
}

fn default_https_port() -> u16 {
    8443
}

struct AppState {
    registry: Arc<Registry>,
}

struct UploadedFile {
    sha256: String,
    size: u64,
}

fn get_layer_path(_req: &HttpRequest, path: &String) -> PathBuf {
    let registry = _req.app_data::<Data<AppState>>().unwrap().registry.clone();
    // clean() will remove any "." and ".." from the path
    let sub_path = PathBuf::from(format!("/{}", path)).clean();
    let target_path = format!("{}/{}", registry.storage_path, sub_path.display());
    // second clean() to ensure that the path is clean
    PathBuf::from(target_path).clean()
}

/**
Upload file and calculate sha256
 */
async fn write_payload_to_file(
    payload: &mut Payload,
    target_path: &PathBuf,
) -> Result<UploadedFile, RegistryError> {
    let mut manifest_file = create_or_replace_file(target_path)?;
    let mut context = Context::new(&SHA256);
    while let Some(chunk) = payload.next().await {
        let mut body_content = web::BytesMut::new();
        body_content.extend_from_slice(&chunk?);
        context.update(&body_content);
        manifest_file.write_all(&body_content)?;
    }
    Ok(UploadedFile {
        sha256: hex::encode(context.finish()),
        size: target_path.metadata()?.len(),
    })
}

fn create_or_replace_file(path_to_file: &PathBuf) -> Result<File, RegistryError> {
    let mut dir_builder = DirBuilder::new();
    trace!("creating dir: {:?}, saving file {:?}", path_to_file.parent(), path_to_file);

    dir_builder
        .recursive(true)
        .create(path_to_file.parent().ok_or(ErrorBadRequest("invalid path"))?)
        .map_err(ErrorBadRequest)?;

    let manifest_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path_to_file)?;
    Ok(manifest_file)
}

fn lookup_manifest_file(req: HttpRequest, info: &ImageNameWithTag) -> Result<File, RegistryError> {
    let manifest_path = get_layer_path(&req, &format!("{}/manifests/{}.json", info.repo_name, info.tag));
    debug!("manifest_path: {}", manifest_path.display());
    let file = File::open(manifest_path).map_err(map_to_not_found)?;
    Ok(file)
}

#[get("/v2/")]
async fn handle_get_v2() -> Result<HttpResponse, Error> {
    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .json(VersionInfo {
            versions: vec!["registry/2.0".to_string()],
        }))
}

#[get("/v2/_catalog")]
async fn handle_v2_catalog(data: Data<AppState>) -> Result<Json<RepositoryInfo>, Error> {
    let storage_path = data.registry.storage_path.clone();
    let mut repositories = Vec::new();
    let read_dir = fs::read_dir(storage_path)?;

    for path in read_dir.flatten() {
        let file_type = path.file_type()?;
        if file_type.is_dir() {
            let repo_name = path.file_name()
                .into_string()
                .map_err(|_| { ErrorBadRequest(format!("invalid file name: {:?}", path.file_name().to_str())) })?;
            repositories.push(repo_name);
        }
    }
    Ok(Json(RepositoryInfo { repositories }))
}

#[post("/v2/{repo_name:.*}/blobs/uploads/")]
async fn handle_post(req: HttpRequest) -> Result<HttpResponse, RegistryError> {
    let repo_name = req
        .match_info()
        .get("repo_name")
        .ok_or(ErrorBadRequest("repo_name not present"))?;
    let uuid = Uuid::new_v4();

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((
            header::LOCATION,
            format!("/v2/{}/blobs/uploads/{}", &repo_name, uuid),
        ))
        .finish())
}

#[derive(Serialize)]
struct VersionInfo {
    versions: Vec<String>,
}

#[derive(Serialize)]
struct RepositoryInfo {
    repositories: Vec<String>,
}

#[derive(Deserialize)]
struct ImageNameWithUUID {
    repo_name: String,
    uuid: String,
}

#[patch("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_patch(
    info: web::Path<ImageNameWithUUID>,
    req: HttpRequest,
    mut payload: Payload,
) -> Result<HttpResponse, RegistryError> {
    let upload_path = get_layer_path(&req, &format!("{}/blobs/uploads/{}", info.repo_name, info.uuid));
    let uploaded_file = write_payload_to_file(&mut payload, &upload_path).await?;

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((header::RANGE, format!("0-{}", uploaded_file.size)))
        .insert_header(("Docker-Upload-UUID", info.uuid.as_str()))
        .insert_header(("Docker-Content-Digest", format!("sha256:{}", uploaded_file.sha256)))
        .finish())
}


#[derive(Deserialize)]
struct ImageNameWithTag {
    repo_name: String,
    tag: String,
}

#[get("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_get_manifest_by_tag(
    req: HttpRequest,
    info: web::Path<ImageNameWithTag>,
) -> Result<HttpResponse, RegistryError> {
    let mut file = lookup_manifest_file(req, &info)?;

    // read file as string
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut context = Context::new(&SHA256);
    context.update(&buffer);
    let digest = hex::encode(context.finish());

    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Docker-Content-Digest", format!("sha256:{}", digest)))
        .insert_header((
            "Content-Type",
            "application/vnd.docker.distribution.manifest.v2+json",
        ))
        .body(buffer))
}

#[head("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_head_manifest_by_tag(
    req: HttpRequest,
    info: web::Path<ImageNameWithTag>,
) -> Result<HttpResponse, RegistryError> {
    let file = lookup_manifest_file(req, &info)?;
    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.is_dir() {
        return Err(RegistryError::new(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &format!("Manifest {:?} not found", file),
        ));
    }
    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header((CONTENT_LENGTH, metadata.len()))
        .finish())
}

#[derive(Deserialize, Serialize)]
struct ImageNameWithDigest {
    repo_name: String,
    digest: String,
}

#[get("/v2/{repo_name:.*}/{sha}")]
async fn handle_get_layer_by_hash(
    req: HttpRequest,
    info: web::Path<ImageNameWithDigest>,
) -> Result<HttpResponse, RegistryError> {
    let layer_path = get_layer_path(&req, &format!("{}/{}", info.repo_name, info.digest));
    let file = actix_files::NamedFile::open_async(&layer_path)
        .await
        .map_err(map_to_not_found)?;

    if file.metadata().is_dir() {
        return Err(RegistryError::new(
            StatusCode::NOT_FOUND,
            "LAYER_UNKNOWN",
            &format!("file {} for {} not found: is a directory", info.digest, info.repo_name),
        ));
    }
    debug!("streaming layer_path: {}", layer_path.display());
    Ok(file.into_response(&req))
}

#[head("/v2/{repo_name:.*}/blobs/{sha}")]
async fn handle_head_layer_by_hash(
    req: HttpRequest,
    info: web::Path<ImageNameWithDigest>,
) -> Result<HttpResponse, RegistryError> {
    let layer_path = get_layer_path(&req, &format!("{}/blobs/{}", info.repo_name, info.digest));
    trace!("head: layer_path: {}", layer_path.display());

    let file = actix_files::NamedFile::open_async(&layer_path)
        .await
        .map_err(map_to_not_found)?;

    if file.metadata().is_dir() {
        return Err(RegistryError::new(
            StatusCode::NOT_FOUND,
            "LAYER_UNKNOWN",
            &format!("file {} for {} not found: is a directory", info.digest, info.repo_name),
        ));
    }
    debug!("return layer_path: {}", layer_path.display());
    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header((CONTENT_LENGTH, file.metadata().len()))
        .insert_header(("Docker-Content-Digest", info.digest.to_string()))
        .finish())
}

#[derive(serde::Deserialize)]
struct DigestParam {
    digest: String,
}

#[put("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_put_with_digest(
    digest_param: web::Query<DigestParam>,
    info: web::Path<ImageNameWithUUID>,
    req: HttpRequest,
) -> Result<HttpResponse, RegistryError> {
    let layer_path = format!("{}/blobs/{}", info.repo_name, digest_param.digest);
    let upload_path = get_layer_path(&req, &format!("{}/blobs/uploads/{}", info.repo_name, info.uuid));
    let path_to_file = get_layer_path(&req, &layer_path);

    trace!("Moving upload_path: {} to path_to_file: {}", upload_path.display(), path_to_file.display());
    fs::rename(upload_path, path_to_file).map_err(map_to_not_found)?;

    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header((header::LOCATION, format!("/v2/{}", &layer_path)))
        .finish())
}

#[put("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_put_manifest_by_tag(
    req: HttpRequest,
    info: web::Path<ImageNameWithTag>,
    mut payload: Payload,
) -> Result<HttpResponse, RegistryError> {
    let manifest_path = get_layer_path(&req, &format!("{}/manifests/{}.json", info.repo_name, info.tag));
    debug!("manifest_path: {}", manifest_path.display());

    let uploaded_path = write_payload_to_file(&mut payload, &manifest_path).await?;

    // manifest is stored as tag and sha256:digest
    let manifest_digest_path =
        get_layer_path(&req, &format!("{}/manifests/sha256:{}.json", info.repo_name, uploaded_path.sha256));
    trace!("manifest_path: {} linked as {}", &manifest_path.display(), manifest_digest_path.display());

    // unlink the old manifest if it exists
    if manifest_digest_path.exists() {
        fs::remove_file(&manifest_digest_path)?;
    }
    fs::hard_link(&manifest_path, &manifest_digest_path)?;

    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header(("Docker-Content-Digest", format!("sha256:{}", uploaded_path.sha256)))
        .insert_header((header::LOCATION, format!("/v2/{}/manifests/{}", info.repo_name, info.tag)))
        .finish())
}

async fn handle_default(req: HttpRequest) -> HttpResponse {
    info!("default: {:#?}", req);
    let errors = AppErrors {
        errors: vec![AppError {
            code: "UNSUPPORTED".to_string(),
            message: "Unsupported operation".to_string(),
        }],
    };
    HttpResponseBuilder::new(StatusCode::NOT_FOUND).json(errors)
}

fn load_rustls_config(tls_config: &TlsConfig) -> ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(File::open(&tls_config.cert).unwrap());
    let key_file = &mut BufReader::new(File::open(&tls_config.key).unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = rsa_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}

pub async fn user_authorization_check(
    req: ServiceRequest,
    credentials: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let basic_auth: Option<String> =
        match req.headers().get("authorization") {
            Some(h) if !h.is_empty() && h.to_str().is_ok() => {
                let auth = h.to_str().unwrap();
                auth.strip_prefix("Basic ")
                    .map(|s| s.to_string())
            }
            _ => None
        };
    let bearer_auth = credentials.map(|c| { c.token().to_string() });

    trace!("user_authorization_check: basic: {:?}, bearer: {:?}", basic_auth, bearer_auth);
    Ok(req)
    //Err((ErrorUnauthorized("Unauthorized"), req))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let registry_config: Registry =
        serde_json::from_reader(File::open("config.json").unwrap()).unwrap();
    let tls_config = registry_config
        .tls_config
        .clone()
        .map(|cfg| load_rustls_config(&cfg));
    let http_port = registry_config.port;
    let https_port = registry_config.tls_config.as_ref().map(|cfg| cfg.port);

    let app_data = Data::new(AppState {
        registry: Arc::new(registry_config),
    });

    let mut server = HttpServer::new(move || {
        App::new()
            .wrap(HttpAuthentication::with_fn(user_authorization_check))
            .app_data(Data::clone(&app_data))
            .wrap(actix_cors::Cors::permissive()
                .allow_any_origin()
                .allow_any_method())
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
        .bind(format!("[::0]:{}", http_port))?;

    match &tls_config {
        Some(cfg) => server = server
            .bind_rustls(format!("[::0]:{}", https_port.unwrap()), cfg.clone())?,
        None => {}
    }

    server.run().await
}

#[cfg(test)]
mod tests {
    use actix_web::{http::header::ContentType, test};

    use super::*;

    #[actix_web::test]
    async fn test_get_upload_path() {
        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .app_data(Data::new(AppState {
                registry: Arc::new(Registry {
                    storage_path: "/tmp".to_string(),
                    port: 8080,
                    tls_config: None,
                    #[cfg(feature = "ldap")]
                    ldap_config: None,
                }),
            }))
            .to_http_request();

        let path = "foo/bar".to_string();
        let upload_path = get_layer_path(&req, &path);
        assert_eq!(upload_path, PathBuf::from("/tmp/foo/bar"));
    }

    #[actix_web::test]
    async fn test_create_or_replace_file() {
        let uuid = Uuid::new_v4();
        let path_to_file = PathBuf::from(format!("/tmp/foo/bar/{}/sample", uuid));
        assert!(path_to_file.metadata().is_err());

        let manifest_file = create_or_replace_file(&path_to_file).unwrap();
        assert!(manifest_file.metadata().unwrap().is_file());
        assert_eq!(manifest_file.metadata().unwrap().len(), 0);
        // delete path_to_file
        fs::remove_file(&path_to_file).unwrap();
        fs::remove_dir(path_to_file.parent().unwrap()).unwrap();
    }

    #[actix_web::test]
    #[cfg(feature = "ldap")]
    async fn test_ldap() {
        env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));
        let cfg = LdapConfig {
            ldap_url: "ldap://localhost:11389".to_string(),
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: "adminpassword".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            group_search_filter: "(&(objectClass=groupOfNames)(member={}))".to_string(),
            group_attribute: "cn".to_string(),
            user_search_filter: "(&(objectClass=inetOrgPerson)(uid={}))".to_string(),
            group_search_base_dn: "dc=example,dc=com".to_string(),
            user_search_base_dn: "dc=example,dc=com".to_string(),
        };

        let groups = authenticate_and_get_groups(&cfg, "user02", "bitnami2").await.unwrap();
        assert_eq!(groups, vec!["readers"]);
        info!("Groups: {:?}", groups);
    }
}
