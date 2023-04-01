use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::{App, Error, get, head, http::header, HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, middleware, patch, post, put, Result, web};
use actix_web::dev::ServiceRequest;
use actix_web::error::{ErrorBadRequest, ErrorForbidden};
use actix_web::http::header::CONTENT_LENGTH;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Payload};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use futures_util::StreamExt;
use lazy_static::lazy_static;
use log::{debug, info, trace};
use path_clean::PathClean;
use ring::digest::{Context, SHA256};
use tokio::sync::Mutex;
use uuid::*;

use crate::api_objects::*;
#[cfg(feature = "ldap")]
use crate::authentication::*;
use crate::configuration::*;
use crate::error::*;

#[cfg(feature = "ldap")]
mod ldap;
mod error;

mod api_objects {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct ImageNameWithDigest {
        pub repo_name: String,
        pub digest: String,
    }

    pub struct UploadedFile {
        pub sha256: String,
        pub size: u64,
    }

    #[derive(Serialize)]
    pub struct RepositoryInfo {
        pub repositories: Vec<String>,
    }

    #[derive(Deserialize)]
    pub struct ImageNameWithUUID {
        pub repo_name: String,
        pub uuid: String,
    }

    #[derive(Deserialize)]
    pub struct ImageNameWithTag {
        pub repo_name: String,
        pub tag: String,
    }

    #[derive(serde::Deserialize)]
    pub struct DigestParam {
        pub digest: String,
    }

    #[derive(Serialize)]
    pub struct VersionInfo {
        pub versions: Vec<String>,
    }
}

mod configuration {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::BufReader;

    use async_trait::async_trait;
    use rustls::{Certificate, PrivateKey, ServerConfig};
    use rustls_pemfile::{certs, rsa_private_keys};
    use serde::Deserialize;

    #[cfg(feature = "ldap")]
    use crate::ldap::LdapConfig;

    pub trait SocketSpecification: StorageSpecification {
        fn get_bind_address(&self) -> String;
        fn get_tls_config(&self) -> Option<TlsConfig>;
    }

    #[async_trait]
    pub trait StorageSpecification {
        fn get_storage_path(&self) -> String;
        // async fn load_manifest_by_tag(&self, image: &ImageNameWithTag);
        // async fn load_manifest_by_digest(&self, image: &ImageNameWithDigest);
        // async fn load_blob_by_digest(&self, image: &ImageNameWithDigest);
        // async fn load_blob_by_tag(&self, image: &ImageNameWithTag);
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Repository {
        pub storage_path: String,
        #[serde(default = "default_http_port")]
        pub bind_address: String,
        pub tls_config: Option<TlsConfig>,
    }

    impl StorageSpecification for Repository {
        fn get_storage_path(&self) -> String {
            self.storage_path.clone()
        }
    }

    impl SocketSpecification for Repository {
        fn get_bind_address(&self) -> String {
            self.bind_address.clone()
        }
        fn get_tls_config(&self) -> Option<TlsConfig> {
            self.tls_config.clone()
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Proxy {
        pub storage_path: String,
        #[serde(default = "default_http_port")]
        pub bind_address: String,
        pub tls_config: Option<TlsConfig>,
        pub remote_url: String,
    }


    #[derive(Debug, Clone, Deserialize)]
    pub struct Registry {
        pub repositories: HashMap<String, Repository>,
        pub proxies: HashMap<String, Proxy>,
        #[cfg(feature = "ldap")]
        pub ldap_config: Option<LdapConfig>,
    }

    pub struct NamedRepository {
        pub name: String,
        pub repository: Option<Repository>,
        pub proxy: Option<Proxy>,
    }

    impl StorageSpecification for NamedRepository {
        fn get_storage_path(&self) -> String {
            if let Some(proxy) = &self.proxy {
                proxy.storage_path.clone()
            } else if let Some(repo) = &self.repository {
                repo.storage_path.clone()
            } else {
                panic!("Neither repository nor proxy is set for this request")
            }
        }
    }

    pub trait TlsServerConfiguration {
        fn load_rustls_config(self: &Self) -> ServerConfig;
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct TlsConfig {
        pub cert: String,
        pub key: String,
        #[serde(default = "default_https_port")]
        pub bind_address: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct UserRoles {
        pub username: String,
        pub roles: Vec<String>,
    }

    fn default_http_port() -> String {
        "[::]:8080".to_string()
    }

    fn default_https_port() -> String {
        "[::]:8443".to_string()
    }

    impl TlsServerConfiguration for TlsConfig {
        fn load_rustls_config(self: &TlsConfig) -> ServerConfig {
            // init server config builder with safe defaults
            let config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth();

            // load TLS key/cert files
            let cert_file = &mut BufReader::new(File::open(&self.cert).unwrap());
            let key_file = &mut BufReader::new(File::open(&self.key).unwrap());

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
    }
}

#[cfg(feature = "ldap")]
mod authentication {
    use actix_web::http::StatusCode;
    use base64::{alphabet, engine, Engine};
    use base64::engine::general_purpose;

    use crate::configuration::{Registry, UserRoles};
    use crate::error::RegistryError;
    use crate::ldap::authenticate_and_get_groups;

    pub async fn get_roles_for_authentication(basic_auth: Option<String>, reg_arc: &Registry) -> Result<UserRoles, RegistryError> {
        let auth = basic_auth.ok_or_else(|| RegistryError::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", &"Unauthorized, no basic auth".to_string()))?;
        let engine = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);
        let decoded = engine
            .decode(auth.as_bytes())
            .map_err(|_| RegistryError::new(StatusCode::FORBIDDEN, "FORBIDDEN", &"Unauthorized, invalid base64".to_string()))?;

        let decoded_str = String::from_utf8(decoded)
            .map_err(|_| RegistryError::new(StatusCode::FORBIDDEN, "FORBIDDEN", &"Unauthorized, invalid utf8".to_string()))?;

        let parts: Vec<&str> = decoded_str.split(':').collect();

        if parts.len() != 2 {
            return Err(RegistryError::new(StatusCode::FORBIDDEN, "FORBIDDEN", &"Unauthorized, wrong format".to_string()));
        }

        let username = parts[0].to_string();
        let password = parts[1].to_string();

        let ldap = reg_arc.ldap_config.as_ref();

        match ldap {
            Some(ldap) => {
                let roles = authenticate_and_get_groups(
                    ldap,
                    &username,
                    &password).await
                    .map_err(|e| {
                        RegistryError::new(
                            StatusCode::FORBIDDEN,
                            "FORBIDDEN",
                            &format!("Unauthorized, ldap error: {}", e),
                        )
                    })?;
                if roles.is_empty() {
                    Err(RegistryError::new(
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        &"Unauthorized, no ldap groups".to_string()))
                } else {
                    Ok(UserRoles { username, roles })
                }
            }
            _ => Err(RegistryError::new(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &"Unauthorized, no ldap config".to_string()))
        }
    }
}

pub struct AppState {
    pub registry: Arc<Registry>,
}

fn get_layer_path(_req: &HttpRequest, path: &String) -> PathBuf {
    let extensions = _req.extensions();
    let repo: &NamedRepository = extensions.get().unwrap();
    // clean() will remove any "." and ".." from the path
    let sub_path = PathBuf::from(format!("/{}", path)).clean();
    let target_path = format!("{}/{}", repo.get_storage_path(), sub_path.display());

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
async fn handle_get_v2(req: HttpRequest) -> Result<HttpResponse, Error> {
    let ext = req.extensions();
    let user_with_roles = ext.get::<UserRoles>().ok_or(ErrorBadRequest("no user roles"))?;
    info!("userWithRoles: {:?}", user_with_roles);

    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .json(VersionInfo {
            versions: vec!["registry/2.0".to_string()],
        }))
}

#[get("/v2/_catalog")]
async fn handle_v2_catalog(req: HttpRequest) -> Result<Json<RepositoryInfo>, Error> {
    let ext = req.extensions();
    let repo = ext.get::<Repository>().unwrap();

    let storage_path = &repo.storage_path;
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

fn ensure_write_access(req: &HttpRequest) -> Result<(), RegistryError> {
    let ext = req.extensions();
    let repo = ext.get::<NamedRepository>().unwrap();
    info!("repo: {:?}", repo.name);
    if repo.repository.is_none() {
        return Err(RegistryError::new(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &format!("Unauthorized, no writable repo: {}", repo.name)));
    }

    let user_with_roles = ext.get::<UserRoles>().ok_or(ErrorBadRequest("no user roles"))?;
    info!("userWithRoles: {:?}", user_with_roles);

    Ok(())
}

fn ensure_read_access(req: &HttpRequest) -> Result<(), RegistryError> {
    let ext = req.extensions();
    let user_with_roles = ext.get::<UserRoles>().ok_or(ErrorBadRequest("no user roles"))?;
    info!("userWithRoles: {:?}", user_with_roles);

    let repo = ext.get::<NamedRepository>().unwrap();
    info!("repo: {:?}", repo.name);

    Ok(())
}

#[post("/v2/{repo_name:.*}/blobs/uploads/")]
async fn handle_post(req: HttpRequest) -> Result<HttpResponse, RegistryError> {
    let repo_name = req
        .match_info()
        .get("repo_name")
        .ok_or(ErrorBadRequest("repo_name not present"))?;
    let uuid = Uuid::new_v4();

    ensure_write_access(&req)?;

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((
            header::LOCATION,
            format!("/v2/{}/blobs/uploads/{}", &repo_name, uuid),
        ))
        .finish())
}

#[patch("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_patch(
    info: web::Path<ImageNameWithUUID>,
    req: HttpRequest,
    mut payload: Payload,
) -> Result<HttpResponse, RegistryError> {
    ensure_write_access(&req)?;

    let upload_path = get_layer_path(&req, &format!("{}/blobs/uploads/{}", info.repo_name, info.uuid));
    let uploaded_file = write_payload_to_file(&mut payload, &upload_path).await?;

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((header::RANGE, format!("0-{}", uploaded_file.size)))
        .insert_header(("Docker-Upload-UUID", info.uuid.as_str()))
        .insert_header(("Docker-Content-Digest", format!("sha256:{}", uploaded_file.sha256)))
        .finish())
}

#[get("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_get_manifest_by_tag(
    req: HttpRequest,
    info: web::Path<ImageNameWithTag>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req)?;

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
    ensure_read_access(&req)?;

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

#[get("/v2/{repo_name:.*}/{digest}")]
async fn handle_get_layer_by_hash(
    req: HttpRequest,
    info: web::Path<ImageNameWithDigest>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req)?;

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

#[head("/v2/{repo_name:.*}/blobs/{digest}")]
async fn handle_head_layer_by_hash(
    req: HttpRequest,
    info: web::Path<ImageNameWithDigest>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req)?;

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


#[put("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_put_with_digest(
    digest_param: web::Query<DigestParam>,
    info: web::Path<ImageNameWithUUID>,
    req: HttpRequest,
) -> Result<HttpResponse, RegistryError> {
    ensure_write_access(&req)?;

    let layer_path = format!("{}/blobs/{}", info.repo_name, digest_param.digest);
    let upload_path = get_layer_path(&req, &format!("{}/blobs/uploads/{}", info.repo_name, info.uuid));
    let path_to_file = get_layer_path(&req, &layer_path);

    // mutex to prevent concurrent writes to the same file
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
    ensure_write_access(&req)?;

    lazy_static! {
        static ref LOCK_MUTEX:Mutex<u16> = Mutex::new(0);
    }

    let manifest_path = get_layer_path(&req, &format!("{}/manifests/{}.json", info.repo_name, info.tag));
    debug!("manifest_path: {}", manifest_path.display());

    let uploaded_path = write_payload_to_file(&mut payload, &manifest_path).await?;

    // manifest is stored as tag and sha256:digest
    let manifest_digest_path =
        get_layer_path(&req, &format!("{}/manifests/sha256:{}.json", info.repo_name, uploaded_path.sha256));
    trace!("manifest_path: {} linked as {}", &manifest_path.display(), manifest_digest_path.display());

    // lock to prevent concurrent writes to the same file
    let lock = LOCK_MUTEX.lock().await;
    if manifest_digest_path.exists() {
        fs::remove_file(&manifest_digest_path)?;
    }
    fs::hard_link(&manifest_path, &manifest_digest_path)?;
    drop(lock);

    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header(("Docker-Content-Digest", format!("sha256:{}", uploaded_path.sha256)))
        .insert_header((header::LOCATION, format!("/v2/{}/manifests/{}", info.repo_name, info.tag)))
        .finish())
}

async fn handle_default(req: HttpRequest) -> HttpResponse {
    info!("default: {:#?}", req);
    let errors = AppErrors {
        errors: vec![AppError {
            code: "NOT_FOUND".to_string(),
            message: "Unsupported operation".to_string(),
            detail: None,
        }],
    };
    HttpResponseBuilder::new(StatusCode::NOT_FOUND).json(errors)
}

pub async fn user_authorization_check(
    req: ServiceRequest,
    credentials: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let req = insert_resolved_repo(req)?;
    #[cfg(feature = "ldap")]
    {
        let basic_auth: Option<String> = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Basic "))
            .map(|s| s.to_string());

        let bearer_auth = credentials.map(|c| c.token().to_string());

        let app_config = req.app_data::<Data<AppState>>();
        let reg_arc = app_config.unwrap().registry.as_ref();

        match get_roles_for_authentication(basic_auth, reg_arc).await {
            Ok(user) => {
                req.extensions_mut().insert(user);
                Ok(req)
            }
            Err(e) =>
                Err((e.into(), req)),
        }
    }
    #[cfg(not(feature = "ldap"))]
    {
        let anon_user = UserRoles {
            username: "anonymous".to_string(),
            roles: vec!["*".to_string()],
        };
        req.extensions_mut().insert(anon_user);
        Ok(req)
    }
}

fn insert_resolved_repo(req: ServiceRequest) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let request_host = req.app_config().host();
    let is_tls = req.app_config().secure();
    let reg = req.app_data::<Data<AppState>>().unwrap().as_ref();
    let app_config = reg.registry.as_ref();

    let repo = if is_tls {
        app_config.repositories.iter().find(|&r| {
            let tls_cfg = r.1.tls_config.as_ref().unwrap();
            tls_cfg.bind_address == request_host
        })
    } else {
        app_config.repositories.iter().find(|&r| r.1.bind_address == request_host)
    };

    let proxy = if is_tls {
        app_config.proxies.iter().find(|&r| {
            let tls_cfg = r.1.tls_config.as_ref().unwrap();
            tls_cfg.bind_address == request_host
        })
    } else {
        app_config.proxies.iter().find(|&r| r.1.bind_address == request_host)
    };

    let named_repo = match (repo, proxy) {
        (Some(r), _) => {
            Some(NamedRepository {
                name: r.0.clone(),
                repository: Some(r.1.clone()),
                proxy: None,
            })
        }
        (_, Some(p)) => {
            Some(NamedRepository {
                name: p.0.clone(),
                repository: None,
                proxy: Some(p.1.clone()),
            })
        }
        _ => None
    };

    match named_repo {
        Some(r) => {
            trace!("insert_resolved_repo: request_host: {}, is_tls: {}, repo: {:?}", request_host, is_tls, repo);
            req.extensions_mut().insert(r);
            Ok(req)
        }
        None => Err((RegistryError::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            &format!("Not found, no repo config for host {}", request_host)).into(), req)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info,rust_registry=trace"));

    let registry_config: Registry =
        serde_json::from_reader(File::open("config.json").unwrap()).unwrap();

    let app_data = Data::new(AppState {
        registry: Arc::new(registry_config.clone()),
    });

    let server = HttpServer::new(move || {
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
            .service(handle_head_layer_by_hash)
            .service(handle_head_manifest_by_tag)
            .service(handle_get_manifest_by_tag)
            .service(handle_get_layer_by_hash)
            .service(handle_put_with_digest)
            .service(handle_put_manifest_by_tag)
            .default_service(web::route().to(handle_default))
    });

    let http_binds = registry_config
        .repositories
        .iter()
        .map(|repo| &repo.1.bind_address)
        .collect::<Vec<&String>>();

    let https_cfgs = registry_config
        .repositories
        .iter()
        .filter_map(|repo| repo.1.tls_config.as_ref())
        .collect::<Vec<&TlsConfig>>();

    let server = http_binds.into_iter().fold(server, |s, x| {
        trace!("binding http: {}", x);
        s.bind(x).unwrap()
    });
    let server = https_cfgs.into_iter().fold(server, |s, cfg| {
        let tls_config = cfg.load_rustls_config();
        trace!("binding https: {}", &cfg.bind_address);
        s.bind_rustls(&cfg.bind_address, tls_config).unwrap()
    });

    server.run().await
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use actix_web::{http::header::ContentType, test};

    use super::*;

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        let _ = env_logger::try_init();
    }

    #[actix_web::test]
    async fn test_get_upload_path() {
        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .app_data(build_app_data())
            .to_http_request();

        let repo = Repository {
            storage_path: "/tmp".to_string(),
            bind_address: "[::]:8080".to_string(),
            tls_config: None,
        };
        req.extensions_mut().insert(NamedRepository {
            name: "repo1".to_string(),
            repository: Some(repo),
            proxy: None,
        });

        let path = "foo/bar".to_string();
        let upload_path = get_layer_path(&req, &path);
        assert_eq!(upload_path, PathBuf::from("/tmp/foo/bar"));
    }

    fn build_app_data() -> Data<AppState> {
        Data::new(AppState {
            registry: Arc::new(Registry {
                repositories: HashMap::from([("repo1".to_string(), Repository {
                    storage_path: "/tmp".to_string(),
                    bind_address: "[::]:8080".to_string(),
                    tls_config: None,
                })]),
                proxies: HashMap::new(),
                #[cfg(feature = "ldap")]
                ldap_config: None,
            }),
        })
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
    async fn test_put_upload() {
        let uuid = Uuid::new_v4();

        let path_to_file = PathBuf::from(format!("/tmp/foo/bar/blobs/uploads/{}", uuid));
        create_or_replace_file(&path_to_file).unwrap();

        let path_to_target_file = PathBuf::from("/tmp/foo/bar/blobs/123");
        fs::remove_file(&path_to_target_file).unwrap_or(());
        assert!(!path_to_target_file.exists());

        let app = test::init_service(
            App::new()
                .app_data(build_app_data())
                .service(handle_put_with_digest)
        ).await;

        let req =
            test::TestRequest::put()
                .uri(format!("/v2/foo/bar/blobs/uploads/{}?digest=123", uuid).as_str())
                .to_request();

        req.extensions_mut().insert(NamedRepository {
            name: "repo1".to_string(),
            repository: Some(Repository {
                storage_path: "/tmp".to_string(),
                bind_address: "[::]:8080".to_string(),
                tls_config: None,
            }),
            proxy: None,
        });

        let resp = test::call_service(&app, req).await;

        assert!(path_to_target_file.exists());
        assert!(!path_to_file.exists());
        assert_eq!(resp.status(), StatusCode::CREATED);
        fs::remove_file(&path_to_target_file).unwrap_or(());
    }
}
