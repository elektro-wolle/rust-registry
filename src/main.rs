use std::collections::HashMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::{
    App, Error, get, head, http::header, HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, middleware,
    patch, post, put, Result, web,
};
use actix_web::error::ErrorBadRequest;
use actix_web::http::header::CONTENT_LENGTH;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Path, Payload};
use actix_web_httpauth::middleware::HttpAuthentication;
use futures_util::StreamExt;
use lazy_static::lazy_static;
use log::{debug, info, trace};
use ring::digest::{Context, SHA256};
use tokio::sync::Mutex;
use uuid::*;

use crate::api_objects::*;
use crate::authentication::*;
use crate::configuration::*;
use crate::error::*;
use crate::perm::*;
use crate::utils::{create_or_replace_file, resolve_layer_path, resolve_manifest_file};

mod api_objects;
mod authentication;
mod configuration;
mod error;
#[cfg(feature = "ldap")]
mod ldap;
mod perm;
mod utils;

pub struct AppState {
    pub registry: Arc<Registry>,
    pub permissions: Arc<GroupPermissions>,
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

#[get("/v2/")]
async fn handle_get_v2(req: HttpRequest) -> Result<HttpResponse, Error> {
    let ext = req.extensions();
    let user_with_roles = ext
        .get::<UserRoles>()
        .ok_or(ErrorBadRequest("no user roles"))?;
    info!("userWithRoles: {:?}", user_with_roles);

    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .json(VersionInfo {
            versions: vec!["registry/2.0"],
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
            let repo_name = path.file_name().into_string().map_err(|_| {
                ErrorBadRequest(format!(
                    "invalid file name: {:?}",
                    path.file_name().to_str()
                ))
            })?;
            repositories.push(repo_name);
        }
    }
    Ok(Json(RepositoryInfo { repositories }))
}

#[post("/v2/{repo_name:.*}/blobs/uploads/")]
async fn handle_post(
    info: Path<ImageName>,
    req: HttpRequest,
) -> Result<HttpResponse, RegistryError> {
    ensure_write_access(&req, &info.repo_name)?;

    let uuid = Uuid::new_v4();

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((
            header::LOCATION,
            format!("/v2/{}/blobs/uploads/{}", &info.repo_name, uuid),
        ))
        .finish())
}

#[patch("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_patch(
    info: Path<ImageNameWithUUID>,
    req: HttpRequest,
    mut payload: Payload,
) -> Result<HttpResponse, RegistryError> {
    ensure_write_access(&req, &info.repo_name)?;

    let upload_path = {
        let repo = get_writable_repo(&req)?;
        repo.get_layer_path(info.repo_name.as_str(), format!("blobs/uploads/{}", info.uuid).as_str())?
    };

    let uploaded_file = write_payload_to_file(&mut payload, &upload_path).await?;

    Ok(HttpResponseBuilder::new(StatusCode::ACCEPTED)
        .insert_header((header::RANGE, format!("0-{}", uploaded_file.size)))
        .insert_header(("Docker-Upload-UUID", info.uuid.as_str()))
        .insert_header((
            "Docker-Content-Digest",
            format!("sha256:{}", uploaded_file.sha256),
        ))
        .finish())
}

#[get("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_get_manifest_by_tag(
    req: HttpRequest,
    info: Path<ImageNameWithTag>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req, &info.repo_name)?;

    let mut file = resolve_manifest_file(req, &info)?;

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
    info: Path<ImageNameWithTag>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req, &info.repo_name)?;

    let file = resolve_manifest_file(req, &info)?;
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

#[get("/v2/{repo_name:.*}/blobs/{digest}")]
async fn handle_get_layer_by_hash(
    req: HttpRequest,
    info: Path<ImageNameWithDigest>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req, &info.repo_name)?;

    let layer_path = resolve_layer_path(&req, &info)?;

    let file = actix_files::NamedFile::open_async(&layer_path)
        .await
        .map_err(map_to_not_found)?;

    if file.metadata().is_dir() {
        return Err(RegistryError::new(
            StatusCode::NOT_FOUND,
            "LAYER_UNKNOWN",
            &format!(
                "file {} for {} not found: is a directory",
                info.digest, info.repo_name
            ),
        ));
    }
    debug!("streaming layer_path: {}", layer_path.display());
    Ok(file.into_response(&req))
}

#[head("/v2/{repo_name:.*}/blobs/{digest}")]
async fn handle_head_layer_by_hash(
    req: HttpRequest,
    info: Path<ImageNameWithDigest>,
) -> Result<HttpResponse, RegistryError> {
    ensure_read_access(&req, &info.repo_name)?;

    let layer_path = resolve_layer_path(&req, &info)?;

    trace!("head: layer_path: {}", layer_path.display());

    if !layer_path.is_file() {
        return Err(RegistryError::new(
            StatusCode::NOT_FOUND,
            "LAYER_UNKNOWN",
            &format!(
                "file {} for {} not found: is a directory",
                info.digest, info.repo_name
            ),
        ));
    }

    let file = actix_files::NamedFile::open_async(&layer_path)
        .await
        .map_err(map_to_not_found)?;

    debug!("return layer_path: {}", layer_path.display());
    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header((CONTENT_LENGTH, file.metadata().len()))
        .insert_header(("Docker-Content-Digest", info.digest.to_string()))
        .finish())
}

#[put("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_put_with_digest(
    digest_param: web::Query<DigestParam>,
    info: Path<ImageNameWithUUID>,
    req: HttpRequest,
) -> Result<HttpResponse, RegistryError> {
    ensure_write_access(&req, &info.repo_name)?;
    let writable_repo = get_writable_repo(&req)?;

    let upload_path =
        writable_repo.get_layer_path(info.repo_name.as_str(), &format!("blobs/uploads/{}", info.uuid))?;
    let path_to_file = writable_repo.get_layer_path("_blobs", digest_param.digest.as_str())?;

    // mutex to prevent concurrent writes to the same file
    trace!(
        "Moving upload_path: {} to path_to_file: {}",
        upload_path.display(),
        path_to_file.display()
    );
    fs::rename(upload_path, path_to_file).map_err(map_to_not_found)?;

    let layer_path = format!("{}/blobs/{}", info.repo_name, digest_param.digest);
    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header((header::LOCATION, format!("/v2/{}", &layer_path)))
        .finish())
}

#[put("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_put_manifest_by_tag(
    req: HttpRequest,
    info: Path<ImageNameWithTag>,
    mut payload: Payload,
) -> Result<HttpResponse, RegistryError> {
    ensure_write_access(&req, &info.repo_name)?;

    lazy_static! {
        static ref LOCK_MUTEX: Mutex<u16> = Mutex::new(0);
    }
    let manifest_path = get_writable_repo(&req)?
        .lookup_manifest_file(&info)?;

    debug!("manifest_path: {}", manifest_path.display());

    let uploaded_path = write_payload_to_file(&mut payload, &manifest_path).await?;

    // manifest is stored as tag and sha256:digest
    let manifest_digest_path = get_writable_repo(&req)?
        .get_layer_path(
            info.repo_name.as_str(),
            &format!("/manifests/sha256:{}.json", uploaded_path.sha256))?;
    trace!(
        "manifest_path: {} linked as {}",
        &manifest_path.display(),
        manifest_digest_path.display()
    );

    // lock to prevent concurrent writes to the same file
    let lock = LOCK_MUTEX.lock().await;
    if manifest_digest_path.exists() {
        fs::remove_file(&manifest_digest_path)?;
    }
    fs::hard_link(&manifest_path, &manifest_digest_path)?;
    drop(lock);

    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header((
            "Docker-Content-Digest",
            format!("sha256:{}", uploaded_path.sha256),
        ))
        .insert_header((
            header::LOCATION,
            format!("/v2/{}/manifests/{}", info.repo_name, info.tag),
        ))
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info,rust_registry=debug"));

    let registry_config: Registry =
        serde_json::from_reader(File::open("config.json").unwrap()).unwrap();

    #[cfg(feature = "ldap")]
        let permission_definitions = if let Some(ldap) = registry_config.clone().ldap_config {
        ldap.roles
    } else {
        HashMap::new()
    };

    #[cfg(not(feature = "ldap"))]
        let permission_definitions = HashMap::new();

    let group_permissions = parse_permissions(&permission_definitions);

    let app_data = Data::new(AppState {
        registry: Arc::new(registry_config.clone()),
        permissions: Arc::new(group_permissions),
    });

    let server = HttpServer::new(move || {
        App::new()
            .wrap(HttpAuthentication::with_fn(user_authorization_check))
            .app_data(Data::clone(&app_data))
            .wrap(
                actix_cors::Cors::permissive()
                    .allow_any_origin()
                    .allow_any_method(),
            )
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

    let mut endpoints: Vec<&dyn SocketSpecification> = vec![];

    registry_config.repositories.iter().for_each(|x| {
        endpoints.push(x.1);
    });
    registry_config.proxies.iter().for_each(|x| {
        endpoints.push(x.1);
    });

    let server = endpoints.iter().fold(server, |s, &x| {
        let f = if let Some(http_bind_address) = &x.get_bind_address() {
            trace!("binding http: {}", &http_bind_address);
            s.bind(&http_bind_address).unwrap()
        } else {
            s
        };
        if let Some(cfg) = &x.get_tls_config() {
            let bind_address = cfg.get_bind_address().unwrap();
            let tls_config = cfg.load_rustls_config();
            trace!("binding https: {}", &bind_address);
            f.bind_rustls(&bind_address, tls_config).unwrap()
        } else {
            f
        }
    });

    server.run().await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use actix_web::{http::header::ContentType, test};

    use crate::configuration::TargetRegistry::WriteableRepository;

    use super::*;

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        env_logger::init_from_env(
            env_logger::Env::new().default_filter_or("info,rust_registry=debug"),
        );
    }

    #[actix_web::test]
    async fn test_get_upload_path() {
        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .app_data(build_app_data())
            .to_http_request();

        let repo = Repository {
            storage_path: "target/tests/rust-registry".to_string(),
            bind_address: Some("[::]:8080".to_string()),
            tls_config: None,
        };
        let path = "foo/bar".to_string();
        let layer_path = &repo.get_layer_path(&path, "baz").unwrap();

        req.extensions_mut().insert(NamedRepository {
            name: "repo1".to_string(),
            repository: WriteableRepository(repo),
        });

        assert_eq!(layer_path, &PathBuf::from("target/tests/rust-registry/foo/bar/baz"));
    }

    fn build_app_data() -> Data<AppState> {
        Data::new(AppState {
            registry: Arc::new(Registry {
                repositories: HashMap::from([(
                    "repo1".to_string(),
                    Repository {
                        storage_path: "/tmp".to_string(),
                        bind_address: Some("[::]:8080".to_string()),
                        tls_config: None,
                    },
                )]),
                proxies: HashMap::new(),
                #[cfg(feature = "ldap")]
                ldap_config: None,
            }),
            permissions: Arc::new(GroupPermissions::new(HashMap::new())),
        })
    }

    #[actix_web::test]
    async fn test_create_or_replace_file() {
        let uuid = Uuid::new_v4();
        let path_to_file = PathBuf::from(format!("target/tests/rust-registry/foo/bar/{}/sample", uuid));
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

        let path_to_file = PathBuf::from(format!("target/tests/rust-registry/foo/bar/blobs/uploads/{}", uuid));
        create_or_replace_file(&path_to_file).unwrap();

        let path_to_target_file = PathBuf::from("target/tests/rust-registry/_blobs/12/34/sha256:1234567");
        fs::remove_file(&path_to_target_file).unwrap_or(());
        assert!(!path_to_target_file.exists());

        let app = test::init_service(
            App::new()
                .app_data(build_app_data())
                .service(handle_put_with_digest),
        )
            .await;

        let req = test::TestRequest::put()
            .uri(format!("/v2/foo/bar/blobs/uploads/{}?digest=sha256:1234567", uuid).as_str())
            .to_request();

        req.extensions_mut().insert(NamedRepository {
            name: "repo1".to_string(),
            repository: WriteableRepository(Repository {
                storage_path: "target/tests/rust-registry".to_string(),
                bind_address: Some("[::]:8080".to_string()),
                tls_config: None,
            }),
        });

        req.extensions_mut().insert(UserRoles {
            username: "anonymous".to_string(),
            roles: vec!["anonymous".to_string()],
        });

        let resp = test::call_service(&app, req).await;

        assert!(path_to_target_file.exists());
        assert!(!path_to_file.exists());
        assert_eq!(resp.status(), StatusCode::CREATED);
        fs::remove_file(&path_to_target_file).unwrap_or(());
    }
}
