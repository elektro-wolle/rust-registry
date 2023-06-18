use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::{
    App, Error, get, head, http::header, HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, middleware,
    patch, post, put, Result, web,
};
use actix_web::body::SizedStream;
use actix_web::error::ErrorBadRequest;
use actix_web::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Path, Payload};
use actix_web_httpauth::middleware::HttpAuthentication;
use diesel::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use dotenvy::dotenv;
use futures_util::StreamExt;
use lazy_static::lazy_static;
use log::{debug, info, trace};
use ring::digest::{Context, SHA256};
use tokio::sync::Mutex;
use uuid::*;
use walkdir::{DirEntry, WalkDir};

use crate::api_objects::*;
use crate::authentication::*;
use crate::configuration::*;
use crate::db::update_access_time_to_manifest_and_tag;
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
mod db;
mod schema;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConn = PooledConnection<ConnectionManager<PgConnection>>;

pub struct AppState {
    pub registry: Arc<RegistryRunConfiguration>,
    pub permissions: Arc<GroupPermissions>,
    pub connection_pool: Arc<DbPool>,
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
async fn handle_v2_catalog(req: HttpRequest) -> Result<Json<RepositoryInfo>, RegistryError> {
    let ext = req.extensions();
    let repo = ext.get::<NamedRepository>().unwrap();

    let storage_path = repo.repository.get_storage_path()?;
    let storage_path = if storage_path.ends_with('/') {
        storage_path.to_string()
    } else {
        format!("{}/", storage_path)
    };

    let mut repositories = HashSet::new();
    WalkDir::new(&storage_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !e.path().file_name().unwrap().to_str().unwrap().starts_with("sha256:"))
        .filter(|e| e.path().parent().unwrap().file_name().unwrap().to_str().unwrap() == "manifests")
        .map(|e: DirEntry| {
            let p = e.path().parent().unwrap().parent().unwrap();
            p.to_path_buf().to_str().unwrap().to_string()
        })
        .for_each(|e| {
            repositories.insert(e.replace(&storage_path, ""));
        });

    Ok(Json(RepositoryInfo {
        repositories: repositories.iter()
            .filter(|&image_name| ensure_read_access(&req, image_name).is_ok())
            .map(|e| e.to_string()).collect()
    }))
}

#[post("/v2/{repo_name:.*}/blobs/uploads/")]
async fn handle_post(
    info: Path<ImageName>,
    req: HttpRequest,
) -> Result<HttpResponse, RegistryError> {
    let _repository = get_writable_repo(&req, &info.repo_name)?;

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
    let (repository, _) = get_writable_repo(&req, &info.repo_name)?;

    let upload_path = repository.get_layer_path(
        info.repo_name.as_str(),
        format!("blobs/uploads/{}", info.uuid).as_str())?;

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
    debug!("handle_get_manifest_by_tag: {:?}", info.repo_name);
    let user_roles = ensure_read_access(&req, &info.repo_name)?;

    let app_data = req.app_data::<Data<AppState>>().expect("no app data").as_ref();
    let conn = app_data.connection_pool.get().unwrap();

    let (mut file, path_buf) = resolve_manifest_file(req, &info)?;
    debug!("try to read manifest {}", path_buf  .to_str().unwrap());

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut context = Context::new(&SHA256);
    context.update(&buffer);
    let digest = hex::encode(context.finish());
    let digest_to_update = digest.clone();

    debug!("manifest file {} with {} bytes and digest {}", path_buf  .to_str().unwrap(), buffer.len(), digest);

    update_access_time_to_manifest_and_tag(conn, &digest_to_update, &path_buf, &user_roles, &info.tag, &info.repo_name, true)?;

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

    let (file, _) = resolve_manifest_file(req, &info)?;
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
    let size = file.metadata().len();
    debug!("return layer_path: {} with size {}", layer_path.display(), size);

    let empty_stream: futures_util::stream::Empty<Result<_>> = futures_util::stream::empty();
    let empty = SizedStream::new(size, empty_stream);
    let response = HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Docker-Content-Digest", info.digest.to_string()))
        .body(empty);
    Ok(response)
}

#[put("/v2/{repo_name:.*}/blobs/uploads/{uuid}")]
async fn handle_put_with_digest(
    digest_param: web::Query<DigestParam>,
    info: Path<ImageNameWithUUID>,
    req: HttpRequest,
) -> Result<HttpResponse, RegistryError> {
    let (writable_repo, _) = get_writable_repo(&req, &info.repo_name)?;

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

#[get("/v2/{repo_name:.*}/tags/list")]
async fn handle_get_tags_for_repo_name(
    req: HttpRequest,
    info: Path<ImageName>,
) -> Result<HttpResponse, RegistryError> {
    let repository = get_readable_repo(&req, &info.repo_name)?;
    let manifest_path = repository
        .get_layer_path(info.repo_name.as_str(), "manifests")?;

    let tags = manifest_path.read_dir().map_err(map_to_not_found)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_str().unwrap().to_string())
        .filter(|entry| !entry.starts_with("sha256:"))
        .map(|entry| entry.replace(".json", "")).collect();

    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header((CONTENT_TYPE, "application/json"))
        .json(TagList { name: info.repo_name.clone(), tags }))
}

#[put("/v2/{repo_name:.*}/manifests/{tag}")]
async fn handle_put_manifest_by_tag(
    req: HttpRequest,
    info: Path<ImageNameWithTag>,
    mut payload: Payload,
) -> Result<HttpResponse, RegistryError> {
    let (repository, user_roles) = get_writable_repo(&req, &info.repo_name)?;

    let manifest_path = repository.lookup_manifest_file(&info)?;
    debug!("manifest_path: {}", manifest_path.display());

    let uploaded_path = write_payload_to_file(&mut payload, &manifest_path).await?;

    // manifest is stored as tag and sha256:digest
    let digest_to_update = uploaded_path.sha256;
    let manifest_digest_path = repository.get_layer_path(
        info.repo_name.as_str(),
        &format!("/manifests/sha256:{}.json", digest_to_update))?;
    trace!(
        "manifest_path: {} linked as {}",
        &manifest_path.display(),
        manifest_digest_path.display()
    );

    link_files_atomically(&manifest_path, &manifest_digest_path).await?;

    let app_data = req.app_data::<Data<AppState>>().expect("no app data").as_ref();
    let conn = app_data.connection_pool.get().unwrap();
    update_access_time_to_manifest_and_tag(conn, &digest_to_update, &manifest_path, &user_roles, &info.tag, &info.repo_name, false)?;

    Ok(HttpResponseBuilder::new(StatusCode::CREATED)
        .insert_header((
            "Docker-Content-Digest",
            format!("sha256:{}", digest_to_update),
        ))
        .insert_header((
            header::LOCATION,
            format!("/v2/{}/manifests/{}", info.repo_name, info.tag),
        ))
        .finish())
}

async fn link_files_atomically(manifest_path: &PathBuf, manifest_digest_path: &PathBuf) -> Result<(), RegistryError> {
    // lock to prevent concurrent writes to the same file
    lazy_static! {
        static ref LOCK_MUTEX: Mutex<u16> = Mutex::new(0);
    }
    let lock = LOCK_MUTEX.lock().await;
    if manifest_digest_path.exists() {
        fs::remove_file(manifest_digest_path)?;
    }
    fs::hard_link(manifest_path, manifest_digest_path)?;
    drop(lock);
    Ok(())
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
    dotenv().ok();

    let registry_config: RegistryRunConfiguration =
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

    let database_url = env::var("DATABASE_URL")
        .ok()
        .or(registry_config.clone().database_url)
        .expect("DATABASE_URL must be set or defined in config.json");
    let connection_pool = build_connection_pool_for_url(database_url.as_str());

    let app_data = Data::new(AppState {
        registry: Arc::new(registry_config.clone()),
        permissions: Arc::new(group_permissions),
        connection_pool: Arc::new(connection_pool),
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
            .service(handle_get_tags_for_repo_name)
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

fn build_connection_pool_for_url(database_url: &str) -> Pool<ConnectionManager<PgConnection>> {
    Pool::builder()
        .max_size(15)
        .build(ConnectionManager::<PgConnection>::new(database_url)).unwrap()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use actix_web::{http::header::ContentType, test};
    use diesel::connection::SimpleConnection;
    use testcontainers::clients::Cli;
    use testcontainers::Container;
    use testcontainers::images::generic::GenericImage;

    use crate::configuration::TargetRepository::WriteableRepository;

    use super::*;

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        env_logger::init_from_env(
            env_logger::Env::new().default_filter_or("info,rust_registry=debug"),
        );
    }

    lazy_static! {
        static ref DOCKER: Cli = Cli::default();
        }

    fn start_db_container() -> Container<'static, GenericImage> {
        DOCKER.run(GenericImage::new("postgres", "13")
            .with_env_var("POSTGRES_USER", "registry")
            .with_env_var("POSTGRES_PASSWORD", "registry")
            .with_env_var("POSTGRES_DB", "registry")
            .with_wait_for(testcontainers::core::WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            )))
    }


    #[actix_web::test]
    async fn test_get_upload_path() {
        let c = start_db_container();
        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .app_data(build_app_data(c.get_host_port_ipv4(5432)))
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

    fn build_app_data(db_port: u16) -> Data<AppState> {
        let db_url = format!("postgres://registry:registry@localhost:{}/registry", db_port);
        Data::new(AppState {
            registry: Arc::new(RegistryRunConfiguration {
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
                database_url: Some(db_url.clone()),
            }),
            permissions: Arc::new(GroupPermissions::new(HashMap::new())),
            connection_pool: Arc::new(build_connection_pool_for_url(db_url.as_str())),
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
        use diesel_migrations::MigrationHarness;
        let uuid = Uuid::new_v4();

        let path_to_file = PathBuf::from(format!("target/tests/rust-registry/foo/bar/blobs/uploads/{}", uuid));
        create_or_replace_file(&path_to_file).unwrap();

        let path_to_target_file = PathBuf::from("target/tests/rust-registry/_blobs/12/34/sha256:1234567");
        fs::remove_file(&path_to_target_file).unwrap_or(());
        assert!(!path_to_target_file.exists());

        let c = start_db_container();

        let app_data = build_app_data(c.get_host_port_ipv4(5432));
        let mut co = app_data.connection_pool.get().unwrap();
        co.build_transaction().run(|pg_conn| {
            // run pending migrations
            pg_conn.run_pending_migrations(MIGRATIONS).unwrap();

            Ok(1) as Result<i32, diesel::result::Error>
        }).unwrap();
        co.build_transaction().run(|pg_conn| {
            // insert sample data
            pg_conn.batch_execute("INSERT INTO manifests (id, path, file_path) VALUES ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'foo/bar', 'manifests/foo/bar/manifests/1.0.0.json')")?;
            pg_conn.batch_execute("INSERT INTO tags (manifest, tag) VALUES ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '1.0.0')")?;
            Ok(1) as Result<i32, diesel::result::Error>
        }).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(app_data)
                .service(handle_put_with_digest)
                .service(handle_get_manifest_by_tag)
            ,
        ).await;

        let req = test::TestRequest::put()
            .uri(format!("/v2/foo/bar/blobs/uploads/{}?digest=sha256:1234567", uuid).as_str())
            .to_request();

        let named_repository = NamedRepository {
            name: "repo1".to_string(),
            repository: WriteableRepository(Repository {
                storage_path: "target/tests/rust-registry".to_string(),
                bind_address: Some("[::]:8080".to_string()),
                tls_config: None,
            }),
        };

        let user_roles = UserRoles {
            username: "anonymous".to_string(),
            roles: vec!["anonymous".to_string()],
        };
        req.extensions_mut().insert(named_repository.clone());
        req.extensions_mut().insert(user_roles.clone());

        let resp = test::call_service(&app, req).await;

        assert!(path_to_target_file.exists());
        assert!(!path_to_file.exists());
        assert_eq!(resp.status(), StatusCode::CREATED);
        fs::remove_file(&path_to_target_file).unwrap_or(());


        let path_to_file = PathBuf::from("target/tests/rust-registry/foo/bar/manifests/1.0.0.json");
        create_or_replace_file(&path_to_file).unwrap();

        let req = test::TestRequest::get()
            // #[get("/v2/{repo_name:.*}/manifests/{tag}")]
            .uri("/v2/foo/bar/manifests/1.0.0")
            .to_request();
        req.extensions_mut().insert(named_repository.clone());
        req.extensions_mut().insert(user_roles.clone());
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = test::TestRequest::get()
            // #[get("/v2/{repo_name:.*}/manifests/{tag}")]
            .uri("/v2/foo/bar/manifests/1.0.0")
            .to_request();
        req.extensions_mut().insert(named_repository.clone());
        req.extensions_mut().insert(user_roles.clone());
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
