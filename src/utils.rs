use std::fs::{DirBuilder, File, OpenOptions};
use std::path::PathBuf;

use actix_web::{Error, HttpMessage, HttpRequest};
use actix_web::dev::ServiceRequest;
use actix_web::error::ErrorBadRequest;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Path};
use log::trace;

use crate::api_objects::{ImageNameWithDigest, ImageNameWithTag};
use crate::AppState;
use crate::configuration::{
    NamedRepository, ReadableRepository, RegistryRunConfiguration, SocketSpecification, TargetRepository,
};
use crate::db::DbConnection;
use crate::error::{map_to_not_found, RegistryError};

/** This function is used to resolve the path to a manifest file.
* It will return the path to the manifest file and the path to the directory containing the manifest file.
 */
pub fn resolve_manifest_file(
    req: &HttpRequest,
    info: &Path<ImageNameWithTag>,
) -> Result<(File, PathBuf), RegistryError> {
    let ext = req.extensions();
    let named_repo = ext.get::<NamedRepository>().unwrap();
    let file_path = &named_repo.repository.lookup_manifest_file(info)?;
    let file = File::open(file_path).map_err(map_to_not_found)?;
    Ok((file, file_path.clone()))
}

/**
 * This function is used to resolve the path to a layer file.
 * It will return the path to the layer file and the path to the directory containing the layer file.
 */
pub fn resolve_layer_path(
    req: &HttpRequest,
    info: &Path<ImageNameWithDigest>,
) -> Result<PathBuf, RegistryError> {
    let layer_path = {
        let ext = req.extensions();
        let named_repo = ext.get::<NamedRepository>().unwrap();
        named_repo.repository.lookup_blob_file(info)?
    };
    Ok(layer_path)
}

/**
 * This function is used to create a file if it does not exist or replace it if it does.
 * It will create the directory structure if it does not exist.
 */
pub fn create_or_replace_file(path_to_file: &PathBuf) -> Result<File, RegistryError> {
    let mut dir_builder = DirBuilder::new();
    trace!(
        "creating dir: {:?}, saving file {:?}",
        path_to_file.parent(),
        path_to_file
    );

    dir_builder
        .recursive(true)
        .create(
            path_to_file
                .parent()
                .ok_or(ErrorBadRequest("invalid path"))?,
        )
        .map_err(ErrorBadRequest)?;

    let manifest_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path_to_file)?;
    Ok(manifest_file)
}

/**
 * check if the request is a valid request for this registry.
 */
fn check_host(request_host: String, repo_spec: &dyn SocketSpecification) -> bool {
    if repo_spec.get_bind_address() == Some(request_host.clone()) {
        true
    } else if let Some(tls_cfg) = repo_spec.get_tls_config() {
        tls_cfg.bind_address == request_host
    } else {
        false
    }
}

/** find the repository that matches the request host.
* If no repository matches, return None.
 */
fn resolve_repo(request_host: String, app_config: &RegistryRunConfiguration) -> Option<(String, TargetRepository)> {
    if let Some((name, proxy)) = app_config
        .repositories
        .iter()
        .find(|&(_, r)| check_host(request_host.clone(), r))
    {
        return Some((name.clone(), proxy.to_target_repository()));
    } else if let Some((name, proxy)) = app_config
        .proxies
        .iter()
        .find(|&(_, r)| check_host(request_host.clone(), r))
    {
        return Some((name.clone(), proxy.to_target_repository()));
    }
    None
}

/**
 * This function is used to resolve the repository that matches the request host.
 * It will return the name of the repository and the repository configuration.
 */
fn resolve_repo_by_bind_address(
    req: &ServiceRequest,
    request_host: String,
) -> Option<(String, TargetRepository)> {
    let reg = req.app_data::<Data<AppState>>().unwrap().as_ref();
    let app_config = reg.registry.as_ref();
    resolve_repo(request_host, app_config)
}

/**
 * Inserts the resolved repository into the request extensions.
 */
pub fn insert_resolved_repo(
    req: ServiceRequest,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let request_host = req.app_config().host().to_string();

    let named_repo = resolve_repo_by_bind_address(&req, request_host.clone());
    if let Some((name, repository)) = named_repo {
        let repo = NamedRepository { name, repository };
        trace!(
            "insert_resolved_repo: request_host: {}, repo: {:?}",
            request_host,
            repo.name
        );

        req.extensions_mut().insert(repo);
        Ok(req)
    } else {
        Err((
            RegistryError::new(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("Not found, no repo config for host {}", &request_host),
            )
                .into(),
            req,
        ))
    }
}


pub fn run_in_tx<T, F>(req: &HttpRequest, f: F) -> Result<T, RegistryError>
    where
        F: FnOnce(&mut DbConnection) -> Result<T, RegistryError>,
{
    let app_data = &req.app_data::<Data<AppState>>().expect("no app data").as_ref();
    let mut pool = app_data.connection_pool.get()?;
    pool.build_transaction().read_write().run(|c| {
        f(c)
    })
}
