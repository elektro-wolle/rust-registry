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
use crate::error::{map_to_not_found, RegistryError};

pub fn resolve_manifest_file(
    req: HttpRequest,
    info: &Path<ImageNameWithTag>,
) -> Result<File, RegistryError> {
    let ext = req.extensions();
    let named_repo = ext.get::<NamedRepository>().unwrap();
    let file_path = &named_repo.repository.lookup_manifest_file(info)?;
    let file = File::open(file_path).map_err(map_to_not_found)?;
    Ok(file)
}

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

fn check_host(request_host: String, repo_spec: &dyn SocketSpecification) -> bool {
    if repo_spec.get_bind_address() == Some(request_host.clone()) {
        return true;
    }
    if let Some(tls_cfg) = repo_spec.get_tls_config() {
        return tls_cfg.bind_address == request_host;
    }
    false
}

fn resolve_repo(request_host: String, app_config: &RegistryRunConfiguration) -> Option<(String, TargetRepository)> {
    let mut named_repo: Option<(String, TargetRepository)> = None;

    if let Some((name, proxy)) = app_config
        .repositories
        .iter()
        .find(|&(_, r)| check_host(request_host.clone(), r))
    {
        named_repo = Some((name.clone(), proxy.to_target_repository()));
    } else if let Some((name, proxy)) = app_config
        .proxies
        .iter()
        .find(|&(_, r)| check_host(request_host.clone(), r))
    {
        named_repo = Some((name.clone(), proxy.to_target_repository()));
    }
    named_repo
}

fn resolve_repo_by_bind_address(
    req: &ServiceRequest,
    request_host: String,
) -> Option<(String, TargetRepository)> {
    let reg = req.app_data::<Data<AppState>>().unwrap().as_ref();
    let app_config = reg.registry.as_ref();
    resolve_repo(request_host, app_config)
}

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
