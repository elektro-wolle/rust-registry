use std::collections::HashMap;

use actix_web::{Error, HttpMessage, HttpRequest};
use actix_web::dev::ServiceRequest;
use actix_web::error::ErrorBadRequest;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web_httpauth::extractors::bearer::BearerAuth;
#[cfg(feature = "ldap")]
use base64::{alphabet, engine, Engine, engine::general_purpose};
use log::info;

use crate::AppState;
use crate::configuration::{NamedRepository, Repository, TargetRepository, UserRoles};
#[cfg(feature = "ldap")]
use crate::configuration::RegistryRunConfiguration;
use crate::configuration::TargetRepository::WriteableRepository;
use crate::error::RegistryError;
#[cfg(feature = "ldap")]
use crate::ldap::{authenticate_and_get_groups, ReadWriteDefinition};
use crate::perm::GroupPermissions;
#[cfg(feature = "ldap")]
use crate::perm::ReadWritePermissions;
use crate::utils::insert_resolved_repo;

struct AccessForbiddenError {
    message: String,
}

impl AccessForbiddenError {
    #[cfg(feature = "ldap")]
    fn new(message: &str) -> Self {
        AccessForbiddenError { message: message.to_string() }
    }
}

impl From<AccessForbiddenError> for RegistryError {
    fn from(e: AccessForbiddenError) -> Self {
        RegistryError::new(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &format!("Unauthorized, error: {}", e.message),
        )
    }
}

#[cfg(feature = "ldap")]
pub async fn get_roles_for_authentication(
    basic_auth: Option<String>,
    reg_arc: &RegistryRunConfiguration,
) -> Result<UserRoles, RegistryError> {
    let auth = basic_auth.ok_or_else(|| {
        RegistryError::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            &"Unauthorized, no basic auth".to_string(),
        )
    })?;

    let engine = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);

    let decoded = engine
        .decode(auth.as_bytes())
        .map_err(|_| AccessForbiddenError::new("Unauthorized, invalid base64"))?;

    let decoded_str = String::from_utf8(decoded)
        .map_err(|_| AccessForbiddenError::new("Unauthorized, invalid utf8"))?;

    let parts: Vec<&str> = decoded_str.split(':').collect();

    if parts.len() != 2 {
        return Err(AccessForbiddenError::new("Unauthorized, wrong format").into());
    }

    let username = parts[0].to_string();
    let password = parts[1].to_string();

    let ldap = reg_arc.ldap_config.as_ref();

    match ldap {
        Some(ldap) => {
            let roles = authenticate_and_get_groups(ldap, &username, &password)
                .await
                .map_err(|e|
                    AccessForbiddenError { message: format!("Unauthorized, ldap error: {}", e) }
                )?;
            if roles.is_empty() {
                Err(AccessForbiddenError::new("Unauthorized, no ldap groups").into())
            } else {
                Ok(UserRoles { username, roles })
            }
        }
        _ => Err(AccessForbiddenError::new("Unauthorized, no ldap config").into()),
    }
}

fn ensure_access(
    req: &HttpRequest,
    path: &String,
    f: fn(&GroupPermissions, Vec<String>, &str) -> bool,
) -> Result<(), RegistryError> {
    let ext = req.extensions();
    let app_config = req.app_data::<Data<AppState>>();
    let perms = app_config.unwrap().permissions.as_ref();
    let user_with_roles = ext
        .get::<UserRoles>()
        .ok_or(ErrorBadRequest("no user roles"))?;

    let roles = user_with_roles.roles.clone();

    let ext = req.extensions();
    let repo = ext.get::<NamedRepository>().unwrap();

    info!(
        "check access to repo: {}:{} for user: {:?}",
        repo.name, path, &roles
    );
    if f(perms, roles, format!("{}:{}", &repo.name, path).as_str()) {
        Ok(())
    } else {
        Err(RegistryError::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            &format!(
                "Unauthorized, no access to repo: {} path: {}",
                repo.name, path
            ),
        ))
    }
}

fn ensure_write_access(req: &HttpRequest, path: &String) -> Result<(), RegistryError> {
    ensure_access(req, path, |perms, roles, path| perms.can_write(roles, path))
}

pub fn ensure_read_access(req: &HttpRequest, path: &String) -> Result<(), RegistryError> {
    ensure_access(req, path, |perms, roles, path| perms.can_read(roles, path))
}

fn retrieve_named_repo(req: &HttpRequest) -> Result<NamedRepository, RegistryError> {
    let ext = req.extensions();
    let repo = ext.get::<NamedRepository>().ok_or(RegistryError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        &"No repository found in request".to_string(),
    ))?;
    Ok(repo.clone())
}

pub fn get_readable_repo(req: &HttpRequest, repo_name: &String) -> Result<TargetRepository, RegistryError> {
    ensure_read_access(req, repo_name)?;
    let repo = retrieve_named_repo(req)?;
    Ok(repo.repository.clone())
}

pub fn get_writable_repo(req: &HttpRequest, repo_name: &String) -> Result<Repository, RegistryError> {
    ensure_write_access(req, repo_name)?;
    let repo = retrieve_named_repo(req)?;
    match &repo.repository {
        WriteableRepository(r) => Ok(r.clone()),
        _ => Err(RegistryError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            &"No repository found in request".to_string(),
        )),
    }
}

pub async fn user_authorization_check(
    req: ServiceRequest,
    _credentials: Option<BearerAuth>,
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

        let app_config = req.app_data::<Data<AppState>>();
        let reg_arc = app_config.unwrap().registry.as_ref();

        match get_roles_for_authentication(basic_auth, reg_arc).await {
            Ok(user) => {
                req.extensions_mut().insert(user);
                Ok(req)
            }
            Err(e) => Err((e.into(), req)),
        }
    }
    #[cfg(not(feature = "ldap"))]
    {
        let anon_user = UserRoles {
            username: "anonymous".to_string(),
            roles: vec!["anonymous".to_string()],
        };
        req.extensions_mut().insert(anon_user);
        Ok(req)
    }
}

#[cfg(not(feature = "ldap"))]
pub struct ReadWriteDefinition {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

pub fn parse_permissions(_permissions: &HashMap<String, ReadWriteDefinition>) -> GroupPermissions {
    #[cfg(not(feature = "ldap"))]
    return GroupPermissions::new(HashMap::new());

    #[cfg(feature = "ldap")]
    {
        let mut mapped_permissions: HashMap<String, ReadWritePermissions> = HashMap::new();
        _permissions
            .iter()
            .map(|(group, p)| (group.clone(), ReadWritePermissions::new(&p.read, &p.write)))
            .for_each(|(group, p)| {
                mapped_permissions.insert(group, p);
            });
        GroupPermissions::new(mapped_permissions)
    }
}
