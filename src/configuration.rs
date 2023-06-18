use std::collections::HashMap;
use std::fs::{DirBuilder, File};
use std::io::BufReader;
use std::path::PathBuf;

use lazy_static::lazy_static;
use log::{debug, trace};
use path_clean::PathClean;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use serde::Deserialize;

use crate::api_objects::{ImageNameWithDigest, ImageNameWithTag};
use crate::configuration::TargetRepository::{ReadOnlyProxy, WriteableRepository};
use crate::error::RegistryError;
#[cfg(feature = "ldap")]
use crate::ldap::LdapConfig;

pub trait SocketSpecification {
    fn get_bind_address(&self) -> Option<String>;
    fn get_tls_config(&self) -> Option<TlsConfig>;
    fn to_target_repository(&self) -> TargetRepository;
}

pub trait ReadableRepository {
    fn get_layer_path(&self, repo: &str, uuid: &str) -> Result<PathBuf, RegistryError>;
    fn lookup_manifest_file(&self, info: &ImageNameWithTag) -> Result<PathBuf, RegistryError>;
    fn lookup_blob_file(&self, info: &ImageNameWithDigest) -> Result<PathBuf, RegistryError>;
}

pub trait TlsServerConfiguration: SocketSpecification {
    fn load_rustls_config(&self) -> ServerConfig;
}

#[derive(Debug, Clone, Deserialize)]
pub struct Repository {
    pub storage_path: String,
    #[serde(default = "default_http_port")]
    pub bind_address: Option<String>,
    pub tls_config: Option<TlsConfig>,
}

impl SocketSpecification for Repository {
    fn get_bind_address(&self) -> Option<String> {
        self.bind_address.clone()
    }
    fn get_tls_config(&self) -> Option<TlsConfig> {
        self.tls_config.clone()
    }
    fn to_target_repository(&self) -> TargetRepository {
        WriteableRepository(self.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Proxy {
    pub storage_path: String,
    #[serde(default = "default_http_port")]
    pub bind_address: Option<String>,
    pub tls_config: Option<TlsConfig>,
    pub remote_url: String,
}

impl SocketSpecification for Proxy {
    fn get_bind_address(&self) -> Option<String> {
        self.bind_address.clone()
    }
    fn get_tls_config(&self) -> Option<TlsConfig> {
        self.tls_config.clone()
    }
    fn to_target_repository(&self) -> TargetRepository {
        ReadOnlyProxy(self.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum TargetRepository {
    WriteableRepository(Repository),
    ReadOnlyProxy(Proxy),
}

impl TargetRepository {
    pub(crate) fn get_storage_path(&self) -> Result<&str, RegistryError> {
        match self {
            WriteableRepository(w) => Ok(&w.storage_path),
            ReadOnlyProxy(r) => Ok(&r.storage_path),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryRunConfiguration {
    pub repositories: HashMap<String, Repository>,
    pub proxies: HashMap<String, Proxy>,
    #[cfg(feature = "ldap")]
    pub ldap_config: Option<LdapConfig>,
    pub database_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NamedRepository {
    pub name: String,
    pub repository: TargetRepository,
}

impl ReadableRepository for TargetRepository {
    fn get_layer_path(&self, repo: &str, uuid: &str) -> Result<PathBuf, RegistryError> {
        match self {
            WriteableRepository(w) => w.get_layer_path(repo, uuid),
            ReadOnlyProxy(r) => r.get_layer_path(repo, uuid),
        }
    }

    fn lookup_manifest_file(&self, info: &ImageNameWithTag) -> Result<PathBuf, RegistryError> {
        match self {
            WriteableRepository(w) => w.lookup_manifest_file(info),
            ReadOnlyProxy(r) => r.lookup_manifest_file(info),
        }
    }

    fn lookup_blob_file(&self, info: &ImageNameWithDigest) -> Result<PathBuf, RegistryError> {
        match self {
            WriteableRepository(w) => w.lookup_blob_file(info),
            ReadOnlyProxy(r) => r.lookup_blob_file(info),
        }
    }
}

impl ReadableRepository for Repository {
    fn get_layer_path(&self, repo: &str, uuid: &str) -> Result<PathBuf, RegistryError> {
        lazy_static! { static ref REPO_REGEX: regex::Regex = regex::Regex::new(r"^sha256:(..)(..).*$").unwrap(); }

        let new_path = REPO_REGEX.replace(uuid, "$1/$2/$0");
        trace!("convert {} to new_path: {}", uuid, new_path);

        // clean() will remove any "." and ".." from the path
        let sub_path = PathBuf::from(format!("/{}/{}", repo, new_path)).clean();
        let target_path = format!("{}/{}", self.storage_path, sub_path.display());

        // second clean() to ensure that the path is clean
        let path_buf = PathBuf::from(target_path).clean();

        // ensure, that the parent directory exists
        DirBuilder::new().recursive(true).create(path_buf.parent().unwrap())?;
        Ok(path_buf)
    }

    fn lookup_manifest_file(&self, info: &ImageNameWithTag) -> Result<PathBuf, RegistryError> {
        let manifest_path = Self::get_layer_path(
            self,
            info.repo_name.as_str(),
            &format!("manifests/{}.json", info.tag),
        )?;
        debug!("manifest_path: {}", manifest_path.display());
        Ok(manifest_path)
    }

    fn lookup_blob_file(&self, info: &ImageNameWithDigest) -> Result<PathBuf, RegistryError> {
        let blob_path =
            Self::get_layer_path(self, "_blobs", info.digest.as_str())?;
        debug!("blob_path: {}", blob_path.display());
        Ok(blob_path)
    }
}

impl ReadableRepository for Proxy {
    fn get_layer_path(&self, _path: &str, _uuid: &str) -> Result<PathBuf, RegistryError> {
        panic!("not implemented")
    }

    fn lookup_manifest_file(&self, _info: &ImageNameWithTag) -> Result<PathBuf, RegistryError> {
        panic!("not implemented")
    }

    fn lookup_blob_file(&self, _info: &ImageNameWithDigest) -> Result<PathBuf, RegistryError> {
        panic!("not implemented")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserRoles {
    pub username: String,
    pub roles: Vec<String>,
}

fn default_http_port() -> Option<String> {
    Some("[::]:8080".to_string())
}

fn default_https_port() -> String {
    "[::]:8443".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
    #[serde(default = "default_https_port")]
    pub bind_address: String,
}

impl SocketSpecification for TlsConfig {
    fn get_bind_address(&self) -> Option<String> {
        Some(self.bind_address.clone())
    }
    fn get_tls_config(&self) -> Option<TlsConfig> {
        Some(self.clone())
    }
    fn to_target_repository(&self) -> TargetRepository {
        panic!("not implemented")
    }
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
