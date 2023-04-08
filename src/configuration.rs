use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use log::debug;
use path_clean::PathClean;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use serde::Deserialize;

use crate::api_objects::{ImageNameWithDigest, ImageNameWithTag};
use crate::configuration::TargetRegistry::{ReadOnlyProxy, WriteableRepository};
use crate::error::RegistryError;
#[cfg(feature = "ldap")]
use crate::ldap::LdapConfig;

pub trait SocketSpecification {
    fn get_bind_address(&self) -> Option<String>;
    fn get_tls_config(&self) -> Option<TlsConfig>;
    fn to_target_repository(&self) -> TargetRegistry;
}

pub trait ReadableRepository {
    fn get_layer_path(&self, path: &str) -> Result<PathBuf, RegistryError>;
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
    fn to_target_repository(&self) -> TargetRegistry {
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
    fn to_target_repository(&self) -> TargetRegistry {
        ReadOnlyProxy(self.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum TargetRegistry {
    WriteableRepository(Repository),
    ReadOnlyProxy(Proxy),
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
    pub repository: TargetRegistry,
}

impl ReadableRepository for TargetRegistry {
    fn get_layer_path(&self, path: &str) -> Result<PathBuf, RegistryError> {
        match self {
            WriteableRepository(w) => w.get_layer_path(path),
            ReadOnlyProxy(r) => r.get_layer_path(path),
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
    fn get_layer_path(&self, path: &str) -> Result<PathBuf, RegistryError> {
        // clean() will remove any "." and ".." from the path
        let sub_path = PathBuf::from(format!("/{}", path)).clean();
        let target_path = format!("{}/{}", self.storage_path, sub_path.display());

        // second clean() to ensure that the path is clean
        Ok(PathBuf::from(target_path).clean())
    }

    fn lookup_manifest_file(&self, info: &ImageNameWithTag) -> Result<PathBuf, RegistryError> {
        let manifest_path = Self::get_layer_path(
            self,
            &format!("{}/manifests/{}.json", info.repo_name, info.tag),
        )?;
        debug!("manifest_path: {}", manifest_path.display());
        Ok(manifest_path)
    }

    fn lookup_blob_file(&self, info: &ImageNameWithDigest) -> Result<PathBuf, RegistryError> {
        let blob_path =
            Self::get_layer_path(self, &format!("{}/blobs/{}", info.repo_name, info.digest))?;
        debug!("blob_path: {}", blob_path.display());
        Ok(blob_path)
    }
}

impl ReadableRepository for Proxy {
    fn get_layer_path(&self, _path: &str) -> Result<PathBuf, RegistryError> {
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
    fn to_target_repository(&self) -> TargetRegistry {
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
