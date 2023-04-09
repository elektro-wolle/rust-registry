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
pub struct ImageName {
    pub repo_name: String,
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
    pub versions: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct TagList {
    pub name: String,
    pub tags: Vec<String>,
}
