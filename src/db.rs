use std::fs::File;
use std::path::Path;

use actix_web::http::StatusCode;
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use log::{debug, trace};
use uuid::Uuid;

use crate::configuration::UserRoles;
use crate::error::RegistryError;

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::manifests)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Manifests {
    pub id: Uuid,
    pub repo: String,
    pub digest: String,
    pub path: String,
    pub file_path: String,
    pub configuration: String,
    pub access_count: i64,
    pub uploaded_by: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_accessed_at: NaiveDateTime, //  timestamp    not null default current_timestamp
}

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::tags)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Tags {
    pub id: i64,
    pub repo: String,
    pub manifest: Uuid,
    pub tag: String,
    pub access_count: i64,
    pub uploaded_by: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_accessed_at: NaiveDateTime, //  timestamp    not null default current_timestamp
}

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::tags)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct TagsWithoutId {
    pub manifest: Uuid,
    pub repo: String,
    pub tag: String,
    pub access_count: i64,
    pub uploaded_by: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_accessed_at: NaiveDateTime, //  timestamp    not null default current_timestamp
}

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::layers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Layers {
    pub id: Uuid,
    pub digest: String,
    pub repo: String,
    pub file_path: String,
    pub size: i64,
    pub access_count: i64,
    pub uploaded_by: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_accessed_at: NaiveDateTime, //  timestamp    not null default current_timestamp
}

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::manifests2layers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Manifests2Layers {
    pub manifest: Uuid,
    //  varchar(255) not null,
    pub layer: Uuid, //  varchar(255) not null,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
pub struct DockerManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i64,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub config: DockerManifestConfig,
    pub layers: Vec<ManifestLayer>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
pub struct DockerManifestConfig {
    // use mediaType in json
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: i64,
    pub digest: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
pub struct ManifestLayer {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: i64,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub struct UpdateOrCreateManifestTagAndLayers<'a> {
    pub repo_name: &'a str,
    pub sha256_digest: &'a str,
    pub path_buf: &'a Path,
    pub user_roles: &'a UserRoles,
    pub image_tag: &'a str,
    pub image_name: &'a str,
    pub fail_if_not_found: bool,
}

pub type DbConnection = PgConnection;

pub trait UpdateOrInsert<T> {
    fn update_or_insert(&self, conn: &mut DbConnection) -> Result<usize, RegistryError>;
    fn insert_new_tag(&self, c: &mut DbConnection, manifest_id: Uuid) -> Result<i64, RegistryError>;
    fn insert_new_manifest(&self, c: &mut DbConnection, json_manifest: &DockerManifest) -> Result<Uuid, RegistryError>;
}

impl<'a> UpdateOrInsert<UpdateOrCreateManifestTagAndLayers<'a>> for UpdateOrCreateManifestTagAndLayers<'a> {
    /**
     * Update the last_accessed_at field of the manifest and tag.
     * @param fail_if_not_found, if true, will return error if manifest not found. Otherwise, will create a new manifest and tag.
     */
    fn update_or_insert(
        &self,
        c: &mut DbConnection,
    ) -> Result<usize, RegistryError> {
        let manifest_file = File::open(self.path_buf)?;
        let json_manifest: DockerManifest = serde_json::from_reader(manifest_file)?;

        let manifest_id = {
            // add manifest if not exists (and is allowed to be created)
            use crate::schema::manifests::dsl::*;
            let manifest = manifests
                .filter(
                    digest.eq(self.sha256_digest).and(
                        repo.eq(self.repo_name))
                )
                .select(Manifests::as_select())
                .load(c)?;

            trace!("loaded manifest from db: {:?}", manifest);

            if manifest.is_empty() {
                if self.fail_if_not_found {
                    return Err(RegistryError::new(
                        StatusCode::NOT_FOUND,
                        "manifest not found",
                        &format!("manifest not found: {}", self.sha256_digest),
                    ));
                }

                // parse json from path_buf to docker manifest struct

                self.insert_new_manifest(c, &json_manifest)?
            } else {
                let now = Utc::now().naive_utc();
                trace!("update manifest {}:{} last_accessed : {:?}", self.image_name, self.image_tag, now);
                diesel::update(manifests.find(manifest[0].id))
                    .set((
                        last_accessed_at.eq(now),
                        access_count.eq(access_count + 1)
                    ))
                    .execute(c)?;
                manifest[0].id
            }
        };
        {
            // add tag to the manifest if not exists (and is allowed to be created)
            use crate::schema::tags::dsl::*;
            let found_tag = tags
                .filter(tag.eq(self.image_tag).and(manifest.eq(manifest_id)))
                .select(Tags::as_select())
                .load::<Tags>(c)?;
            if found_tag.is_empty() {
                if self.fail_if_not_found {
                    return Err(RegistryError::new(
                        StatusCode::NOT_FOUND,
                        "tag not found",
                        &format!("tag not found: {}", self.sha256_digest),
                    ));
                }
                let created_id = self.insert_new_tag(c, manifest_id)?;
                trace!("created id: {:?}", created_id);
            } else {
                let id_to_update = found_tag[0].id;
                let now = Utc::now().naive_utc();
                trace!("update tag {}:{} with id {} last_accessed : {:?}", self.image_name,  self.image_tag, id_to_update, now);
                diesel::update(tags.find(id))
                    .set((
                        last_accessed_at.eq(now),
                        access_count.eq(access_count + 1)
                    ))
                    .execute(c)?;
            };

            // insert layers and manifest2layers
            let layers = json_manifest.layers;
            for l in layers {
                let layer_id = {
                    use crate::schema::layers::dsl::*;

                    let found_layer = layers
                        .filter(repo.eq(self.repo_name).and(digest.eq(&l.digest)))
                        .select(Layers::as_select())
                        .load(c)?;
                    let layer_digest = &l.digest;
                    if found_layer.is_empty() {
                        trace!("insert layer: {:?}", &l);
                        let layer_id = Uuid::new_v4();
                        let now = Utc::now().naive_utc();
                        let layer = Layers {
                            id: layer_id,
                            repo: self.repo_name.to_string(),
                            digest: layer_digest.to_string(),
                            file_path: self.path_buf.to_str().unwrap().to_string(),
                            size: l.size,
                            access_count: 1,
                            created_at: now,
                            updated_at: now,
                            last_accessed_at: now,
                            uploaded_by: Some(self.user_roles.username.clone()),
                        };
                        diesel::insert_into(layers)
                            .values(&layer)
                            .execute(c)?;
                        layer_id
                    } else {
                        trace!("layer already exists: {:?}", l);
                        // insert if not exist
                        diesel::update(layers.find(found_layer[0].id))
                            .set((
                                last_accessed_at.eq(Utc::now().naive_utc()),
                                access_count.eq(access_count + 1)
                            ))
                            .execute(c)?;
                        found_layer[0].id
                    }
                };

                {
                    use crate::schema::manifests2layers::dsl::*;
                    let manifest2layer = Manifests2Layers {
                        manifest: manifest_id,
                        layer: layer_id,
                    };
                    trace!("insert manifest2layer: {:?}", manifest2layer);
                    // insert if not exist
                    diesel::insert_into(manifests2layers)
                        .values(&manifest2layer)
                        .on_conflict_do_nothing()
                        .execute(c)?;
                }
            }
        }
        let result: Result<usize, RegistryError> = Ok(1);
        result
    }

    fn insert_new_tag(&self, c: &mut DbConnection, manifest_id: Uuid) -> Result<i64, RegistryError> {
        use crate::schema::tags::dsl::*;
        let now = Utc::now().naive_utc();
        let tag_to_create = TagsWithoutId {
            manifest: manifest_id,
            repo: self.repo_name.to_string(),
            tag: self.image_tag.to_string(),
            access_count: 1,
            created_at: now,
            updated_at: now,
            last_accessed_at: now,
            uploaded_by: Some(self.user_roles.username.clone()),
        };
        debug!("insert new tag: {:?} for {}:{}", tag_to_create, self.image_name, self.image_tag);
        let created_id = diesel::insert_into(tags)
            .values(&tag_to_create)
            .returning(id)
            .get_result::<i64>(c)?;
        trace!("created id: {:?}", created_id);
        Ok(created_id)
    }

    fn insert_new_manifest(&self, c: &mut DbConnection, json_manifest: &DockerManifest) -> Result<Uuid, RegistryError> {
        use crate::schema::manifests::dsl::*;
        let now = Utc::now().naive_utc();
        let manifest = Manifests {
            id: Uuid::new_v4(),
            repo: self.repo_name.to_string(),
            digest: self.sha256_digest.to_string(),
            path: self.image_name.to_string(),
            file_path: self.path_buf.to_str().unwrap().to_string(),
            configuration: json_manifest.config.digest.clone(),
            access_count: 1,
            created_at: now,
            updated_at: now,
            last_accessed_at: now,
            uploaded_by: Some(self.user_roles.username.clone()),
        };
        debug!("insert new manifest: {:?}", manifest);
        diesel::insert_into(manifests)
            .values(&manifest)
            .execute(c)?;

        // insert layers
        Ok(manifest.id)
    }
}