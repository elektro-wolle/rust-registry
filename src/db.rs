use std::path::Path;

use actix_web::http::StatusCode;
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use log::{debug, trace};

use crate::configuration::UserRoles;
use crate::DbConn;
use crate::error::RegistryError;

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::manifests)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Manifests {
    pub id: String,
    //  varchar(255) not null primary key,
    pub path: String,
    //  varchar(255) not null,
    pub file_path: String,
    pub access_count: i64,
    //  varchar(255) not null default 'latest',
    pub uploaded_by: Option<String>,
    //  varchar(255),
    pub created_at: NaiveDateTime,
    //  timestamp    not null default current_timestamp,
    pub updated_at: NaiveDateTime,
    //  timestamp    not null default current_timestamp,
    pub last_accessed_at: NaiveDateTime, //  timestamp    not null default current_timestamp
}

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::tags)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Tags {
    pub id: i64,
    pub manifest: String,
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
    pub manifest: String,
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
    pub id: String,
    //  varchar(255) not null primary key,
    pub file_path: String,
    pub access_count: i64,
    //  varchar(255) not null,
    pub uploaded_by: Option<String>,
    //  varchar(255),
    pub created_at: NaiveDateTime,
    //  timestamp    not null default current_timestamp,
    pub updated_at: NaiveDateTime,
    //  timestamp    not null default current_timestamp,
    pub last_accessed_at: NaiveDateTime, //  timestamp    not null default current_timestamp
}

#[derive(Queryable, Selectable, Insertable, Debug, Eq, PartialEq)]
#[diesel(table_name = crate::schema::manifests2layers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Manifests2Layers {
    pub manifest: String,
    //  varchar(255) not null,
    pub layer: String, //  varchar(255) not null,
}


/**
 * Update the last_accessed_at field of the manifest and tag.
 * @param fail_if_not_found, if true, will return error if manifest not found. Otherwise, will create a new manifest and tag.
 */
pub fn update_access_time_to_manifest_and_tag(
    mut conn: DbConn,
    digest_to_update: &str,
    path_buf: &Path,
    user_roles: &UserRoles,
    image_tag: &str,
    image_name: &str,
    fail_if_not_found: bool,
) -> Result<usize, RegistryError> {
    conn.build_transaction().read_write().run(|c| {
        let now = Utc::now().naive_utc();
        {
            // add manifest if not exists (and is allowed to be created)
            use crate::schema::manifests::dsl::*;
            let manifest = manifests
                .find(&digest_to_update)
                .select(Manifests::as_select())
                .load(c)?;

            trace!("loaded manifest: {:?}", manifest);

            let now = Utc::now().naive_utc();
            if manifest.is_empty() {
                if fail_if_not_found {
                    return Err(RegistryError::new(
                        StatusCode::NOT_FOUND,
                        "manifest not found",
                        &format!("manifest not found: {}", digest_to_update),
                    ));
                }
                let manifest = Manifests {
                    id: digest_to_update.to_string(),
                    path: image_name.to_string(),
                    file_path: path_buf.to_str().unwrap().to_string(),
                    access_count: 1,
                    created_at: now,
                    updated_at: now,
                    last_accessed_at: now,
                    uploaded_by: Some(user_roles.username.clone()),
                };
                debug!("insert new manifest: {:?}", manifest);
                diesel::insert_into(manifests)
                    .values(&manifest)
                    .execute(c)?
            } else {
                trace!("update manifest {}:{} last_accessed : {:?}", image_name, image_tag, now);
                diesel::update(manifests.find(digest_to_update))
                    .set((
                        last_accessed_at.eq(now),
                        access_count.eq(access_count + 1)
                    ))
                    .execute(c)?
            };
        }
        {
            // add tag to the manifest if not exists (and is allowed to be created)
            use crate::schema::tags::dsl::*;
            let found_tag = tags
                .filter(tag.eq(image_tag).and(manifest.eq(digest_to_update)))
                .select(Tags::as_select())
                .load::<Tags>(c)?;
            if found_tag.is_empty() {
                if fail_if_not_found {
                    return Err(RegistryError::new(
                        StatusCode::NOT_FOUND,
                        "tag not found",
                        &format!("tag not found: {}", digest_to_update),
                    ));
                }

                let tag_to_create = TagsWithoutId {
                    manifest: digest_to_update.to_string(),
                    tag: image_tag.to_string(),
                    access_count: 1,
                    created_at: now,
                    updated_at: now,
                    last_accessed_at: now,
                    uploaded_by: Some(user_roles.username.clone()),
                };
                debug!("insert new tag: {:?} for {}:{}", tag_to_create, image_name, image_tag);
                let created_id = diesel::insert_into(tags)
                    .values(&tag_to_create)
                    .returning(id)
                    .get_result::<i64>(c)?;
                trace!("created id: {:?}", created_id);
            } else {
                let id_to_update = found_tag[0].id;
                trace!("update tag {}:{} with id {} last_accessed : {:?}", image_name, image_tag, id_to_update, now);
                diesel::update(tags.find(id))
                    .set((
                        last_accessed_at.eq(now),
                        access_count.eq(access_count + 1)
                    ))
                    .execute(c)?;
            };
        }
        let result: Result<usize, RegistryError> = Ok(1);
        result
    })
}
