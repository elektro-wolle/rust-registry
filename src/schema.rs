// @generated automatically by Diesel CLI.

diesel::table! {
    layers (id) {
        id -> Uuid,
        #[max_length = 255]
        repo -> Varchar,
        #[max_length = 255]
        digest -> Varchar,
        #[max_length = 255]
        file_path -> Varchar,
        access_count -> Int8,
        size -> Int8,
        #[max_length = 255]
        uploaded_by -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_accessed_at -> Timestamp,
    }
}

diesel::table! {
    manifests (id) {
        id -> Uuid,
        #[max_length = 255]
        repo -> Varchar,
        #[max_length = 255]
        digest -> Varchar,
        #[max_length = 255]
        path -> Varchar,
        #[max_length = 255]
        file_path -> Varchar,
        access_count -> Int8,
        #[max_length = 255]
        uploaded_by -> Nullable<Varchar>,
        #[max_length = 255]
        configuration -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_accessed_at -> Timestamp,
    }
}

diesel::table! {
    manifests2layers (manifest, layer) {
        manifest -> Uuid,
        layer -> Uuid,
    }
}

diesel::table! {
    tags (id) {
        id -> Int8,
        #[max_length = 255]
        repo -> Varchar,
        manifest -> Uuid,
        #[max_length = 255]
        tag -> Varchar,
        access_count -> Int8,
        #[max_length = 255]
        uploaded_by -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_accessed_at -> Timestamp,
    }
}

diesel::joinable!(manifests2layers -> layers (layer));
diesel::joinable!(manifests2layers -> manifests (manifest));
diesel::joinable!(tags -> manifests (manifest));

diesel::allow_tables_to_appear_in_same_query!(
    layers,
    manifests,
    manifests2layers,
    tags,
);
