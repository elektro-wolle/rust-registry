// @generated automatically by Diesel CLI.

diesel::table! {
    layers (id) {
        #[max_length = 255]
        id -> Varchar,
        #[max_length = 255]
        file_path -> Varchar,
        access_count -> Int8,
        #[max_length = 255]
        uploaded_by -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_accessed_at -> Timestamp,
    }
}

diesel::table! {
    manifests (id) {
        #[max_length = 255]
        id -> Varchar,
        #[max_length = 255]
        path -> Varchar,
        #[max_length = 255]
        file_path -> Varchar,
        access_count -> Int8,
        #[max_length = 255]
        uploaded_by -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_accessed_at -> Timestamp,
    }
}

diesel::table! {
    manifests2layers (manifest, layer) {
        #[max_length = 255]
        manifest -> Varchar,
        #[max_length = 255]
        layer -> Varchar,
    }
}

diesel::table! {
    tags (id) {
        id -> Int8,
        #[max_length = 255]
        manifest -> Varchar,
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
