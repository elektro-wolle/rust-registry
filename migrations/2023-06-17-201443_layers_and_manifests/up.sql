-- Your SQL goes here
create table manifests
(
    -- the sha256 of the manifest
    id               varchar(255) not null primary key,
    path             varchar(255) not null,
    file_path        varchar(255) not null,
    access_count     bigint       not null default 0,
    uploaded_by      varchar(255),
    created_at       timestamp    not null default current_timestamp,
    updated_at       timestamp    not null default current_timestamp,
    last_accessed_at timestamp    not null default current_timestamp
);

create table tags
(
    id               bigserial    not null primary key,
    manifest         varchar(255) not null references manifests,
    tag              varchar(255) not null default 'latest',
    access_count     bigint       not null default 0,

    uploaded_by      varchar(255),
    created_at       timestamp    not null default current_timestamp,
    updated_at       timestamp    not null default current_timestamp,
    last_accessed_at timestamp    not null default current_timestamp
);

create table layers
(
    -- the sha256 of the image
    id               varchar(255) not null primary key,
    file_path        varchar(255) not null,
    access_count     bigint       not null default 0,

    uploaded_by      varchar(255),
    created_at       timestamp    not null default current_timestamp,
    updated_at       timestamp    not null default current_timestamp,
    last_accessed_at timestamp    not null default current_timestamp
);

create table manifests2layers
(
    manifest varchar(255) not null references manifests,
    layer    varchar(255) not null references layers,
    constraint pk_m2l PRIMARY KEY (manifest, layer)
);

create unique index ix_l2m on manifests2layers (layer, manifest);