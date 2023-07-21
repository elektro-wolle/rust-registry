-- Your SQL goes here
create table manifests
(
    id               uuid         not null primary key,
    repo             varchar(255) not null,
    -- the sha256 of the manifest
    digest           varchar(255) not null,
    path             varchar(255) not null,
    file_path        varchar(255) not null,
    access_count     bigint       not null default 0,
    uploaded_by      varchar(255),
    configuration    varchar(255) not null,
    created_at       timestamp    not null default current_timestamp,
    updated_at       timestamp    not null default current_timestamp,
    last_accessed_at timestamp    not null default current_timestamp
);

create table tags
(
    id               bigserial    not null primary key,
    repo             varchar(255) not null,
    manifest         uuid         not null references manifests,
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
    id               uuid         not null primary key,
    repo             varchar(255) not null,
    digest           varchar(255) not null,
    file_path        varchar(255) not null,
    access_count     bigint       not null default 0,
    size             bigint       not null default 0,

    uploaded_by      varchar(255),
    created_at       timestamp    not null default current_timestamp,
    updated_at       timestamp    not null default current_timestamp,
    last_accessed_at timestamp    not null default current_timestamp
);

create table manifests2layers
(
    manifest uuid not null references manifests,
    layer    uuid not null references layers,
    constraint pk_m2l PRIMARY KEY (manifest, layer)
);

create unique index ix_l2m on manifests2layers (layer, manifest);