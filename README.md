# docker registry in rust

Rewrite of the [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/) in rust, using actix-web.
It is intended to be used as a private registry for docker images as a replacement for nexus.

This project will implement the server-side of the registry API, but not the client-side.
For client-side functionality, please use [dkregistry-rs](https://github.com/camallo/dkregistry-rs).

**This is a work in progress.**

## Planned Features:

- LDAP Authentication (with groups): Each group can be limited to a namespaces (e.g. group "dev" can only pull/push
  images matching "foo/img/*")
- Better Lifecycle Management: e.g. keep only the latest 5 major, 3 minor (of the last major version), all patch
  versions (of the last major version) of an image, or is accessed in the last 30 days.
- Use maven-inspired semver tags: e.g. "-SNAPSHOT" for latest build, "-RC" for release candidate. Releases can be
  configured as non over-writable.
- Allow saving to local file system or S3.
- Using a database for reference counting and garbage collection.

Currently, only the basic functionality is implemented. The following features are missing:

# TODOs

- [x] rewrite endpoints for actix-web
- [x] add logging
- [x] docker push pong:8000/foo/sen:1.2.3 -> invalid checksum digest format
- [x] docker pull pong:8000/foo/sen:1.2.3 -> Error response from daemon: missing signature key
- [x] add CORS Headers
- [x] HEAD /v2/<name>/blobs/sha256:<digest>
- [x] basic auth credentials
- [x] ldap auth
- [x] make ldap search configurable
- [x] `docker login` with username and password
- [x] sha256 checks
- [x] Streaming upload
- [x] Streaming download
- [ ] add tests, based on https://github.com/ecarrara/oci-registry-client
- [x] add synchronisation for concurrent uploads
- [x] add support for multiple registries in one instance
- [x] add test-container for testing against ldap
- [x] deduplicate layers
- [ ] add proxying request to other registries
- [ ] add support grouping registries in namespaces, e.g. first query the "dev" registry, then the "prod" registry
  before ghcr.io is queried.
- [x] add rights management for namespaces
- [ ] add docker-compose file for easy setup of database
- [ ] add database backend for reference counting and garbage collection: https://diesel.rs/guides/getting-started.html
- [ ] async calls to database: https://hub.packtpub.com/multithreading-in-rust-using-crates-tutorial/
- [ ] add search within database
- [ ] delete unfinished uploads
- [ ] multiple uploads of the same tag result in multiple manifests, indentation is changed (3 vs 4 spaces).
- [x] add /v2/_catalog listing
- [x] add /v2/<name>/tags/list
- [ ] config file for auth and storage backends
- [ ] make trait for storage backend
- [x] implement storage backend for local fs
- [ ] implement storage backend for s3
- [x] add tls support
- [ ] semver parsing for tags, keeping the latest x-major, y-minor, z-patch versions
- [ ] cleanup-jobs for removing old images/manifests

# Maybe

- [ ] add DELETE Endpoints
- [ ] make trait for auth backend
- [ ] add `docker login` token support
- [ ] add virtual host support

# License

Licensed under

* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
