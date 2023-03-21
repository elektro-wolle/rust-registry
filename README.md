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
- [ ] add /v2/_catalog listing
- [ ] add /v2/<name>/tags/list
- [ ] basic auth credentials
- [x] ldap auth
- [ ] `docker login` with username and password
- [x] sha256 checks
- [x] Streaming upload
- [x] Streaming download
- [ ] add tests, based on https://github.com/ecarrara/oci-registry-client
- [ ] add synchronisation for concurrent uploads
- [ ] add proxying request to other registries
- [ ] add virtual host support
- [ ] add support for multiple registries in one instance
- [ ] add support grouping registries in namespaces, e.g. first query the "dev" registry, then the "prod" registry
  before ghcr.io is queried.
- [ ] delete unfinished uploads
- [ ] add `docker login` token support
- [ ] add docker-compose file for easy setup of database
- [ ] add database backend for reference counting and garbage collection
- [ ] add search within database
- [ ] add /v2/_catalog listing via DB
- [ ] config file for auth and storage backends
- [ ] add DELETE Endpoints
- [ ] make trait for auth backend
- [ ] make trait for storage backend
- [ ] implement storage backend for local fs
- [ ] implement storage backend for s3
- [x] add tls support
- [ ] semver parsing for tags, keeping the latest x-major, y-minor, z-patch versions
- [ ] cleanup-jobs for removing old images/manifests

# License

Licensed under

* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.
