# docker registry in rust

Rewrite of docker-registry in rust, using actix-web. This is a work in progress.

Planned Features:

- LDAP Authentication (with groups): Each group can be limited to a namespaces (e.g. group "dev" can only pull/push
  images matching "foo/img/*")
- Better Lifecycle Management: e.g. keep only the latest 5 major, 3 minor (of the last major version), all patch
  versions (of the last major version) of an image, or is accessed in the last 30 days.
- Use maven-inspired semver tags: e.g. "-SNAPSHOT" for latest build, "-RC" for release candidate. Releases can be
  configured as non over-writable.
- Allow saving to local file system or S3.
- Using a database for reference counting and garbage collection.

Currently, only the basic functionality is implemented. The following features are missing:

## TODOs

- [x] rewrite for actix-web
- [x] add logging
- [x] docker push pong:8000/foo/sen:1.2.3 -> invalid checksum digest format
- [x] docker pull pong:8000/foo/sen:1.2.3 -> Error response from daemon: missing signature key
- [ ] add tests, based on https://github.com/ecarrara/oci-registry-client
- [x] sha256 checks
- [x] Streaming upload
- [x] Streaming download
- [ ] add synchronisation for concurrent uploads
- [ ] delete unfinished uploads
- [ ] basic auth credentials
- [ ] `docker login` with username and password
- [ ] add `docker login` token support
- [ ] add docker-compose file for easy setup of database
- [ ] add database backend for reference counting and garbage collection
- [ ] add search within database
- [ ] ldap auth
- [ ] config file for auth and storage backends
- [ ] make trait for auth backend
- [ ] make trait for storage backend
- [ ] implement storage backend for local fs
- [ ] implement storage backend for s3
- [x] add tls support
- [ ] add virtual host support
- [ ] semver parsing for tags, keeping the latest x-major, y-minor, z-patch versions
- [ ] cleanup-jobs for removing old images/manifests
