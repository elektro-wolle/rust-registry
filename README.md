# docker registry in rust

## TODOs

- [ ] rewrite for actix-web
- [ ] docker push pong:8000/foo/sen:1.2.3  -> invalid checksum digest format
- [ ] docker pull pong:8000/foo/sen:1.2.3  -> Error response from daemon: missing signature key
- [ ] add tests, based on https://github.com/ecarrara/oci-registry-client
- [ ] sha256 checks
- [ ] Streaming upload
- [ ] Streaming download
- [ ] basic auth credentials
- [ ] `docker login` with username and password
- [ ] add `docker login` token support
- [ ] add docker-compose file for easy setup
- [ ] add database backend for reference counting and garbage collection
- [ ] add search within database
- [ ] ldap auth
- [ ] config file for auth and storage backends
- [ ] make trait for auth backend
- [ ] make trait for storage backend
- [ ] implement storage backend for local fs
- [ ] implement storage backend for s3
- [ ] add tls support
- [ ] add virtual host support
- [ ] semver parsing for tags, keeping the latest x-major, y-minor, z-patch versions
- [ ] cleanup-jobs for removing old images/manifests
