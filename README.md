# docker registry in rust

## TODOs

- [ ] rewrite for actix-web
- [ ] docker push pong:8000/foo/sen:1.2.3  -> invalid checksum digest format
- [ ] docker pull pong:8000/foo/sen:1.2.3  -> Error response from daemon: missing signature key
- [ ] sha256 checks
- [ ] Streaming upload
- [ ] Streaming download
- [ ] basic auth credentials
- [ ] add database backend for reference counting and garbage collection
- [ ] add search within database
- [ ] ldap auth
- [ ] make trait for auth backend
- [ ] docker login
- [ ] make trait for storage backend
- [ ] implement storage backend for local fs
- [ ] implement storage backend for s3
