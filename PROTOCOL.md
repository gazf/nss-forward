# NSS Forward — HTTP Protocol

The NSS Forward server exposes a plain-text HTTP API.
All responses are UTF-8 text in `/etc/passwd` or `/etc/group` format.

## Endpoints

| Method | Path                | Description                    |
|--------|---------------------|--------------------------------|
| GET    | `/passwd/{name}`    | Look up user by name           |
| GET    | `/passwd/uid/{uid}` | Look up user by UID (integer)  |
| GET    | `/group/{name}`     | Look up group by name          |
| GET    | `/group/gid/{gid}`  | Look up group by GID (integer) |

## Response formats

### Passwd entry (HTTP 200)

```
alice:x:10001:100:Alice Smith:/home/alice:/bin/sh
```

Fields: `name:password:uid:gid:gecos:home:shell`

- `password` is always the literal string `x`
- `gecos` may be empty

### Group entry (HTTP 200)

```
staff:x:100:alice,bob,carol
```

Fields: `name:password:gid:members`

- `members` is a comma-separated list of usernames (may be empty)

### Not found (HTTP 404)

```
Not Found
```

### Server error (HTTP 500)

```
Internal Server Error
```

## Environment variables (server)

| Variable          | Default                     | Description                    |
|-------------------|-----------------------------|--------------------------------|
| `LDAP_URL`        | `ldap://localhost:389`      | LDAP server URL                |
| `LDAP_BIND_DN`    | *(required)*                | Bind DN for Simple Auth        |
| `LDAP_BIND_PW`    | *(required)*                | Bind password                  |
| `LDAP_USER_BASE`  | *(required)*                | Search base for users          |
| `LDAP_GROUP_BASE` | *(required)*                | Search base for groups         |
| `PORT`            | `8080`                      | HTTP listen port               |

## Environment variables (client .so)

| Variable          | Default                     | Description                    |
|-------------------|-----------------------------|--------------------------------|
| `NSS_PROXY_URL`   | `http://nss-proxy:8080`     | Base URL of the NSS server     |
