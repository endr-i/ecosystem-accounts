# ecosystem-accounts

Accounts microservice in Go. Owns tenant/account context: users create accounts
and are assigned to them as members. Authentication is delegated to
[`ecosystem-auth`](https://github.com/endr-i/ecosystem-auth) — this service only
verifies the access tokens it issues. Backed by PostgreSQL.

## Stack

- Go (stdlib `net/http`), pgx/v5
- Access tokens verified locally as HS256 JWTs using the secret shared with
  `ecosystem-auth`; the token subject is the user ID
- Embedded SQL migrations applied automatically on startup

## Running

```sh
docker compose up --build
```

Or locally against your own Postgres:

```sh
export DATABASE_URL=postgres://accounts:accounts@localhost:5432/accounts?sslmode=disable
export JWT_SECRET=your-secret   # must match ecosystem-auth
go run ./cmd/server
```

### Configuration

| Env var        | Required | Default          | Description                                    |
| -------------- | -------- | ---------------- | ---------------------------------------------- |
| `DATABASE_URL` | yes      | —                | Postgres connection string                     |
| `JWT_SECRET`   | yes      | —                | HMAC secret, must match `ecosystem-auth`       |
| `JWT_ISSUER`   | no       | `ecosystem-auth` | Expected `iss` claim; empty disables the check |
| `PORT`         | no       | `8081`           | HTTP listen port                               |

## Data model

**Account** — `id`, `name`, `slug` (unique), `status` (`ACTIVE` / `SUSPENDED` /
`DELETED`), `created_at`, `updated_at`.

**AccountMember** — `account_id`, `user_id`, `role` (`OWNER` / `ADMIN` /
`MEMBER`), `status` (`INVITED` / `ACTIVE` / `DISABLED`), `created_at`,
`updated_at`. Primary key is `(account_id, user_id)`, so a user has at most one
membership per account.

`user_id` refers to a user in `ecosystem-auth`; there is no foreign key across
the service boundary.

## API

Base path: `/api/v1`. Both account endpoints require
`Authorization: Bearer <access_token>` and return `401` otherwise.

### `POST /api/v1/accounts`

Creates an account; the caller becomes its `OWNER` member with status `ACTIVE`.
The account row and the owner membership are written in one transaction.

```json
{ "name": "Acme Corp", "slug": "acme-corp" }
```

`slug` is optional. When omitted it is derived from the name, with a numeric
suffix (`acme-corp-2`, `acme-corp-3`, …) appended if that slug is already taken.
When given explicitly it must match `^[a-z0-9]+(-[a-z0-9]+)*$`, be 2–63
characters, and a collision returns `409`.

Returns `201` with the account:

```json
{
  "id": "…",
  "name": "Acme Corp",
  "slug": "acme-corp",
  "status": "ACTIVE",
  "created_at": "…",
  "updated_at": "…"
}
```

`400` on validation errors, `409` if an explicitly requested slug is taken.

### `GET /api/v1/accounts`

Lists the accounts the caller is a member of, newest first, along with their
membership. Accounts with status `DELETED` are excluded.

```json
{
  "accounts": [
    {
      "id": "…",
      "name": "Acme Corp",
      "slug": "acme-corp",
      "status": "ACTIVE",
      "created_at": "…",
      "updated_at": "…",
      "role": "OWNER",
      "member_since": "…",
      "member_status": "ACTIVE"
    }
  ]
}
```

### `GET /healthz`

Liveness probe.

## Tests

```sh
go test ./...
```
