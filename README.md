# ecosystem-accounts

Accounts microservice in Go. Owns tenant/account context: users create accounts
and are assigned to them as members. Authentication is delegated to
[`ecosystem-auth`](https://github.com/endr-i/ecosystem-auth) — this service only
verifies the access tokens it issues. Backed by PostgreSQL.

## Stack

- Go (stdlib `net/http`), pgx/v5
- Access tokens verified locally as RS256 JWTs against public keys fetched from
  the auth service's JWKS endpoint; the token subject is the user ID
- Embedded SQL migrations applied automatically on startup

## Running

### Default: against the ecosystem

The default way to run this service is as a container on the shared
`ecosystem` Docker network published by
[`ecosystem-infra`](https://github.com/endr-i/ecosystem-infra), using the
Postgres and `ecosystem-auth` already running there. Start infra first (so the
`ecosystem` network and its Postgres exist), then:

```sh
export ACCOUNTS_DB_PASSWORD=<password>
docker compose -f docker-compose.ecosystem.yml up --build
```

This starts only the `accounts` container -- no local Postgres -- and attaches
it to the external `ecosystem` network, where it reaches Postgres at
`postgres:5432` and `ecosystem-auth` at `http://ecosystem-auth:8080`. If the
`ecosystem` network doesn't exist yet, `docker compose` fails with a "network
not found" error; create it (or start `ecosystem-infra`) first.

### Dev: standalone with its own Postgres

For local development without `ecosystem-infra`, `docker-compose.yml` brings up
its own throwaway Postgres alongside the service:

```sh
docker compose up --build
```

This still expects `ecosystem-auth` reachable at `http://ecosystem-auth:8080`
to fetch signing keys; run it separately and join it to this compose project's
network, or override `AUTH_BASE_URL` (see below) to point at wherever it's
running.

### Running the binary directly

```sh
export DATABASE_URL=postgres://accounts:<password>@localhost:5432/accounts?sslmode=disable
export AUTH_BASE_URL=http://localhost:8080
go run ./cmd/server
```

The service needs `ecosystem-auth` reachable at startup to load its signing
keys.

### Configuration

| Env var                      | Required | Default                     | Description                                                 |
| ---------------------------- | -------- | --------------------------- | ----------------------------------------------------------- |
| `DATABASE_URL`               | yes      | —                           | Postgres connection string                                  |
| `AUTH_BASE_URL`              | yes\*    | —                           | Base address of `ecosystem-auth`, e.g. `http://auth:8080`    |
| `AUTH_JWKS_URL`              | yes\*    | `$AUTH_BASE_URL` + JWKS path | Explicit JWKS endpoint; overrides `AUTH_BASE_URL`           |
| `AUTH_ISSUER`                | no       | `ecosystem-auth`            | Expected `iss` claim; empty disables the check              |
| `AUTH_JWKS_REFRESH_INTERVAL` | no       | `5m`                        | How often cached keys are refreshed                         |
| `AUTH_JWKS_TIMEOUT`          | no       | `5s`                        | Timeout for a single JWKS request                           |
| `AUTH_JWKS_STARTUP_TIMEOUT`  | no       | `30s`                       | How long to retry the initial key fetch before giving up    |
| `PORT`                       | no       | `8081`                      | HTTP listen port                                            |

\* At least one of `AUTH_BASE_URL` or `AUTH_JWKS_URL` is required. When only
`AUTH_BASE_URL` is set, the JWKS URL becomes
`$AUTH_BASE_URL/.well-known/jwks.json`.

> `AUTH_ISSUER` is the value of the `iss` claim, which `ecosystem-auth`
> currently sets to the identifier `ecosystem-auth` — not its URL. Only change
> it if the auth service starts issuing a different `iss`.

`DATABASE_URL` above is only used when running the Go binary directly; each
compose file builds it from its own variable instead:

| Compose file                   | Variable              | Default    | Notes                                          |
| ------------------------------- | --------------------- | ---------- | ----------------------------------------------- |
| `docker-compose.ecosystem.yml`  | `ACCOUNTS_DB_PASSWORD` | *(none)*   | Required; the run fails fast if unset          |
| `docker-compose.yml` (dev)      | `POSTGRES_PASSWORD`    | `accounts` | Also sets the throwaway Postgres's own password |

## Token verification

Access tokens are RS256 JWTs carrying a `kid` header. On startup the service
fetches `GET /.well-known/jwks.json` from the auth service (retrying with
backoff, since auth may still be coming up) and caches the RSA public keys, so
no network call happens per request.

Keys are refreshed on a timer, and a token whose `kid` is not cached triggers an
immediate out-of-band refresh — rate limited to once every 30 seconds — so key
rotation is picked up without a restart. If a refresh fails, the previously
cached keys keep being served.

Verification enforces `alg: RS256` and a valid `kid`, which rejects both
`alg: none` and HS256 algorithm-confusion tokens.

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
