# Brinecrypt

Brinecrypt is a secure resource management and encryption service designed to provide a centralized way to store, version, and manage sensitive configuration data and secrets. It features a robust RBAC system, multi-layered authentication, and transparent AES-256-GCM encryption.

## Key Features

- **Transparent Encryption:** Automatically encrypts/decrypts resources of type `encrypted` using AES-256-GCM with per-version unique Data Encryption Keys (DEKs).
- **Resource Versioning:** Maintains a full history of all resource changes, allowing retrieval of any previous version.
- **Granular RBAC:** Flexible permission system based on Principals (Users/SAs), Verbs (List/Read/Write/Delete), and Resource Patterns (e.g., `prod/*`).
- **Flexible Authentication:**
  - Session-based login for interactive use.
  - Personal Access Tokens (PATs) for programmatic access.
  - Capability Tokens for restricted, delegated access.
  - Kubernetes Service Account integration.
  - Anonymous Tokens for unauthenticated read-only access to public resources.
- **Audit Log:** Every mutating operation and auth event is recorded with actor, action, resource, status, and remote address. Queryable via `GET /admin/audit`.
- **Developer Friendly:** High-performance incremental builds with Docker and live-reloading via Air.

## Architecture

Brinecrypt is built with:
- **Language:** Go 1.25+
- **Database:** PostgreSQL 16+
- **ORM:** GORM
- **Encryption:** AES-256-GCM (Master key provided via `BRINECRYPT_KEK`)
- **API:** OpenAPI 3.0 compliant REST API

## Getting Started

### Prerequisites

- Docker and Docker Compose
- A 32-byte (64 hex characters) encryption key for the Master KEK.

### Development Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/brinecrypt.git
    cd brinecrypt
    ```

2.  **Generate a Master KEK (if you don't have one):**
    ```bash
    openssl rand -hex 32
    ```

3.  **Configure environment:**
    Update the `BRINECRYPT_KEK` in `docker-compose.yaml` with your generated key.

4.  **Start the environment:**
    ```bash
    docker-compose up --build
    ```
    This will start PostgreSQL and the Brinecrypt app with live-reloading enabled via `air`.

### Production Build

To build a minimized, secure production image:
```bash
docker build -f Dockerfile.prod -t brinecrypt:latest .
```

## API Documentation

The API is fully documented using OpenAPI 3.0. You can find the specification in:
- `./openapi/openapi.yaml`

### Common Operations

- **Login:** `POST /auth/login`
- **Issue PAT:** `POST /api/v1/tokens/pat`
- **List namespaces:** `GET /api/v1/namespace?op=list`
- **List resources in namespace:** `POST /api/v1/namespace?op=query` — body: `{"namespace":"<ns>"}`
- **Store resource:** `PUT /api/v1/resource` — body: `{"namespace":"<ns>","name":"<name>","type":"cleartext|encrypted","value":"<data>"}`
- **Retrieve resource:** `POST /api/v1/resource?op=query` — body: `{"namespace":"<ns>","name":"<name>"}` (add `"version":"<n|uuid|latest>"` for a specific version)
- **List versions:** `POST /api/v1/resource?op=versions` — body: `{"namespace":"<ns>","name":"<name>"}`
- **Delete resource:** `DELETE /api/v1/resource` — body: `{"namespace":"<ns>","name":"<name>"}`
- **Query Audit Log:** `GET /admin/audit` (params: `actor`, `action`, `resource`, `status`, `since`, `until`, `limit`)

Anonymous permissions are additive: every principal (including unauthenticated callers) transparently gains access to resources covered by the anon permission set without explicit grants on their account.

### User & Permission Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/user` | Session or PAT | Returns the calling user's own permissions (self-info). Cap tokens and SAs are not supported. |
| `GET /admin/user?op=list` | Session + `_/users` list | Lists all user names. |
| `GET /admin/user?op=query` | Session + `_/users` read | Returns permissions for queried principals. Body: `{"query": [{"username":"<name>"}, {"namespace":"<ns>","sa":"<name>"}, {"cap_token":<id>}]}` |
| `POST /admin/user` | Session + `_/users` write | Creates a new user. |
| `DELETE /admin/user/{name}` | Session + `_/users` delete | Deletes a user. |

### Anonymous Access

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/anon` | None (public) | Lists the anonymous permission set — what any caller of `/auth/anon` will receive. Not secret. |
| `POST /auth/anon` | None | Issues a short-lived capability token scoped to the anonymous permissions. |
| `GET /admin/anon/permissions` | Session + `_/users` list | Admin view of the anonymous permission template. |
| `POST /admin/anon/permissions` | Session + `_/users` write | Adds patterns to the anonymous permission set. |
| `DELETE /admin/anon/permissions/{id}` | Session + `_/users` write | Removes a pattern from the anonymous permission set. |

## Security Model

Brinecrypt uses an **Envelope Encryption** strategy:
1.  A unique **DEK** (Data Encryption Key) is generated for every version of an encrypted resource.
2.  The resource data is encrypted with the DEK using **AES-256-GCM**.
3.  The DEK is then encrypted with the **Master KEK** (Key Encryption Key) provided via environment variables.
4.  Only the encrypted DEK and the encrypted data are stored in the database.
