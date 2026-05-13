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

The API is also described in `./openapi/openapi.yaml`.

All endpoints except those marked "None" require a `Authorization: Bearer <token>` header.

### Authentication

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /auth/login` | None | Obtain session and refresh tokens. Body: `{"user":"<name>","pass":"<pass>"}`. Returns `{"session_token":"...","refresh_token":"..."}`. |
| `POST /auth/refresh` | None | Exchange a refresh token for a new session + refresh token pair. Body: `{"token":"<refresh_token>"}`. |
| `DELETE /auth/logout` | Bearer | Invalidate the current session token. |
| `POST /auth/anon` | None | Issue a short-lived capability token scoped to the anonymous permission set. Returns 503 if no anon permissions are configured. |

### Token Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/tokens/pat` | Session or PAT | Issue a Personal Access Token for the calling user. Optional body: `{"expiry":"<RFC3339>"}`. Returns `{"token":"pat_..."}`. |
| `DELETE /api/v1/tokens/pat/{id}` | Session or PAT | Revoke a PAT by ID. Only the owning user may revoke their own PATs. |
| `POST /api/v1/tokens/capability` | Session or PAT | Issue a capability token scoped to a subset of the caller's own permissions. Body: `{"permissions":[{"verb":"<verb>","resource_pattern":"<ns>/<name>"}]}`. Returns `{"token":"cap_..."}`. |
| `DELETE /api/v1/tokens/capability/{id}` | Session or PAT | Revoke a capability token by ID. Only the issuing user may revoke. |

### Namespaces

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/namespace?op=list` | Any | Returns namespaces the caller has permissions on, with available verbs. Callers with `_/ns` list see all DB namespaces. |
| `POST /api/v1/namespace?op=query` | Any | List resources in a namespace. Body: `{"namespace":"<ns>"}`. Requires list permission on the namespace (or `_/ns` read). |
| `POST /api/v1/namespace?op=create` | Session + `_/ns` write | Create a namespace explicitly. Body: `{"namespace":"<ns>"}`. Returns 409 if it already exists. |
| `POST /api/v1/namespace?op=delete` | Session + `_/ns` delete | Delete an empty namespace. Body: `{"namespace":"<ns>"}`. Returns 409 if namespace has resources. |

### Resources

Anonymous permissions are additive: every principal (including unauthenticated callers) transparently gains access to resources covered by the anon permission set.

| Endpoint | Auth | Description |
|----------|------|-------------|
| `PUT /api/v1/resource` | Any (write perm) | Create or update a resource. Body: `{"namespace":"<ns>","name":"<name>","type":"cleartext\|encrypted","value":"<data>"}`. Creates the namespace if it does not exist. |
| `POST /api/v1/resource?op=query` | Any (read perm) | Fetch a resource. Body: `{"namespace":"<ns>","name":"<name>"}` for the latest version; add `"version":"<n\|uuid\|latest>"` for a specific version; or `{"uuid":"<uuid>"}` to look up a version directly by UUID. |
| `POST /api/v1/resource?op=versions` | Any (list perm) | List all versions of a resource. Body: `{"namespace":"<ns>","name":"<name>"}`. |
| `DELETE /api/v1/resource` | Any (delete perm) | Delete a resource and all its versions. Body: `{"namespace":"<ns>","name":"<name>"}`. |

### User & Permission Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/user` | Session or PAT | Returns the calling user's own permissions (self-info). Not available to capability tokens or SAs. |
| `GET /admin/user?op=list` | Session + `_/users` list | Lists all user names. |
| `GET /admin/user?op=query` | Session + `_/users` read | Returns permissions for one or more principals. Body: `{"query":[{"username":"<name>"},{"namespace":"<ns>","sa":"<name>"},{"cap_token":<id>},{"pat":<id>}]}`. PAT entries also return the owning user's current permissions. |
| `POST /admin/user` | Session + `_/users` write | Creates a new user. Body: `{"name":"<name>","pass":"<pass>","email":"<email>"}`. |
| `DELETE /admin/user/{name}` | Session + `_/users` delete | Deletes a user. |
| `POST /admin/permissions` | Session + `_/users` write | Grant permissions to a user or SA. Body: `{"principal":"user/<name>\|sa/<ns>/<name>","permissions":[{"verb":"<verb>","resource_pattern":"<ns>/<name>"}]}`. |
| `DELETE /admin/permissions` | Session + `_/users` write | Revoke matching permissions from a user or SA. Same body as grant. |

### Service Account Principals

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/principals` | Session + `_/sa` list | No body (or empty body): list all known service accounts. |
| `GET /admin/principals` | Session + `_/sa` read | Body `{"principals":[{"namespace":"<ns>","name":"<name>"}]}`: returns permissions for each named SA. Response key format: `"<ns>:<name>"`. |

### Anonymous Access

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/anon` | None (public) | Lists the anonymous permission set. Not secret — intended for self-discovery by unauthenticated clients. |
| `GET /admin/anon/permissions` | Session + `_/users` list | Admin view of the anonymous permission set (same data, auth-gated). |
| `POST /admin/anon/permissions` | Session + `_/users` write | Add patterns to the anonymous permission set. Body: array of `{"verb":"<verb>","resource_pattern":"<ns>/<name>"}`. |
| `DELETE /admin/anon/permissions/{id}` | Session + `_/users` write | Remove a pattern from the anonymous permission set by ID. |

### Audit Log

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/audit` | Session + `_/users` read | Query audit log entries. Query params: `actor`, `action`, `resource`, `status` (`ok\|denied\|error`), `since` (RFC3339), `until` (RFC3339), `limit` (1–10000). |

## Security Model

Brinecrypt uses an **Envelope Encryption** strategy:
1.  A unique **DEK** (Data Encryption Key) is generated for every version of an encrypted resource.
2.  The resource data is encrypted with the DEK using **AES-256-GCM**.
3.  The DEK is then encrypted with the **Master KEK** (Key Encryption Key) provided via environment variables.
4.  Only the encrypted DEK and the encrypted data are stored in the database.
