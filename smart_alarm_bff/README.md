# Smart Alarm BFF

Independent production control-plane service for Smart Alarm. This directory is a sibling of the untouched official `thingsboard-4.3.1.3` source tree.

The service owns product sessions, inventory binding, product roles, idempotency, approvals, notification outbox and audit associations. ThingsBoard remains authoritative for Device entities, telemetry, Alarm, RPC and OTA assignment.

## Production rules

- Start only with HTTPS/TLS upstreams and file-backed or workload-injected secrets.
- Run database migrations as a separate release job before API/worker rollout. The migrator, API and worker use distinct database identities; migration credentials are never mounted into runtime pods.
- Run API, worker and scheduler as separate processes and identities.
- Never mount the Docker socket or persist secrets in the image/database.
- Do not connect to or modify ThingsBoard internal database tables.

Configuration is documented in the parent repository at `deployment/preproduction.env.example`. `python -m smart_alarm_bff.config` validates the environment without printing secret values.

Direct and transitive runtime dependencies are pinned in `requirements.lock`. Production CI should additionally attach hashes/SBOM and sign the built image before promotion; the package index can be overridden with Docker build argument `PIP_INDEX_URL` without changing the lock.

## Commands

```bash
smart-alarm-migrate
smart-alarm-bff
```

The API exposes `/health`, `/ready` and loopback/protected `/metrics`, plus the initial `/api/v1/session` create/read/logout boundary. A session is created only after the presented ThingsBoard Bearer token is cross-checked against a locally registered user, an active Product Role and the mapped Tenant/Customer scope. The platform token is retained only as an AES-GCM envelope; the browser receives an HttpOnly/Secure cookie and a CSRF token. `SYS_ADMIN` deliberately has no Tenant or Customer scope; Tenant and Customer authorities must have both mappings present.

The first scoped directory routes are now available for Customer, Asset, Entity Group, Device Profile, managed-device and system Tenant/User/Role reads. Each query applies `smart_alarm.tenant_id` inside a transaction and also carries an explicit Customer predicate; RLS remains an independent backstop. Tenant, Customer, Customer-member, Asset, Device Profile and Entity Group lifecycle writes use the same session/CSRF boundary, idempotency record and append-only audit transaction. Device Profile type/transport metadata is persisted by a forward migration rather than reconstructed in the browser. System User creation remains suspended until an identity-provisioning outbox event has produced the required OIDC/ThingsBoard mapping; Product Role assignments validate authority and increment identity versions so existing sessions are revoked. Device registration now validates the immutable inventory UUID, serial number and one-time claim proof before it creates an `ACTIVATING` product record. Registration, metadata synchronization and retirement return a durable `QUEUED` operation and publish an outbox request; they do not claim that the ThingsBoard side effect has completed. The worker and ThingsBoard adapter are the next deployment stage. System scope is explicit and only enabled for a `SYS_ADMIN` principal, so global operation/audit records do not weaken Tenant isolation.

Business routes are added behind the same cookie session boundary. Readiness remains false until PostgreSQL, Redis, ThingsBoard and OIDC discovery are reachable.
