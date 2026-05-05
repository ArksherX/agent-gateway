CREATE TABLE agent_gateway_schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO agent_gateway_schema_version (version) VALUES (1);

CREATE TABLE principal_signing_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL CHECK (algorithm = 'ecdsa_p256_sha256'),
    public_key_spki_der BYTEA NOT NULL UNIQUE,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (key_id <> ''),
    CHECK (not_before < not_after)
);

CREATE TABLE principal_key_permissions (
    id BIGSERIAL PRIMARY KEY,
    signing_key_id TEXT NOT NULL REFERENCES principal_signing_keys(key_id),
    destination TEXT NOT NULL CHECK (destination <> ''),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (not_before < not_after)
);

CREATE TABLE permission_registry (
    permission_id TEXT PRIMARY KEY,
    signing_key_id TEXT NOT NULL REFERENCES principal_signing_keys(key_id),
    subject_identity TEXT NOT NULL CHECK (subject_identity <> ''),
    subject_public_key_spki_der BYTEA NOT NULL,
    destination TEXT NOT NULL CHECK (destination <> ''),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (permission_id <> ''),
    CHECK (not_before < not_after)
);

CREATE INDEX permission_registry_active_lookup_idx
    ON permission_registry (subject_identity, destination, subject_public_key_spki_der, not_after DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX principal_key_permissions_active_scope_idx
    ON principal_key_permissions (signing_key_id, destination)
    WHERE revoked_at IS NULL;
