-- Foundry-owned operational state. Artifact bodies and grants stay outside this schema.
CREATE TABLE {schema}.schema_version (
    version integer PRIMARY KEY CHECK (version = 1),
    migration_digest text NOT NULL CHECK (migration_digest ~ '^[0-9a-f]{{64}}$')
);
CREATE TABLE {schema}.projects (
    project_id uuid PRIMARY KEY
);
CREATE TABLE {schema}.batches (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    batch_id uuid NOT NULL,
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{{64}}$'),
    manifest_ref jsonb NOT NULL,
    PRIMARY KEY (project_id, batch_id),
    UNIQUE (project_id, batch_id, manifest_digest)
);
CREATE TABLE {schema}.admission_reports (
    project_id uuid NOT NULL,
    report_digest text NOT NULL,
    batch_id uuid NOT NULL,
    manifest_digest text NOT NULL,
    report_ref jsonb NOT NULL,
    policy_ref jsonb NOT NULL,
    policy_version text NOT NULL,
    checked_at timestamptz NOT NULL,
    PRIMARY KEY (project_id, report_digest),
    FOREIGN KEY (project_id,batch_id,manifest_digest)
        REFERENCES {schema}.batches (project_id,batch_id,manifest_digest)
);
CREATE TABLE {schema}.assets (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    asset_id uuid NOT NULL,
    source_id uuid NOT NULL,
    original_digest text NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 9007199254740991),
    PRIMARY KEY (project_id, asset_id),
    UNIQUE (project_id,asset_id,source_id)
);
CREATE TABLE {schema}.admission_entries (
    project_id uuid NOT NULL,
    report_digest text NOT NULL,
    asset_id uuid NOT NULL,
    source_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('admitted','blocked','withdrawn')),
    snapshot_ref jsonb,
    reason_codes text[] NOT NULL,
    PRIMARY KEY (project_id,report_digest,asset_id),
    FOREIGN KEY (project_id,report_digest) REFERENCES {schema}.admission_reports,
    FOREIGN KEY (project_id,asset_id,source_id)
        REFERENCES {schema}.assets (project_id,asset_id,source_id),
    CHECK ((status = 'admitted') = (snapshot_ref IS NOT NULL))
);
CREATE TABLE {schema}.runs (
    project_id uuid NOT NULL,
    run_id uuid NOT NULL,
    admission_report_digest text NOT NULL,
    current_authorization_id uuid,
    max_run_cost numeric CHECK (max_run_cost > 0),
    max_concurrent_attempts bigint CHECK (max_concurrent_attempts > 0),
    frozen boolean NOT NULL DEFAULT false,
    freeze_reason text,
    PRIMARY KEY (project_id,run_id),
    FOREIGN KEY (project_id,admission_report_digest) REFERENCES {schema}.admission_reports
);
CREATE TABLE {schema}.authorizations (
    project_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    authorization_ref jsonb NOT NULL,
    allowed_plan_digests text[] NOT NULL,
    max_run_cost numeric NOT NULL CHECK (max_run_cost > 0),
    max_concurrent_attempts bigint NOT NULL CHECK (max_concurrent_attempts > 0),
    actor_id uuid NOT NULL,
    authorized_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,authorization_id),
    UNIQUE (project_id,run_id,authorization_id),
    FOREIGN KEY (project_id,run_id) REFERENCES {schema}.runs,
    CHECK (expires_at > authorized_at)
);
ALTER TABLE {schema}.runs ADD CONSTRAINT current_authorization_same_run
    FOREIGN KEY (project_id,run_id,current_authorization_id)
    REFERENCES {schema}.authorizations (project_id,run_id,authorization_id);
CREATE TABLE {schema}.plans (
    project_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    run_id uuid NOT NULL,
    plan_digest text NOT NULL,
    plan_ref jsonb NOT NULL,
    authorization_id uuid NOT NULL,
    operation_key text NOT NULL,
    PRIMARY KEY (project_id,plan_id),
    UNIQUE (project_id,run_id,plan_id),
    UNIQUE (project_id,run_id,plan_id,operation_key),
    FOREIGN KEY (project_id,run_id,authorization_id)
        REFERENCES {schema}.authorizations (project_id,run_id,authorization_id)
);
CREATE TABLE {schema}.operations (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    asset_id uuid NOT NULL,
    attempts_allocated bigint NOT NULL DEFAULT 0 CHECK (attempts_allocated >= 0),
    held boolean NOT NULL DEFAULT false,
    selected_result_ref jsonb,
    selected_comparison_digest text,
    latest_event_id uuid,
    PRIMARY KEY (project_id,operation_key),
    FOREIGN KEY (project_id,asset_id) REFERENCES {schema}.assets
);
ALTER TABLE {schema}.plans ADD CONSTRAINT plan_operation_same_project
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations;
CREATE TABLE {schema}.reservations (
    project_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    run_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    operation_key text,
    scope text NOT NULL CHECK (scope IN ('attempt','run_storage')),
    reserved_usd numeric NOT NULL CHECK (reserved_usd > 0),
    outstanding_usd numeric NOT NULL CHECK (outstanding_usd >= 0),
    settled_usd numeric NOT NULL CHECK (settled_usd >= 0),
    released_usd numeric NOT NULL DEFAULT 0 CHECK (released_usd >= 0),
    final_billing boolean NOT NULL DEFAULT false,
    evidence_ref jsonb,
    PRIMARY KEY (project_id,reservation_id),
    UNIQUE (project_id,run_id,reservation_id),
    UNIQUE (project_id,run_id,reservation_id,operation_key),
    FOREIGN KEY (project_id,run_id) REFERENCES {schema}.runs,
    FOREIGN KEY (project_id,run_id,authorization_id)
        REFERENCES {schema}.authorizations (project_id,run_id,authorization_id),
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations,
    CHECK ((scope = 'attempt') = (operation_key IS NOT NULL)),
    CHECK (outstanding_usd + released_usd <= reserved_usd)
);
CREATE TABLE {schema}.attempts (
    project_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    run_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    operation_key text NOT NULL,
    attempt_number bigint NOT NULL CHECK (attempt_number > 0),
    reservation_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('planned','reserved','dispatching','running',
        'succeeded','failed','unknown_outcome','cancel_requested','cancelled')),
    attempt_ref jsonb,
    created_at timestamptz NOT NULL,
    dispatched_at timestamptz,
    finished_at timestamptz,
    remote_call_id text,
    provider_scope text,
    result_ref jsonb,
    PRIMARY KEY (project_id,attempt_id),
    UNIQUE (project_id,operation_key,attempt_number),
    UNIQUE (project_id,operation_key,attempt_id),
    UNIQUE (project_id,reservation_id),
    FOREIGN KEY (project_id,run_id,plan_id,operation_key)
        REFERENCES {schema}.plans (project_id,run_id,plan_id,operation_key),
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations,
    FOREIGN KEY (project_id,run_id,reservation_id,operation_key)
        REFERENCES {schema}.reservations (project_id,run_id,reservation_id,operation_key),
    CHECK ((state IN ('succeeded','failed','cancelled')) = (finished_at IS NOT NULL))
);
CREATE TABLE {schema}.dispatch_claims (
    project_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    claimed_at timestamptz NOT NULL,
    claim_id uuid NOT NULL,
    reserved_attempt_ref jsonb NOT NULL,
    dispatched_attempt_ref jsonb NOT NULL,
    PRIMARY KEY (project_id,attempt_id),
    UNIQUE (project_id,claim_id),
    FOREIGN KEY (project_id,attempt_id) REFERENCES {schema}.attempts
);
CREATE TABLE {schema}.budget_events (
    project_id uuid NOT NULL,
    event_id uuid NOT NULL,
    run_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    schema_version text NOT NULL,
    record_digest text NOT NULL,
    record_bytes bytea NOT NULL,
    PRIMARY KEY (project_id,event_id),
    FOREIGN KEY (project_id,run_id,reservation_id)
        REFERENCES {schema}.reservations (project_id,run_id,reservation_id)
);
CREATE TABLE {schema}.billing_adjustments (
    project_id uuid NOT NULL,
    adjustment_id uuid NOT NULL,
    run_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    settlement_event_id uuid NOT NULL,
    record_digest text NOT NULL,
    record_bytes bytea NOT NULL,
    PRIMARY KEY (project_id,adjustment_id),
    FOREIGN KEY (project_id,run_id,reservation_id)
        REFERENCES {schema}.reservations (project_id,run_id,reservation_id),
    FOREIGN KEY (project_id,settlement_event_id) REFERENCES {schema}.budget_events
);
CREATE TABLE {schema}.operation_results (
    project_id uuid NOT NULL,
    event_id uuid NOT NULL,
    operation_key text NOT NULL,
    previous_event_id uuid,
    attempt_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('selected','equivalent','conflict')),
    result_ref jsonb NOT NULL,
    selected_result_ref jsonb NOT NULL,
    comparison_digest text NOT NULL,
    evidence_ref jsonb NOT NULL,
    recorded_at timestamptz NOT NULL,
    record_ref jsonb NOT NULL,
    PRIMARY KEY (project_id,event_id),
    UNIQUE (project_id,operation_key,event_id),
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations,
    FOREIGN KEY (project_id,operation_key,attempt_id)
        REFERENCES {schema}.attempts (project_id,operation_key,attempt_id),
    FOREIGN KEY (project_id,operation_key,previous_event_id)
        REFERENCES {schema}.operation_results (project_id,operation_key,event_id),
    CHECK ((outcome = 'selected') = (previous_event_id IS NULL))
);
CREATE UNIQUE INDEX one_initial_selection ON {schema}.operation_results (project_id,operation_key)
    WHERE outcome = 'selected';
CREATE UNIQUE INDEX one_next_result ON {schema}.operation_results (project_id,previous_event_id)
    WHERE previous_event_id IS NOT NULL;
ALTER TABLE {schema}.operations ADD CONSTRAINT operation_latest_same_chain
    FOREIGN KEY (project_id,operation_key,latest_event_id)
    REFERENCES {schema}.operation_results (project_id,operation_key,event_id);
CREATE TABLE {schema}.integrity_holds (
    project_id uuid NOT NULL,
    hold_id uuid NOT NULL,
    operation_key text NOT NULL,
    evidence_ref jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,hold_id),
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations
);
CREATE TABLE {schema}.attempt_observations (
    project_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    evidence_digest text NOT NULL,
    request_digest text NOT NULL,
    evidence_ref jsonb NOT NULL,
    record_bytes bytea NOT NULL,
    attempt_ref jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,observation_id),
    UNIQUE (project_id,attempt_id,evidence_digest),
    FOREIGN KEY (project_id,attempt_id) REFERENCES {schema}.attempts
);
CREATE TABLE {schema}.control_decisions (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    decision_id uuid NOT NULL,
    run_id uuid,
    operation_key text,
    action text NOT NULL CHECK (action IN ('pause','resume','cancel_attempt','reconcile_budget','manual_retry')),
    evidence_ref jsonb NOT NULL,
    request_digest text NOT NULL,
    record_bytes bytea NOT NULL,
    actor_id uuid NOT NULL,
    decided_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,decision_id),
    FOREIGN KEY (project_id,run_id) REFERENCES {schema}.runs,
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations
);
CREATE TABLE {schema}.reviews (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    review_id uuid NOT NULL,
    revision_digest text NOT NULL,
    revision_ref jsonb NOT NULL,
    operation_key text NOT NULL,
    review_ref jsonb NOT NULL,
    actor_id uuid NOT NULL,
    reviewed_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,review_id),
    FOREIGN KEY (project_id,operation_key) REFERENCES {schema}.operations
);
CREATE TABLE {schema}.releases (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    release_digest text NOT NULL,
    release_ref jsonb NOT NULL,
    selection_digest text NOT NULL,
    local_verified boolean NOT NULL DEFAULT false,
    import_receipt_ref jsonb,
    PRIMARY KEY (project_id,release_digest)
);
CREATE TABLE {schema}.publications (
    project_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    release_digest text NOT NULL,
    publication_ref jsonb NOT NULL,
    actor_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,publication_id),
    FOREIGN KEY (project_id,release_digest) REFERENCES {schema}.releases
);
CREATE TABLE {schema}.active_releases (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    pointer_id text NOT NULL,
    release_digest text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    PRIMARY KEY (project_id,pointer_id),
    FOREIGN KEY (project_id,release_digest) REFERENCES {schema}.releases
);
CREATE TABLE {schema}.pause_state (
    project_id uuid NOT NULL REFERENCES {schema}.projects,
    scope text NOT NULL CHECK (scope IN ('project','run')),
    scope_id uuid NOT NULL,
    run_id uuid,
    paused boolean NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    PRIMARY KEY (project_id,scope,scope_id),
    FOREIGN KEY (project_id,run_id) REFERENCES {schema}.runs,
    CHECK ((scope = 'project' AND scope_id = project_id AND run_id IS NULL)
        OR (scope = 'run' AND scope_id = run_id AND run_id IS NOT NULL))
);
CREATE TABLE {schema}.pause_history (
    project_id uuid NOT NULL,
    decision_id uuid NOT NULL,
    scope text NOT NULL,
    scope_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    paused boolean NOT NULL,
    actor_id uuid NOT NULL,
    reason text NOT NULL,
    decided_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,decision_id),
    UNIQUE (project_id,scope,scope_id,version),
    FOREIGN KEY (project_id,scope,scope_id) REFERENCES {schema}.pause_state
);

CREATE TABLE {schema}.admission_withdrawals (
    project_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    source_id uuid NOT NULL,
    decision_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    reason jsonb NOT NULL,
    evidence_ref jsonb NOT NULL,
    request_digest text NOT NULL,
    record_bytes bytea NOT NULL,
    decided_at timestamptz NOT NULL,
    PRIMARY KEY (project_id,decision_id),
    FOREIGN KEY (project_id,batch_id) REFERENCES {schema}.batches,
    FOREIGN KEY (project_id,asset_id,source_id) REFERENCES {schema}.assets (project_id,asset_id,source_id)
);
