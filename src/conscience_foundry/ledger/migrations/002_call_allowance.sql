-- Shared durable call allowance: scope state and idempotent request events only.
-- Applied additively after 001 by ledger.allowance.install_allowance_schema; never alters 001
-- objects. Counters and events bind to existing admitted operations, reservations and attempts.
CREATE TABLE {schema}.call_allowance_scopes (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    limits jsonb NOT NULL,
    requests bigint NOT NULL DEFAULT 0 CHECK (requests >= 0),
    repairs bigint NOT NULL DEFAULT 0 CHECK (repairs >= 0),
    transports bigint NOT NULL DEFAULT 0 CHECK (transports >= 0),
    transitions bigint NOT NULL DEFAULT 0 CHECK (transitions >= 0),
    input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    peak_context bigint NOT NULL DEFAULT 0 CHECK (peak_context >= 0),
    retries_consumed bigint NOT NULL DEFAULT 0 CHECK (retries_consumed >= 0),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    exhausted boolean NOT NULL DEFAULT false,
    PRIMARY KEY (project_id, operation_key),
    FOREIGN KEY (project_id, operation_key) REFERENCES {schema}.operations,
    CHECK (requests <= (limits->>'maxRequests')::bigint),
    CHECK (repairs <= (limits->>'maxRepairs')::bigint),
    CHECK (transports <= (limits->>'maxTransportAttempts')::bigint),
    CHECK (transitions <= (limits->>'maxTransitions')::bigint),
    CHECK (input_tokens <= (limits->>'maxInputTokens')::bigint),
    CHECK (output_tokens <= (limits->>'maxOutputTokens')::bigint),
    CHECK (peak_context <= (limits->>'maxContextScalars')::bigint)
);
CREATE TABLE {schema}.call_allowance_events (
    project_id uuid NOT NULL,
    event_id uuid NOT NULL,
    call_id uuid NOT NULL,
    operation_key text NOT NULL,
    run_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{{64}}$'),
    kind text NOT NULL CHECK (kind IN ('request','repair','transport','transition','outcome')),
    outcome text NOT NULL CHECK (outcome IN ('pending','known','unknown')),
    external_request_id text CHECK (char_length(external_request_id) BETWEEN 1 AND 256),
    reserved_input_tokens bigint NOT NULL CHECK (reserved_input_tokens >= 0),
    reserved_output_tokens bigint NOT NULL CHECK (reserved_output_tokens >= 0),
    context_scalars bigint NOT NULL CHECK (context_scalars >= 0),
    event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{{64}}$'),
    sequence bigint NOT NULL CHECK (sequence > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (project_id, event_id),
    UNIQUE (project_id, operation_key, sequence),
    FOREIGN KEY (project_id, operation_key) REFERENCES {schema}.call_allowance_scopes,
    FOREIGN KEY (project_id, run_id, reservation_id)
        REFERENCES {schema}.reservations (project_id, run_id, reservation_id),
    FOREIGN KEY (project_id, attempt_id) REFERENCES {schema}.attempts,
    CHECK ((kind IN ('request','repair','transport') AND outcome = 'pending')
        OR (kind = 'transition' AND outcome = 'known')
        OR (kind = 'outcome' AND outcome IN ('known','unknown')))
);
-- Every potentially billable submission (and transition) has a fresh local call identity;
-- only outcome events may reuse it.
CREATE UNIQUE INDEX one_submission_per_call ON {schema}.call_allowance_events (project_id, call_id)
    WHERE kind <> 'outcome';
