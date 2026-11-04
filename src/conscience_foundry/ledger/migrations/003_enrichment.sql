-- Explicit additive enrichment sidecars; canonical ledger tables remain unchanged.
CREATE TABLE {schema}.enrichment_operations (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    operation_ref jsonb NOT NULL,
    operation_digest text NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{{64}}$'),
    PRIMARY KEY (project_id, operation_key),
    UNIQUE (project_id, operation_digest),
    FOREIGN KEY (project_id, operation_key) REFERENCES {schema}.operations,
    CHECK ((operation_ref->>'digest' = operation_digest) IS TRUE),
    CHECK ((operation_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((operation_ref->>'artifactSchema' = 'cf.enrichment-operation.v1') IS TRUE)
);
CREATE TABLE {schema}.enrichment_requests (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    attempt_id uuid NOT NULL,
    request_ref jsonb NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{{64}}$'),
    PRIMARY KEY (project_id, attempt_id),
    UNIQUE (project_id, operation_key, attempt_id),
    UNIQUE (project_id, request_digest),
    FOREIGN KEY (project_id, operation_key) REFERENCES {schema}.enrichment_operations,
    FOREIGN KEY (project_id, operation_key, attempt_id) REFERENCES {schema}.attempts (project_id,operation_key,attempt_id),
    CHECK ((request_ref->>'digest' = request_digest) IS TRUE),
    CHECK ((request_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((request_ref->>'artifactSchema' = 'cf.enrichment-request.v1') IS TRUE)
);
CREATE TABLE {schema}.enrichment_results (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    attempt_id uuid NOT NULL,
    result_digest text NOT NULL CHECK (result_digest ~ '^[0-9a-f]{{64}}$'),
    result_ref jsonb NOT NULL,
    review_ref jsonb,
    PRIMARY KEY (project_id, operation_key, attempt_id, result_digest),
    UNIQUE (project_id, result_digest),
    FOREIGN KEY (project_id, operation_key, attempt_id) REFERENCES {schema}.enrichment_requests (project_id,operation_key,attempt_id),
    CHECK ((result_ref->>'digest' = result_digest) IS TRUE),
    CHECK ((result_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((result_ref->>'artifactSchema' = 'cf.enrichment-result.v1') IS TRUE),
    CHECK ((review_ref IS NULL OR review_ref->>'projectId' = project_id::text) IS TRUE)
);
CREATE TABLE {schema}.enrichment_selections (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    event_id uuid NOT NULL,
    previous_event_id uuid,
    result_attempt_id uuid,
    result_digest text,
    result_ref jsonb,
    evidence_ref jsonb NOT NULL,
    record_ref jsonb NOT NULL,
    PRIMARY KEY (project_id, operation_key, event_id),
    UNIQUE (project_id, operation_key, previous_event_id),
    FOREIGN KEY (project_id, operation_key) REFERENCES {schema}.enrichment_operations,
    FOREIGN KEY (project_id, operation_key, previous_event_id) REFERENCES {schema}.enrichment_selections,
    FOREIGN KEY (project_id, operation_key, result_attempt_id, result_digest)
        REFERENCES {schema}.enrichment_results (project_id,operation_key,attempt_id,result_digest),
    CHECK ((result_ref IS NULL) = (result_digest IS NULL)),
    CHECK ((result_ref IS NULL) = (result_attempt_id IS NULL)),
    CHECK ((result_ref IS NULL OR (result_ref->>'digest' = result_digest AND result_ref->>'projectId' = project_id::text)) IS TRUE),
    CHECK ((evidence_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((record_ref->>'projectId' = project_id::text) IS TRUE)
);
-- Compare the whole reference without indexing arbitrary-length JSON metadata.
CREATE FUNCTION {schema}.enrichment_selection_ref_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.result_ref IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM {schema}.enrichment_results r
        WHERE r.project_id = NEW.project_id AND r.operation_key = NEW.operation_key
          AND r.attempt_id = NEW.result_attempt_id AND r.result_digest = NEW.result_digest
          AND r.result_ref = NEW.result_ref
    ) THEN
        RAISE EXCEPTION 'selection result reference mismatch' USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER enrichment_selection_ref_check BEFORE INSERT OR UPDATE ON {schema}.enrichment_selections
    FOR EACH ROW EXECUTE FUNCTION {schema}.enrichment_selection_ref_check();
CREATE UNIQUE INDEX enrichment_one_selection_root
    ON {schema}.enrichment_selections (project_id, operation_key) WHERE previous_event_id IS NULL;
CREATE TABLE {schema}.enrichment_current_selection (
    project_id uuid NOT NULL,
    operation_key text NOT NULL,
    event_id uuid NOT NULL,
    PRIMARY KEY (project_id, operation_key),
    FOREIGN KEY (project_id, operation_key, event_id) REFERENCES {schema}.enrichment_selections
);
CREATE TABLE {schema}.enrichment_task_schemas (
    project_id uuid NOT NULL,
    spec_digest text NOT NULL CHECK (spec_digest ~ '^[0-9a-f]{{64}}$'),
    spec_ref jsonb NOT NULL,
    installation_ref jsonb NOT NULL,
    input_schema_ref jsonb NOT NULL,
    output_schema_ref jsonb NOT NULL,
    PRIMARY KEY (project_id, spec_digest),
    FOREIGN KEY (project_id) REFERENCES {schema}.projects,
    CHECK ((spec_ref->>'digest' = spec_digest) IS TRUE),
    CHECK ((spec_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((installation_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((input_schema_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((output_schema_ref->>'projectId' = project_id::text) IS TRUE),
    CHECK ((installation_ref->>'artifactSchema' = 'cf.enrichment-schema-installation.v1') IS TRUE),
    CHECK ((input_schema_ref->>'artifactSchema' = 'json-schema.2020-12') IS TRUE),
    CHECK ((output_schema_ref->>'artifactSchema' = 'json-schema.2020-12') IS TRUE)
);

-- History and installation facts are immutable; only the current pointer is mutable.
CREATE FUNCTION {schema}.enrichment_history_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'enrichment history is immutable' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER enrichment_operation_immutable BEFORE UPDATE OR DELETE ON {schema}.enrichment_operations
    FOR EACH ROW EXECUTE FUNCTION {schema}.enrichment_history_immutable();
CREATE TRIGGER enrichment_request_immutable BEFORE UPDATE OR DELETE ON {schema}.enrichment_requests
    FOR EACH ROW EXECUTE FUNCTION {schema}.enrichment_history_immutable();
CREATE TRIGGER enrichment_result_immutable BEFORE UPDATE OR DELETE ON {schema}.enrichment_results
    FOR EACH ROW EXECUTE FUNCTION {schema}.enrichment_history_immutable();
CREATE TRIGGER enrichment_selection_immutable BEFORE UPDATE OR DELETE ON {schema}.enrichment_selections
    FOR EACH ROW EXECUTE FUNCTION {schema}.enrichment_history_immutable();
CREATE TRIGGER enrichment_schema_immutable BEFORE UPDATE OR DELETE ON {schema}.enrichment_task_schemas
    FOR EACH ROW EXECUTE FUNCTION {schema}.enrichment_history_immutable();
