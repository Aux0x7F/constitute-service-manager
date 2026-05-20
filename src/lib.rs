use anyhow::{Result, anyhow};
use constitute_protocol::{
    RECORD_RESOURCE_POSTURE, RECORD_SERVICE_MANAGER_LAB_PROOF,
    RECORD_SERVICE_MANAGER_OPERATION_POSTURE, RECORD_SERVICE_MANAGER_POSTURE,
    RECORD_SERVICE_MANAGER_PROOF_DIGEST, RECORD_SERVICE_MANAGER_RELEASE_CONTRACT,
    RECORD_SERVICE_MANAGER_SECRET_BOUNDARY, RECORD_SERVICE_MANAGER_TRAIN_DIGEST, ResourcePosture,
    SERVICE_MANAGER_OPERATION_HEALTH_CHECK, SERVICE_MANAGER_OPERATION_INSTALL,
    SERVICE_MANAGER_OPERATION_PROMOTE, SERVICE_MANAGER_OPERATION_RELEASE,
    SERVICE_MANAGER_OPERATION_RESTART, SERVICE_MANAGER_OPERATION_ROLLBACK,
    SERVICE_MANAGER_OPERATION_SECRET_READY, SERVICE_MANAGER_OPERATION_START,
    SERVICE_MANAGER_OPERATION_STATE_BLOCKED, SERVICE_MANAGER_OPERATION_STATE_FAILED,
    SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED, SERVICE_MANAGER_OPERATION_STOP,
    SERVICE_MANAGER_OPERATION_UPDATE, SERVICE_MANAGER_POSTURE_BLOCKED,
    SERVICE_MANAGER_POSTURE_READY, SERVICE_MANAGER_PROOF_STATE_BLOCKED,
    SERVICE_MANAGER_PROOF_STATE_FAILED, SERVICE_MANAGER_PROOF_STATE_PROVED,
    SURFACE_APP_CONTRACT_STATE_READY, SURFACE_SECRET_BOUNDARY_RESOLVED,
    ServiceManagerLabProofRecord, ServiceManagerOperationPostureRecord,
    ServiceManagerPostureRecord, ServiceManagerProofDigestRecord,
    ServiceManagerReleaseContractRecord, ServiceManagerSecretBoundaryRecord,
    ServiceManagerTrainDigestRecord, validate_service_manager_lab_proof,
    validate_service_manager_operation_posture, validate_service_manager_posture,
    validate_service_manager_proof_digest, validate_service_manager_release_contract,
    validate_service_manager_secret_boundary, validate_service_manager_train_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const DEFAULT_MANAGER_ID: &str = "manager:lab-service";
pub const DEFAULT_SUBJECT_REF: &str = "service:lab-managed";
pub const DEFAULT_MANAGER_REF: &str = "member:service-manager:lab";
pub const DEFAULT_REQUESTER_REF: &str = "identity:operator";
pub const DEFAULT_RUNNER_REF: &str =
    "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerLifecycleFixture {
    pub manager_id: String,
    pub subject_ref: String,
    pub secret_boundary: ServiceManagerSecretBoundaryRecord,
    pub release_contract: ServiceManagerReleaseContractRecord,
    pub operations: Vec<ServiceManagerOperationPostureRecord>,
    pub proof_digests: Vec<ServiceManagerProofDigestRecord>,
    pub lab_proofs: Vec<ServiceManagerLabProofRecord>,
    pub train_digests: Vec<ServiceManagerTrainDigestRecord>,
    pub posture: ServiceManagerPostureRecord,
}

pub fn build_secret_boundary(issued_at: u64) -> ServiceManagerSecretBoundaryRecord {
    ServiceManagerSecretBoundaryRecord {
        kind: Some(RECORD_SERVICE_MANAGER_SECRET_BOUNDARY.to_string()),
        boundary_id: "secret-boundary:lab-service".to_string(),
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        state: SURFACE_SECRET_BOUNDARY_RESOLVED.to_string(),
        secret_refs: vec!["secret-ref:lab-service:runtime".to_string()],
        access_group_refs: vec!["access-group:ops:service-manager".to_string()],
        authority_refs: vec!["authority:ops-admin".to_string()],
        evidence_refs: vec!["evidence:secret-boundary:resolved".to_string()],
        blocked_reasons: vec![],
        safe_facts: json!({ "boundary": "resolved" }),
        issued_at,
        expires_at: Some(issued_at + 3600),
    }
}

pub fn build_release_contract(issued_at: u64) -> ServiceManagerReleaseContractRecord {
    build_release_contract_with_refs(issued_at, vec![], vec![])
}

pub fn build_release_contract_with_refs(
    issued_at: u64,
    proof_digest_refs: Vec<String>,
    lab_proof_refs: Vec<String>,
) -> ServiceManagerReleaseContractRecord {
    ServiceManagerReleaseContractRecord {
        kind: Some(RECORD_SERVICE_MANAGER_RELEASE_CONTRACT.to_string()),
        contract_id: "release-contract:lab-service:current".to_string(),
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        manager_ref: DEFAULT_MANAGER_REF.to_string(),
        state: SURFACE_APP_CONTRACT_STATE_READY.to_string(),
        app_contract_ref: Some("app-contract:lab-managed@0.1.0".to_string()),
        version: Some("0.1.0".to_string()),
        build_ref: Some("build:lab-service:current".to_string()),
        release_ref: Some("release:lab-service:current".to_string()),
        rollback_ref: Some("rollback:lab-service:previous".to_string()),
        rollback_required: Some(true),
        compatibility_refs: vec!["protocol:service-manager:v1".to_string()],
        authority_refs: vec!["authority:ops-admin".to_string()],
        secret_boundary_refs: vec!["secret-boundary:lab-service".to_string()],
        proof_digest_refs,
        lab_proof_refs,
        evidence_refs: vec!["evidence:release-contract:ready".to_string()],
        blocked_reasons: vec![],
        safe_facts: json!({ "release": "ready" }),
        issued_at,
        expires_at: Some(issued_at + 3600),
    }
}

pub fn build_operation_posture(
    operation: &str,
    state: &str,
    requested_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerOperationPostureRecord> {
    let release_ref = if operation == SERVICE_MANAGER_OPERATION_RELEASE
        || operation == SERVICE_MANAGER_OPERATION_PROMOTE
    {
        Some("release:lab-service:current".to_string())
    } else {
        None
    };
    let rollback_ref = if operation == SERVICE_MANAGER_OPERATION_ROLLBACK
        || operation == SERVICE_MANAGER_OPERATION_PROMOTE
    {
        Some("rollback:lab-service:previous".to_string())
    } else {
        None
    };
    let terminal = matches!(
        state,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
            | SERVICE_MANAGER_OPERATION_STATE_FAILED
            | SERVICE_MANAGER_OPERATION_STATE_BLOCKED
    );

    let record = ServiceManagerOperationPostureRecord {
        kind: Some(RECORD_SERVICE_MANAGER_OPERATION_POSTURE.to_string()),
        operation_id: format!("operation:lab-service:{operation}:{requested_at}"),
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        manager_ref: DEFAULT_MANAGER_REF.to_string(),
        requester_ref: DEFAULT_REQUESTER_REF.to_string(),
        operation: operation.to_string(),
        state: state.to_string(),
        service_refs: vec![DEFAULT_SUBJECT_REF.to_string()],
        capability_refs: vec![constitute_protocol::CAPABILITY_SERVICE_MANAGE.to_string()],
        authority_refs: vec!["authority:ops-admin".to_string()],
        grant_refs: vec!["grant:service-manager:lab-service".to_string()],
        runner_operation_ref: Some(format!(
            "runner-operation:lab-service:{operation}:{requested_at}"
        )),
        runner_ref: Some(DEFAULT_RUNNER_REF.to_string()),
        host_ref: Some("host:lab-service-manager".to_string()),
        release_ref,
        rollback_ref,
        secret_boundary: json!({
            "state": SURFACE_SECRET_BOUNDARY_RESOLVED,
            "accessGroupRefs": ["access-group:ops:service-manager"]
        }),
        release_posture: json!({
            "state": "rollbackReady",
            "buildRef": "build:lab-service:current",
            "releaseRef": "release:lab-service:current",
            "rollbackRef": "rollback:lab-service:previous"
        }),
        rollback_posture: Value::Null,
        resource_budget: json!({
            "profileRef": "resource-profile:service-manager",
            "maxMemoryMiB": 512,
            "maxCpuPct": 25
        }),
        resource_posture: Some(ResourcePosture {
            kind: Some(RECORD_RESOURCE_POSTURE.to_string()),
            posture_id: format!("resource-posture:lab-service:{operation}:{requested_at}"),
            profile_id: "resource-profile:service-manager".to_string(),
            state: "withinBudget".to_string(),
            counts: json!({ "memoryMiB": 96, "cpuPct": 4 }),
            budgets: json!({ "memoryMiB": 512, "cpuPct": 25 }),
            blocked_reasons: vec![],
            sampled_at: requested_at + 30,
        }),
        evidence_refs: vec![format!(
            "evidence:service-manager:{operation}:{requested_at}"
        )],
        proof_refs: vec![format!("proof:service-manager:{operation}")],
        witness_refs: vec![format!("witness:operator:{operation}")],
        retention_refs: vec!["retention:service-manager:90d".to_string()],
        release_witness_refs: vec![],
        blocked_reasons,
        safe_facts: json!({ "operation": operation, "state": state }),
        requested_at,
        accepted_at: Some(requested_at + 10),
        started_at: Some(requested_at + 20),
        completed_at: terminal.then_some(requested_at + 60),
        observed_at: Some(requested_at + 70),
        expires_at: Some(requested_at + 3600),
    };

    validate_service_manager_operation_posture(&record)?;
    Ok(record)
}

pub fn build_proof_digest(
    operation: &ServiceManagerOperationPostureRecord,
    state: &str,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerProofDigestRecord> {
    let proved = state == SERVICE_MANAGER_PROOF_STATE_PROVED;
    let digest = ServiceManagerProofDigestRecord {
        kind: Some(RECORD_SERVICE_MANAGER_PROOF_DIGEST.to_string()),
        digest_id: format!("proof-digest:{}", operation.operation_id),
        operation_id: operation.operation_id.clone(),
        manager_id: operation.manager_id.clone(),
        subject_ref: operation.subject_ref.clone(),
        state: state.to_string(),
        train_ref: Some("train:service-manager:lifecycle".to_string()),
        release_ref: operation.release_ref.clone(),
        rollback_ref: operation.rollback_ref.clone(),
        commit_refs: vec!["git:service-manager:local".to_string()],
        artifact_refs: proved
            .then_some("artifact:service-manager:lifecycle".to_string())
            .into_iter()
            .collect(),
        proof_refs: proved
            .then_some("proof:service-manager:lifecycle".to_string())
            .into_iter()
            .collect(),
        metrics_refs: vec!["metrics:service-manager:lifecycle".to_string()],
        environment_refs: vec!["env:local-dev".to_string()],
        service_refs: operation.service_refs.clone(),
        evidence_refs: operation.evidence_refs.clone(),
        blocked_reasons,
        safe_facts: json!({ "operation": operation.operation, "proof": state }),
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_service_manager_proof_digest(&digest)?;
    Ok(digest)
}

pub fn build_lab_proof(
    proof_id: &str,
    release_contract: &ServiceManagerReleaseContractRecord,
    state: &str,
    started_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerLabProofRecord> {
    build_lab_proof_with_train(
        proof_id,
        "train:service-manager:lifecycle",
        release_contract,
        state,
        started_at,
        blocked_reasons,
    )
}

pub fn build_lab_proof_with_train(
    proof_id: &str,
    train_ref: &str,
    release_contract: &ServiceManagerReleaseContractRecord,
    state: &str,
    started_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerLabProofRecord> {
    let proved = state == SERVICE_MANAGER_PROOF_STATE_PROVED;
    let proof = ServiceManagerLabProofRecord {
        kind: Some(RECORD_SERVICE_MANAGER_LAB_PROOF.to_string()),
        proof_id: proof_id.to_string(),
        manager_id: release_contract.manager_id.clone(),
        subject_ref: release_contract.subject_ref.clone(),
        profile: "surfaceLandscape".to_string(),
        state: state.to_string(),
        train_ref: Some(train_ref.to_string()),
        release_contract_ref: Some(release_contract.contract_id.clone()),
        app_contract_ref: release_contract.app_contract_ref.clone(),
        surface_refs: vec![
            "surface:account".to_string(),
            "surface:operator".to_string(),
        ],
        service_refs: vec![release_contract.subject_ref.clone()],
        environment_refs: vec!["env:local-dev".to_string()],
        artifact_refs: proved
            .then_some("artifact:service-manager:lab-proof".to_string())
            .into_iter()
            .collect(),
        metrics_refs: vec!["metrics:service-manager:lab-proof".to_string()],
        proof_refs: proved
            .then_some("proof:service-manager:lab-proof".to_string())
            .into_iter()
            .collect(),
        evidence_refs: vec!["evidence:service-manager:lab-proof".to_string()],
        blocked_reasons,
        safe_facts: json!({ "profile": "surfaceLandscape", "state": state }),
        started_at,
        accepted_at: Some(started_at + 10),
        completed_at: proved.then_some(started_at + 600),
        observed_at: Some(started_at + 620),
        expires_at: Some(started_at + 3600),
    };
    validate_service_manager_lab_proof(&proof)?;
    Ok(proof)
}

pub fn build_train_digest(
    train_id: &str,
    release_contract: &ServiceManagerReleaseContractRecord,
    operations: &[ServiceManagerOperationPostureRecord],
    proof_digests: &[ServiceManagerProofDigestRecord],
    lab_proofs: &[ServiceManagerLabProofRecord],
    state: &str,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerTrainDigestRecord> {
    let digest = ServiceManagerTrainDigestRecord {
        kind: Some(RECORD_SERVICE_MANAGER_TRAIN_DIGEST.to_string()),
        train_id: train_id.to_string(),
        manager_id: release_contract.manager_id.clone(),
        subject_ref: release_contract.subject_ref.clone(),
        state: state.to_string(),
        repo_refs: vec!["repo:constitute-service-manager".to_string()],
        commit_refs: vec!["git:constitute-service-manager:local".to_string()],
        app_contract_refs: release_contract
            .app_contract_ref
            .clone()
            .into_iter()
            .collect(),
        release_contract_refs: vec![release_contract.contract_id.clone()],
        operation_refs: operations
            .iter()
            .map(|operation| operation.operation_id.clone())
            .collect(),
        proof_digest_refs: proof_digests
            .iter()
            .map(|digest| digest.digest_id.clone())
            .collect(),
        lab_proof_refs: lab_proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect(),
        metrics_refs: vec!["metrics:service-manager:train".to_string()],
        evidence_refs: vec!["evidence:service-manager:train".to_string()],
        blocked_reasons,
        safe_facts: json!({ "train": "service-manager:lifecycle" }),
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_service_manager_train_digest(&digest)?;
    Ok(digest)
}

pub fn reduce_service_manager_posture(
    operations: &[ServiceManagerOperationPostureRecord],
    proof_digests: &[ServiceManagerProofDigestRecord],
    issued_at: u64,
) -> Result<ServiceManagerPostureRecord> {
    if operations.is_empty() {
        return Err(anyhow!("service manager posture requires operations"));
    }
    for operation in operations {
        validate_service_manager_operation_posture(operation)?;
    }
    for proof_digest in proof_digests {
        validate_service_manager_proof_digest(proof_digest)?;
    }
    let mut blocked_reasons = Vec::new();
    for operation in operations {
        if matches!(
            operation.state.as_str(),
            SERVICE_MANAGER_OPERATION_STATE_BLOCKED | SERVICE_MANAGER_OPERATION_STATE_FAILED
        ) {
            blocked_reasons.extend(operation.blocked_reasons.clone());
        }
    }
    for digest in proof_digests {
        if matches!(
            digest.state.as_str(),
            SERVICE_MANAGER_PROOF_STATE_BLOCKED | SERVICE_MANAGER_PROOF_STATE_FAILED
        ) {
            blocked_reasons.extend(digest.blocked_reasons.clone());
        }
    }
    blocked_reasons.sort();
    blocked_reasons.dedup();
    let state = if blocked_reasons.is_empty() {
        SERVICE_MANAGER_POSTURE_READY
    } else {
        SERVICE_MANAGER_POSTURE_BLOCKED
    };
    let posture = ServiceManagerPostureRecord {
        kind: Some(RECORD_SERVICE_MANAGER_POSTURE.to_string()),
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        manager_ref: DEFAULT_MANAGER_REF.to_string(),
        state: state.to_string(),
        service_refs: vec![DEFAULT_SUBJECT_REF.to_string()],
        capability_refs: vec![constitute_protocol::CAPABILITY_SERVICE_MANAGE.to_string()],
        operation_refs: operations
            .iter()
            .map(|operation| operation.operation_id.clone())
            .collect(),
        proof_digest_refs: proof_digests
            .iter()
            .map(|digest| digest.digest_id.clone())
            .collect(),
        secret_boundary: Value::Null,
        release_posture: Value::Null,
        rollback_posture: Value::Null,
        evidence_refs: vec!["evidence:service-manager:posture".to_string()],
        blocked_reasons,
        issued_at,
        expires_at: Some(issued_at + 3600),
    };
    validate_service_manager_posture(&posture)?;
    Ok(posture)
}

pub fn reduce_protected_service_manager_posture(
    secret_boundary: &ServiceManagerSecretBoundaryRecord,
    release_contract: &ServiceManagerReleaseContractRecord,
    operations: &[ServiceManagerOperationPostureRecord],
    proof_digests: &[ServiceManagerProofDigestRecord],
    lab_proofs: &[ServiceManagerLabProofRecord],
    train_digests: &[ServiceManagerTrainDigestRecord],
    issued_at: u64,
) -> Result<ServiceManagerPostureRecord> {
    validate_service_manager_secret_boundary(secret_boundary)?;
    validate_service_manager_release_contract(release_contract)?;
    for lab_proof in lab_proofs {
        validate_service_manager_lab_proof(lab_proof)?;
    }
    for train_digest in train_digests {
        validate_service_manager_train_digest(train_digest)?;
    }

    let mut posture = reduce_service_manager_posture(operations, proof_digests, issued_at)?;
    let mut blocked_reasons = posture.blocked_reasons.clone();

    if secret_boundary.state != SURFACE_SECRET_BOUNDARY_RESOLVED {
        blocked_reasons.push(format!("secretBoundary:{}", secret_boundary.state));
    }
    if secret_boundary
        .expires_at
        .is_some_and(|expires_at| expires_at <= issued_at)
    {
        blocked_reasons.push("secretBoundaryExpired".to_string());
    }
    if release_contract.state != SURFACE_APP_CONTRACT_STATE_READY {
        blocked_reasons.push(format!("releaseContract:{}", release_contract.state));
    }
    if release_contract
        .expires_at
        .is_some_and(|expires_at| expires_at <= issued_at)
    {
        blocked_reasons.push("releaseContractExpired".to_string());
    }
    if release_contract.rollback_required.unwrap_or(true) && release_contract.rollback_ref.is_none()
    {
        blocked_reasons.push("rollbackRequired".to_string());
    }
    if release_contract.proof_digest_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingProofDigestRefs".to_string());
    }
    if release_contract.lab_proof_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingLabProofRefs".to_string());
    }
    for proof_ref in &release_contract.proof_digest_refs {
        if !proof_digests
            .iter()
            .any(|digest| &digest.digest_id == proof_ref)
        {
            blocked_reasons.push(format!("releaseContract:missingProofDigest:{proof_ref}"));
        }
    }
    for lab_proof_ref in &release_contract.lab_proof_refs {
        if !lab_proofs
            .iter()
            .any(|proof| &proof.proof_id == lab_proof_ref)
        {
            blocked_reasons.push(format!("releaseContract:missingLabProof:{lab_proof_ref}"));
        }
    }
    for operation in operations.iter().filter(|operation| {
        matches!(
            operation.state.as_str(),
            SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
                | SERVICE_MANAGER_OPERATION_STATE_FAILED
                | SERVICE_MANAGER_OPERATION_STATE_BLOCKED
        )
    }) {
        if !proof_digests
            .iter()
            .any(|digest| digest.operation_id == operation.operation_id)
        {
            blocked_reasons.push(format!(
                "operationMissingProofDigest:{}",
                operation.operation_id
            ));
        }
    }
    if lab_proofs.is_empty() {
        blocked_reasons.push("missingLabProof".to_string());
    }
    if train_digests.is_empty() {
        blocked_reasons.push("missingTrainDigest".to_string());
    }

    blocked_reasons.sort();
    blocked_reasons.dedup();
    posture.state = if blocked_reasons.is_empty() {
        SERVICE_MANAGER_POSTURE_READY.to_string()
    } else {
        SERVICE_MANAGER_POSTURE_BLOCKED.to_string()
    };
    posture.blocked_reasons = blocked_reasons;
    posture.secret_boundary = json!({
        "state": secret_boundary.state,
        "boundaryId": secret_boundary.boundary_id,
        "secretRefs": secret_boundary.secret_refs,
        "accessGroupRefs": secret_boundary.access_group_refs,
        "authorityRefs": secret_boundary.authority_refs,
        "evidenceRefs": secret_boundary.evidence_refs,
        "expiresAt": secret_boundary.expires_at
    });
    posture.release_posture = json!({
        "state": if release_contract.state == SURFACE_APP_CONTRACT_STATE_READY { "releaseReady" } else { "blocked" },
        "contractId": release_contract.contract_id,
        "appContractRef": release_contract.app_contract_ref,
        "version": release_contract.version,
        "buildRef": release_contract.build_ref,
        "releaseRef": release_contract.release_ref,
        "rollbackRef": release_contract.rollback_ref,
        "rollbackRequired": release_contract.rollback_required.unwrap_or(true),
        "compatibilityRefs": release_contract.compatibility_refs,
        "proofDigestRefs": release_contract.proof_digest_refs,
        "labProofRefs": release_contract.lab_proof_refs,
        "evidenceRefs": release_contract.evidence_refs,
        "blockedReasons": posture.blocked_reasons,
        "expiresAt": release_contract.expires_at
    });
    posture.rollback_posture = json!({
        "state": if release_contract.rollback_ref.is_some() { "rollbackReady" } else { "blocked" },
        "rollbackRef": release_contract.rollback_ref,
        "rollbackRequired": release_contract.rollback_required.unwrap_or(true),
        "blockedReasons": if release_contract.rollback_ref.is_some() { Vec::<String>::new() } else { vec!["rollbackRequired".to_string()] }
    });
    posture.evidence_refs = vec![
        "evidence:service-manager:posture".to_string(),
        secret_boundary.evidence_refs.join("|"),
        release_contract.evidence_refs.join("|"),
    ]
    .into_iter()
    .filter(|value| !value.is_empty())
    .collect();
    validate_service_manager_posture(&posture)?;
    Ok(posture)
}

pub fn service_manager_lifecycle_fixture(issued_at: u64) -> Result<ServiceManagerLifecycleFixture> {
    let operation_kinds = [
        SERVICE_MANAGER_OPERATION_INSTALL,
        SERVICE_MANAGER_OPERATION_UPDATE,
        SERVICE_MANAGER_OPERATION_SECRET_READY,
        SERVICE_MANAGER_OPERATION_START,
        SERVICE_MANAGER_OPERATION_HEALTH_CHECK,
        SERVICE_MANAGER_OPERATION_RESTART,
        SERVICE_MANAGER_OPERATION_STOP,
        SERVICE_MANAGER_OPERATION_RELEASE,
        SERVICE_MANAGER_OPERATION_ROLLBACK,
        SERVICE_MANAGER_OPERATION_PROMOTE,
    ];
    let operations = operation_kinds
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            build_operation_posture(
                operation,
                SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
                issued_at + 100 + (index as u64 * 100),
                vec![],
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let proof_digests = operations
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            build_proof_digest(
                operation,
                SERVICE_MANAGER_PROOF_STATE_PROVED,
                issued_at + 2000 + (index as u64 * 100),
                vec![],
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let proof_digest_refs = proof_digests
        .iter()
        .map(|digest| digest.digest_id.clone())
        .collect::<Vec<_>>();
    let release_contract = build_release_contract_with_refs(
        issued_at,
        proof_digest_refs,
        vec!["lab-proof:service-manager:lifecycle".to_string()],
    );
    let train_id = "train:service-manager:lifecycle";
    let lab_proofs = vec![build_lab_proof_with_train(
        "lab-proof:service-manager:lifecycle",
        train_id,
        &release_contract,
        SERVICE_MANAGER_PROOF_STATE_PROVED,
        issued_at + 3000,
        vec![],
    )?];
    let train_digests = vec![build_train_digest(
        train_id,
        &release_contract,
        &operations,
        &proof_digests,
        &lab_proofs,
        SERVICE_MANAGER_PROOF_STATE_PROVED,
        issued_at + 4000,
        vec![],
    )?];
    let secret_boundary = build_secret_boundary(issued_at);
    let posture = reduce_protected_service_manager_posture(
        &secret_boundary,
        &release_contract,
        &operations,
        &proof_digests,
        &lab_proofs,
        &train_digests,
        issued_at,
    )?;
    let fixture = ServiceManagerLifecycleFixture {
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        secret_boundary,
        release_contract,
        operations,
        proof_digests,
        lab_proofs,
        train_digests,
        posture,
    };
    validate_fixture(&fixture)?;
    Ok(fixture)
}

pub fn blocked_operation_fixture(
    operation: &str,
    reason: &str,
    requested_at: u64,
) -> Result<ServiceManagerLifecycleFixture> {
    let operation = build_operation_posture(
        operation,
        SERVICE_MANAGER_OPERATION_STATE_BLOCKED,
        requested_at,
        vec![reason.to_string()],
    )?;
    let proof_digest = build_proof_digest(
        &operation,
        SERVICE_MANAGER_PROOF_STATE_BLOCKED,
        requested_at + 80,
        vec![reason.to_string()],
    )?;
    let release_contract = build_release_contract_with_refs(
        requested_at,
        vec![proof_digest.digest_id.clone()],
        vec!["lab-proof:service-manager:blocked".to_string()],
    );
    let train_id = "train:service-manager:blocked";
    let lab_proofs = vec![build_lab_proof_with_train(
        "lab-proof:service-manager:blocked",
        train_id,
        &release_contract,
        SERVICE_MANAGER_PROOF_STATE_BLOCKED,
        requested_at + 120,
        vec![reason.to_string()],
    )?];
    let train_digests = vec![build_train_digest(
        train_id,
        &release_contract,
        std::slice::from_ref(&operation),
        std::slice::from_ref(&proof_digest),
        &lab_proofs,
        SERVICE_MANAGER_PROOF_STATE_BLOCKED,
        requested_at + 180,
        vec![reason.to_string()],
    )?];
    let secret_boundary = build_secret_boundary(requested_at);
    let posture = reduce_protected_service_manager_posture(
        &secret_boundary,
        &release_contract,
        std::slice::from_ref(&operation),
        std::slice::from_ref(&proof_digest),
        &lab_proofs,
        &train_digests,
        requested_at,
    )?;
    let fixture = ServiceManagerLifecycleFixture {
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        secret_boundary,
        release_contract,
        operations: vec![operation],
        proof_digests: vec![proof_digest],
        lab_proofs,
        train_digests,
        posture,
    };
    validate_fixture(&fixture)?;
    Ok(fixture)
}

pub fn validate_fixture(fixture: &ServiceManagerLifecycleFixture) -> Result<()> {
    validate_service_manager_secret_boundary(&fixture.secret_boundary)?;
    validate_service_manager_release_contract(&fixture.release_contract)?;
    for operation in &fixture.operations {
        validate_service_manager_operation_posture(operation)?;
    }
    for proof_digest in &fixture.proof_digests {
        validate_service_manager_proof_digest(proof_digest)?;
    }
    for lab_proof in &fixture.lab_proofs {
        validate_service_manager_lab_proof(lab_proof)?;
    }
    for train_digest in &fixture.train_digests {
        validate_service_manager_train_digest(train_digest)?;
    }
    validate_service_manager_posture(&fixture.posture)
}
