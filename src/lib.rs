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
use serde_json::json;
use std::fs;
use std::path::Path;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServiceSpec {
    pub service_id: String,
    pub manager_id: String,
    pub subject_ref: String,
    pub manager_ref: String,
    pub requester_ref: String,
    pub runner_ref: Option<String>,
    pub host_ref: Option<String>,
    pub app_contract_ref: Option<String>,
    pub version: Option<String>,
    pub build_ref: Option<String>,
    pub release_ref: Option<String>,
    pub rollback_ref: Option<String>,
    pub rollback_required: bool,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub secret_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    pub resource_profile_ref: String,
    pub resource_memory_mib: u64,
    pub resource_cpu_pct: u64,
    #[serde(default)]
    pub retention_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerState {
    #[serde(default)]
    pub services: Vec<ManagedServiceSpec>,
    #[serde(default)]
    pub operations: Vec<ServiceManagerOperationPostureRecord>,
    #[serde(default)]
    pub proof_digests: Vec<ServiceManagerProofDigestRecord>,
    pub posture: Option<ServiceManagerPostureRecord>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceOperationRequest {
    pub service_id: String,
    pub operation: String,
    pub requested_at: u64,
    pub dry_run: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceOperationOutcome {
    pub service_id: String,
    pub operation: String,
    pub dry_run: bool,
    pub state: String,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub operation_posture: ServiceManagerOperationPostureRecord,
    pub proof_digest: ServiceManagerProofDigestRecord,
    pub posture: ServiceManagerPostureRecord,
}

pub fn default_managed_service_spec() -> ManagedServiceSpec {
    ManagedServiceSpec {
        service_id: "lab-service".to_string(),
        manager_id: DEFAULT_MANAGER_ID.to_string(),
        subject_ref: DEFAULT_SUBJECT_REF.to_string(),
        manager_ref: DEFAULT_MANAGER_REF.to_string(),
        requester_ref: DEFAULT_REQUESTER_REF.to_string(),
        runner_ref: Some(DEFAULT_RUNNER_REF.to_string()),
        host_ref: Some("host:lab-service-manager".to_string()),
        app_contract_ref: Some("app-contract:lab-managed@0.1.0".to_string()),
        version: Some("0.1.0".to_string()),
        build_ref: Some("build:lab-service:current".to_string()),
        release_ref: Some("release:lab-service:current".to_string()),
        rollback_ref: Some("rollback:lab-service:previous".to_string()),
        rollback_required: true,
        compatibility_refs: vec!["protocol:service-manager:v1".to_string()],
        secret_refs: vec!["secret-ref:lab-service:runtime".to_string()],
        access_group_refs: vec!["access-group:ops:service-manager".to_string()],
        authority_refs: vec!["authority:ops-admin".to_string()],
        grant_refs: vec!["grant:service-manager:lab-service".to_string()],
        resource_profile_ref: "resource-profile:service-manager".to_string(),
        resource_memory_mib: 512,
        resource_cpu_pct: 25,
        retention_refs: vec!["retention:service-manager:90d".to_string()],
    }
}

pub fn default_manager_state(issued_at: u64) -> ServiceManagerState {
    ServiceManagerState {
        services: vec![default_managed_service_spec()],
        operations: vec![],
        proof_digests: vec![],
        posture: None,
        updated_at: issued_at,
    }
}

pub fn build_secret_boundary_for_spec(
    spec: &ManagedServiceSpec,
    issued_at: u64,
) -> ServiceManagerSecretBoundaryRecord {
    let state = if spec.secret_refs.is_empty() {
        constitute_protocol::SURFACE_SECRET_BOUNDARY_UNAVAILABLE
    } else {
        SURFACE_SECRET_BOUNDARY_RESOLVED
    };
    let blocked_reasons = if spec.secret_refs.is_empty() {
        vec!["secretBoundary:missingSecretRefs".to_string()]
    } else {
        vec![]
    };
    ServiceManagerSecretBoundaryRecord {
        kind: Some(RECORD_SERVICE_MANAGER_SECRET_BOUNDARY.to_string()),
        boundary_id: format!("secret-boundary:{}", spec.service_id),
        manager_id: spec.manager_id.clone(),
        subject_ref: spec.subject_ref.clone(),
        state: state.to_string(),
        secret_refs: spec.secret_refs.clone(),
        access_group_refs: spec.access_group_refs.clone(),
        authority_refs: spec.authority_refs.clone(),
        evidence_refs: vec![format!("evidence:secret-boundary:{}", spec.service_id)],
        blocked_reasons,
        safe_facts: json!({ "boundary": state }),
        issued_at,
        expires_at: Some(issued_at + 3600),
    }
}

pub fn build_secret_boundary(issued_at: u64) -> ServiceManagerSecretBoundaryRecord {
    build_secret_boundary_for_spec(&default_managed_service_spec(), issued_at)
}

pub fn build_release_contract(issued_at: u64) -> ServiceManagerReleaseContractRecord {
    build_release_contract_with_refs(issued_at, vec![], vec![])
}

pub fn build_release_contract_for_spec(
    spec: &ManagedServiceSpec,
    issued_at: u64,
    proof_digest_refs: Vec<String>,
    lab_proof_refs: Vec<String>,
) -> ServiceManagerReleaseContractRecord {
    let mut blocked_reasons = Vec::new();
    if spec.release_ref.is_none() {
        blocked_reasons.push("releaseContract:missingReleaseRef".to_string());
    }
    if spec.rollback_required && spec.rollback_ref.is_none() {
        blocked_reasons.push("rollbackRequired".to_string());
    }
    if spec.secret_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingSecretBoundary".to_string());
    }
    let state = if blocked_reasons.is_empty() {
        SURFACE_APP_CONTRACT_STATE_READY
    } else {
        "blocked"
    };
    ServiceManagerReleaseContractRecord {
        kind: Some(RECORD_SERVICE_MANAGER_RELEASE_CONTRACT.to_string()),
        contract_id: format!("release-contract:{}:current", spec.service_id),
        manager_id: spec.manager_id.clone(),
        subject_ref: spec.subject_ref.clone(),
        manager_ref: spec.manager_ref.clone(),
        state: state.to_string(),
        app_contract_ref: spec.app_contract_ref.clone(),
        version: spec.version.clone(),
        build_ref: spec.build_ref.clone(),
        release_ref: spec.release_ref.clone(),
        rollback_ref: spec.rollback_ref.clone(),
        rollback_required: Some(spec.rollback_required),
        compatibility_refs: spec.compatibility_refs.clone(),
        authority_refs: spec.authority_refs.clone(),
        secret_boundary_refs: vec![format!("secret-boundary:{}", spec.service_id)],
        proof_digest_refs,
        lab_proof_refs,
        evidence_refs: vec![format!("evidence:release-contract:{}", spec.service_id)],
        blocked_reasons,
        safe_facts: json!({
            "release": state,
            "serviceId": spec.service_id,
            "version": spec.version
        }),
        issued_at,
        expires_at: Some(issued_at + 3600),
    }
}

pub fn build_release_contract_with_refs(
    issued_at: u64,
    proof_digest_refs: Vec<String>,
    lab_proof_refs: Vec<String>,
) -> ServiceManagerReleaseContractRecord {
    build_release_contract_for_spec(
        &default_managed_service_spec(),
        issued_at,
        proof_digest_refs,
        lab_proof_refs,
    )
}

pub fn build_operation_posture(
    operation: &str,
    state: &str,
    requested_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerOperationPostureRecord> {
    build_operation_posture_for_spec(
        &default_managed_service_spec(),
        operation,
        state,
        requested_at,
        blocked_reasons,
    )
}

pub fn build_operation_posture_for_spec(
    spec: &ManagedServiceSpec,
    operation: &str,
    state: &str,
    requested_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceManagerOperationPostureRecord> {
    let release_ref = if operation == SERVICE_MANAGER_OPERATION_RELEASE
        || operation == SERVICE_MANAGER_OPERATION_PROMOTE
    {
        spec.release_ref.clone()
    } else {
        None
    };
    let rollback_ref = if operation == SERVICE_MANAGER_OPERATION_ROLLBACK
        || operation == SERVICE_MANAGER_OPERATION_PROMOTE
    {
        spec.rollback_ref.clone()
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
        operation_id: format!("operation:{}:{operation}:{requested_at}", spec.service_id),
        manager_id: spec.manager_id.clone(),
        subject_ref: spec.subject_ref.clone(),
        manager_ref: spec.manager_ref.clone(),
        requester_ref: spec.requester_ref.clone(),
        operation: operation.to_string(),
        state: state.to_string(),
        service_refs: vec![spec.subject_ref.clone()],
        capability_refs: vec![constitute_protocol::CAPABILITY_SERVICE_MANAGE.to_string()],
        authority_refs: spec.authority_refs.clone(),
        grant_refs: spec.grant_refs.clone(),
        runner_operation_ref: Some(format!(
            "runner-operation:{}:{operation}:{requested_at}",
            spec.service_id
        )),
        runner_ref: spec.runner_ref.clone(),
        host_ref: spec.host_ref.clone(),
        release_ref,
        rollback_ref,
        secret_boundary: json!({
            "state": if spec.secret_refs.is_empty() {
                constitute_protocol::SURFACE_SECRET_BOUNDARY_UNAVAILABLE
            } else {
                SURFACE_SECRET_BOUNDARY_RESOLVED
            },
            "accessGroupRefs": spec.access_group_refs,
            "authorityRefs": spec.authority_refs
        }),
        release_posture: json!({
            "state": if spec.release_ref.is_some() { "releaseReady" } else { "blocked" },
            "buildRef": spec.build_ref,
            "releaseRef": spec.release_ref,
            "rollbackRef": spec.rollback_ref,
            "blockedReasons": if spec.release_ref.is_some() { Vec::<String>::new() } else { vec!["releaseContract:missingReleaseRef".to_string()] }
        }),
        rollback_posture: json!({
            "state": if !spec.rollback_required || spec.rollback_ref.is_some() { "rollbackReady" } else { "blocked" },
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": if !spec.rollback_required || spec.rollback_ref.is_some() { Vec::<String>::new() } else { vec!["rollbackRequired".to_string()] }
        }),
        resource_budget: json!({
            "profileRef": spec.resource_profile_ref,
            "maxMemoryMiB": spec.resource_memory_mib,
            "maxCpuPct": spec.resource_cpu_pct
        }),
        resource_posture: Some(ResourcePosture {
            kind: Some(RECORD_RESOURCE_POSTURE.to_string()),
            posture_id: format!(
                "resource-posture:{}:{operation}:{requested_at}",
                spec.service_id
            ),
            profile_id: spec.resource_profile_ref.clone(),
            state: "withinBudget".to_string(),
            counts: json!({ "memoryMiB": 96, "cpuPct": 4 }),
            budgets: json!({ "memoryMiB": spec.resource_memory_mib, "cpuPct": spec.resource_cpu_pct }),
            blocked_reasons: vec![],
            sampled_at: requested_at + 30,
        }),
        evidence_refs: vec![format!(
            "evidence:service-manager:{}:{operation}:{requested_at}",
            spec.service_id
        )],
        proof_refs: vec![format!("proof:service-manager:{operation}")],
        witness_refs: vec![format!("witness:operator:{operation}")],
        retention_refs: spec.retention_refs.clone(),
        release_witness_refs: vec![],
        blocked_reasons,
        safe_facts: json!({ "operation": operation, "state": state, "dryRun": true }),
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
    reduce_service_manager_posture_for_spec(
        &default_managed_service_spec(),
        operations,
        proof_digests,
        issued_at,
    )
}

pub fn reduce_service_manager_posture_for_spec(
    spec: &ManagedServiceSpec,
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
        manager_id: spec.manager_id.clone(),
        subject_ref: spec.subject_ref.clone(),
        manager_ref: spec.manager_ref.clone(),
        state: state.to_string(),
        service_refs: vec![spec.subject_ref.clone()],
        capability_refs: vec![constitute_protocol::CAPABILITY_SERVICE_MANAGE.to_string()],
        operation_refs: operations
            .iter()
            .map(|operation| operation.operation_id.clone())
            .collect(),
        proof_digest_refs: proof_digests
            .iter()
            .map(|digest| digest.digest_id.clone())
            .collect(),
        secret_boundary: json!({
            "state": if spec.secret_refs.is_empty() {
                constitute_protocol::SURFACE_SECRET_BOUNDARY_UNAVAILABLE
            } else {
                SURFACE_SECRET_BOUNDARY_RESOLVED
            },
            "secretRefs": spec.secret_refs,
            "accessGroupRefs": spec.access_group_refs,
            "authorityRefs": spec.authority_refs
        }),
        release_posture: json!({
            "state": if spec.release_ref.is_some() { "releaseReady" } else { "blocked" },
            "appContractRef": spec.app_contract_ref,
            "version": spec.version,
            "buildRef": spec.build_ref,
            "releaseRef": spec.release_ref,
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": if spec.release_ref.is_some() { Vec::<String>::new() } else { vec!["releaseContract:missingReleaseRef".to_string()] }
        }),
        rollback_posture: json!({
            "state": if !spec.rollback_required || spec.rollback_ref.is_some() { "rollbackReady" } else { "blocked" },
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": if !spec.rollback_required || spec.rollback_ref.is_some() { Vec::<String>::new() } else { vec!["rollbackRequired".to_string()] }
        }),
        evidence_refs: vec![format!(
            "evidence:service-manager:{}:posture",
            spec.service_id
        )],
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

pub fn load_manager_state(path: impl AsRef<Path>, issued_at: u64) -> Result<ServiceManagerState> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(default_manager_state(issued_at));
    }
    let bytes = fs::read(path)?;
    let mut state: ServiceManagerState = serde_json::from_slice(&bytes)?;
    if state.services.is_empty() {
        state.services.push(default_managed_service_spec());
    }
    Ok(state)
}

pub fn save_manager_state(path: impl AsRef<Path>, state: &ServiceManagerState) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

pub fn service_manager_status(
    state: &ServiceManagerState,
    service_id: &str,
    issued_at: u64,
) -> Result<ServiceManagerPostureRecord> {
    let spec = state
        .services
        .iter()
        .find(|service| service.service_id == service_id)
        .ok_or_else(|| anyhow!("managed service not found: {service_id}"))?;
    let operations = state
        .operations
        .iter()
        .filter(|operation| operation.subject_ref == spec.subject_ref)
        .cloned()
        .collect::<Vec<_>>();
    let proof_digests = state
        .proof_digests
        .iter()
        .filter(|digest| digest.subject_ref == spec.subject_ref)
        .cloned()
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return initial_service_manager_posture(spec, issued_at);
    }
    reduce_service_manager_posture_for_spec(spec, &operations, &proof_digests, issued_at)
}

pub fn apply_service_operation(
    state: &mut ServiceManagerState,
    request: ServiceOperationRequest,
) -> Result<ServiceOperationOutcome> {
    let spec = state
        .services
        .iter()
        .find(|service| service.service_id == request.service_id)
        .ok_or_else(|| anyhow!("managed service not found: {}", request.service_id))?
        .clone();
    validate_supported_operation(&request.operation)?;
    let mut blocked_reasons = operation_blocked_reasons(&spec, &request);
    blocked_reasons.sort();
    blocked_reasons.dedup();

    let operation_state = if blocked_reasons.is_empty() {
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
    } else {
        SERVICE_MANAGER_OPERATION_STATE_BLOCKED
    };
    let operation_posture = build_operation_posture_for_spec(
        &spec,
        &request.operation,
        operation_state,
        request.requested_at,
        blocked_reasons.clone(),
    )?;
    let proof_state = if blocked_reasons.is_empty() {
        SERVICE_MANAGER_PROOF_STATE_PROVED
    } else {
        SERVICE_MANAGER_PROOF_STATE_BLOCKED
    };
    let proof_digest = build_proof_digest(
        &operation_posture,
        proof_state,
        request.requested_at + 80,
        blocked_reasons.clone(),
    )?;
    state.operations.push(operation_posture.clone());
    state.proof_digests.push(proof_digest.clone());
    state.updated_at = request.requested_at + 80;
    let posture = service_manager_status(state, &spec.service_id, state.updated_at)?;
    state.posture = Some(posture.clone());

    Ok(ServiceOperationOutcome {
        service_id: spec.service_id,
        operation: request.operation,
        dry_run: request.dry_run,
        state: operation_state.to_string(),
        blocked_reasons,
        operation_posture,
        proof_digest,
        posture,
    })
}

fn validate_supported_operation(operation: &str) -> Result<()> {
    if matches!(
        operation,
        SERVICE_MANAGER_OPERATION_INSTALL
            | SERVICE_MANAGER_OPERATION_UPDATE
            | SERVICE_MANAGER_OPERATION_SECRET_READY
            | SERVICE_MANAGER_OPERATION_START
            | SERVICE_MANAGER_OPERATION_HEALTH_CHECK
            | SERVICE_MANAGER_OPERATION_RESTART
            | SERVICE_MANAGER_OPERATION_STOP
            | SERVICE_MANAGER_OPERATION_RELEASE
            | SERVICE_MANAGER_OPERATION_ROLLBACK
            | SERVICE_MANAGER_OPERATION_PROMOTE
    ) {
        return Ok(());
    }
    Err(anyhow!(
        "unsupported service-manager operation: {operation}"
    ))
}

fn operation_blocked_reasons(
    spec: &ManagedServiceSpec,
    request: &ServiceOperationRequest,
) -> Vec<String> {
    let mut blocked_reasons = request
        .blocked_reason
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    if !request.dry_run {
        blocked_reasons.push("hostAdapter:notConfigured".to_string());
    }
    if spec.runner_ref.as_deref().unwrap_or_default().is_empty() {
        blocked_reasons.push("runnerRef:missing".to_string());
    }
    if spec.host_ref.as_deref().unwrap_or_default().is_empty() {
        blocked_reasons.push("hostRef:missing".to_string());
    }
    if spec.authority_refs.is_empty() {
        blocked_reasons.push("authorityRefs:missing".to_string());
    }
    if spec.grant_refs.is_empty() {
        blocked_reasons.push("grantRefs:missing".to_string());
    }
    if secret_required_for(&request.operation) && spec.secret_refs.is_empty() {
        blocked_reasons.push("secretBoundary:missingSecretRefs".to_string());
    }
    if release_required_for(&request.operation) && spec.release_ref.is_none() {
        blocked_reasons.push("releaseContract:missingReleaseRef".to_string());
    }
    if rollback_required_for(&request.operation)
        && spec.rollback_required
        && spec.rollback_ref.is_none()
    {
        blocked_reasons.push("rollbackRequired".to_string());
    }
    if spec.resource_memory_mib == 0 || spec.resource_cpu_pct == 0 {
        blocked_reasons.push("resourceBudget:missing".to_string());
    }
    blocked_reasons
}

fn secret_required_for(operation: &str) -> bool {
    matches!(
        operation,
        SERVICE_MANAGER_OPERATION_SECRET_READY
            | SERVICE_MANAGER_OPERATION_START
            | SERVICE_MANAGER_OPERATION_RESTART
            | SERVICE_MANAGER_OPERATION_UPDATE
            | SERVICE_MANAGER_OPERATION_HEALTH_CHECK
            | SERVICE_MANAGER_OPERATION_RELEASE
            | SERVICE_MANAGER_OPERATION_PROMOTE
    )
}

fn release_required_for(operation: &str) -> bool {
    matches!(
        operation,
        SERVICE_MANAGER_OPERATION_START
            | SERVICE_MANAGER_OPERATION_RESTART
            | SERVICE_MANAGER_OPERATION_UPDATE
            | SERVICE_MANAGER_OPERATION_RELEASE
            | SERVICE_MANAGER_OPERATION_PROMOTE
    )
}

fn rollback_required_for(operation: &str) -> bool {
    matches!(
        operation,
        SERVICE_MANAGER_OPERATION_ROLLBACK | SERVICE_MANAGER_OPERATION_PROMOTE
    )
}

fn initial_service_manager_posture(
    spec: &ManagedServiceSpec,
    issued_at: u64,
) -> Result<ServiceManagerPostureRecord> {
    let mut blocked_reasons = Vec::new();
    if spec.secret_refs.is_empty() {
        blocked_reasons.push("secretBoundary:missingSecretRefs".to_string());
    }
    if spec.release_ref.is_none() {
        blocked_reasons.push("releaseContract:missingReleaseRef".to_string());
    }
    if spec.rollback_required && spec.rollback_ref.is_none() {
        blocked_reasons.push("rollbackRequired".to_string());
    }
    let posture = ServiceManagerPostureRecord {
        kind: Some(RECORD_SERVICE_MANAGER_POSTURE.to_string()),
        manager_id: spec.manager_id.clone(),
        subject_ref: spec.subject_ref.clone(),
        manager_ref: spec.manager_ref.clone(),
        state: if blocked_reasons.is_empty() {
            SERVICE_MANAGER_POSTURE_READY.to_string()
        } else {
            SERVICE_MANAGER_POSTURE_BLOCKED.to_string()
        },
        service_refs: vec![spec.subject_ref.clone()],
        capability_refs: vec![constitute_protocol::CAPABILITY_SERVICE_MANAGE.to_string()],
        operation_refs: vec![],
        proof_digest_refs: vec![],
        secret_boundary: json!({
            "state": if spec.secret_refs.is_empty() {
                constitute_protocol::SURFACE_SECRET_BOUNDARY_UNAVAILABLE
            } else {
                SURFACE_SECRET_BOUNDARY_RESOLVED
            },
            "secretRefs": spec.secret_refs,
            "accessGroupRefs": spec.access_group_refs,
            "authorityRefs": spec.authority_refs
        }),
        release_posture: json!({
            "state": if spec.release_ref.is_some() { "releaseReady" } else { "blocked" },
            "appContractRef": spec.app_contract_ref,
            "version": spec.version,
            "buildRef": spec.build_ref,
            "releaseRef": spec.release_ref,
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": if spec.release_ref.is_some() { Vec::<String>::new() } else { vec!["releaseContract:missingReleaseRef".to_string()] }
        }),
        rollback_posture: json!({
            "state": if !spec.rollback_required || spec.rollback_ref.is_some() { "rollbackReady" } else { "blocked" },
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": if !spec.rollback_required || spec.rollback_ref.is_some() { Vec::<String>::new() } else { vec!["rollbackRequired".to_string()] }
        }),
        evidence_refs: vec![format!(
            "evidence:service-manager:{}:posture",
            spec.service_id
        )],
        blocked_reasons,
        issued_at,
        expires_at: Some(issued_at + 3600),
    };
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
