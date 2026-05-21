use constitute_protocol::{
    SERVICE_MANAGER_OPERATION_RELEASE, SERVICE_MANAGER_OPERATION_RESTART,
    SERVICE_MANAGER_OPERATION_ROLLBACK, SERVICE_MANAGER_OPERATION_STATE_BLOCKED,
    SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED, SERVICE_MANAGER_POSTURE_BLOCKED,
    SERVICE_MANAGER_POSTURE_READY, SURFACE_SECRET_BOUNDARY_BLOCKED,
    validate_service_manager_operation_posture,
};
use constitute_service_manager::{
    blocked_operation_fixture, build_lab_proof_with_train, build_operation_posture,
    build_release_contract, build_release_contract_with_refs, build_secret_boundary,
    build_train_digest, reduce_protected_service_manager_posture,
    service_manager_lifecycle_fixture, validate_fixture,
};

#[test]
fn lifecycle_fixture_covers_manager_operations() {
    let fixture = service_manager_lifecycle_fixture(1_700_000_000).expect("fixture");
    assert_eq!(fixture.operations.len(), 10);
    assert_eq!(fixture.proof_digests.len(), 10);
    assert_eq!(fixture.lab_proofs.len(), 1);
    assert_eq!(fixture.train_digests.len(), 1);
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_READY);
    assert_eq!(
        fixture.posture.secret_boundary["state"],
        constitute_protocol::SURFACE_SECRET_BOUNDARY_RESOLVED
    );
    assert_eq!(fixture.posture.release_posture["state"], "releaseReady");
    assert_eq!(fixture.posture.rollback_posture["state"], "rollbackReady");
    validate_fixture(&fixture).expect("fixture validates");

    let release = fixture
        .operations
        .iter()
        .find(|operation| operation.operation == SERVICE_MANAGER_OPERATION_RELEASE)
        .expect("release operation");
    assert!(release.release_ref.is_some());

    let rollback = fixture
        .operations
        .iter()
        .find(|operation| operation.operation == SERVICE_MANAGER_OPERATION_ROLLBACK)
        .expect("rollback operation");
    assert!(rollback.rollback_ref.is_some());
}

#[test]
fn protected_posture_blocks_missing_lifecycle_proof() {
    let issued_at = 1_700_000_000;
    let operation = build_operation_posture(
        SERVICE_MANAGER_OPERATION_RESTART,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        issued_at + 100,
        vec![],
    )
    .expect("operation");
    let secret_boundary = build_secret_boundary(issued_at);
    let release_contract = build_release_contract(issued_at);

    let posture = reduce_protected_service_manager_posture(
        &secret_boundary,
        &release_contract,
        std::slice::from_ref(&operation),
        &[],
        &[],
        &[],
        issued_at,
    )
    .expect("posture");

    assert_eq!(posture.state, SERVICE_MANAGER_POSTURE_BLOCKED);
    assert!(posture.blocked_reasons.contains(&format!(
        "operationMissingProofDigest:{}",
        operation.operation_id
    )));
    assert!(
        posture
            .blocked_reasons
            .contains(&"releaseContract:missingLabProofRefs".to_string())
    );
    assert!(
        posture
            .blocked_reasons
            .contains(&"missingTrainDigest".to_string())
    );
    validate_fixture(
        &constitute_service_manager::ServiceManagerLifecycleFixture {
            manager_id: constitute_service_manager::DEFAULT_MANAGER_ID.to_string(),
            subject_ref: constitute_service_manager::DEFAULT_SUBJECT_REF.to_string(),
            secret_boundary,
            release_contract,
            operations: vec![operation],
            proof_digests: vec![],
            lab_proofs: vec![],
            train_digests: vec![],
            posture,
        },
    )
    .expect("blocked fixture validates");
}

#[test]
fn protected_posture_blocks_unresolved_secret_boundary() {
    let issued_at = 1_700_000_000;
    let operation = build_operation_posture(
        SERVICE_MANAGER_OPERATION_RESTART,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        issued_at + 100,
        vec![],
    )
    .expect("operation");
    let proof_digest = constitute_service_manager::build_proof_digest(
        &operation,
        constitute_protocol::SERVICE_MANAGER_PROOF_STATE_PROVED,
        issued_at + 200,
        vec![],
    )
    .expect("proof digest");
    let release_contract = build_release_contract_with_refs(
        issued_at,
        vec![proof_digest.digest_id.clone()],
        vec!["lab-proof:service-manager:secret-blocked".to_string()],
    );
    let train_id = "train:service-manager:secret-blocked";
    let lab_proof = build_lab_proof_with_train(
        "lab-proof:service-manager:secret-blocked",
        train_id,
        &release_contract,
        constitute_protocol::SERVICE_MANAGER_PROOF_STATE_PROVED,
        issued_at + 300,
        vec![],
    )
    .expect("lab proof");
    let train_digest = build_train_digest(
        train_id,
        &release_contract,
        std::slice::from_ref(&operation),
        std::slice::from_ref(&proof_digest),
        std::slice::from_ref(&lab_proof),
        constitute_protocol::SERVICE_MANAGER_PROOF_STATE_PROVED,
        issued_at + 400,
        vec![],
    )
    .expect("train digest");
    let mut secret_boundary = build_secret_boundary(issued_at);
    secret_boundary.state = SURFACE_SECRET_BOUNDARY_BLOCKED.to_string();
    secret_boundary.blocked_reasons = vec!["blocked:secret-unavailable".to_string()];

    let posture = reduce_protected_service_manager_posture(
        &secret_boundary,
        &release_contract,
        std::slice::from_ref(&operation),
        std::slice::from_ref(&proof_digest),
        std::slice::from_ref(&lab_proof),
        std::slice::from_ref(&train_digest),
        issued_at,
    )
    .expect("posture");

    assert_eq!(posture.state, SERVICE_MANAGER_POSTURE_BLOCKED);
    assert!(
        posture
            .blocked_reasons
            .contains(&"secretBoundary:blocked".to_string())
    );
    assert_eq!(
        posture.secret_boundary["state"],
        SURFACE_SECRET_BOUNDARY_BLOCKED
    );
}

#[test]
fn blocked_operation_reduces_manager_posture() {
    let fixture = blocked_operation_fixture(
        SERVICE_MANAGER_OPERATION_RESTART,
        "blocked:service-unhealthy",
        1_700_000_000,
    )
    .expect("blocked fixture");
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_BLOCKED);
    assert_eq!(
        fixture.posture.blocked_reasons,
        vec!["blocked:service-unhealthy".to_string()]
    );
    validate_fixture(&fixture).expect("blocked fixture validates");
}

#[test]
fn operation_requires_blocked_reason() {
    let err = build_operation_posture(
        SERVICE_MANAGER_OPERATION_RESTART,
        SERVICE_MANAGER_OPERATION_STATE_BLOCKED,
        1_700_000_000,
        vec![],
    )
    .expect_err("missing blocked reason fails");
    assert!(err.to_string().contains("blocked or failed operation"));
}

#[test]
fn release_and_rollback_refs_are_not_implicit() {
    let mut release = build_operation_posture(
        SERVICE_MANAGER_OPERATION_RELEASE,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        1_700_000_000,
        vec![],
    )
    .expect("release");
    release.release_ref = None;
    assert!(validate_service_manager_operation_posture(&release).is_err());

    let mut rollback = build_operation_posture(
        SERVICE_MANAGER_OPERATION_ROLLBACK,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        1_700_000_000,
        vec![],
    )
    .expect("rollback");
    rollback.rollback_ref = None;
    assert!(validate_service_manager_operation_posture(&rollback).is_err());
}

#[test]
fn cli_emits_valid_lifecycle_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args(["fixture", "lifecycle"])
        .output()
        .expect("run cli");
    assert!(output.status.success());
    let fixture: constitute_service_manager::ServiceManagerLifecycleFixture =
        serde_json::from_slice(&output.stdout).expect("fixture json");
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_READY);
    validate_fixture(&fixture).expect("cli fixture validates");
}
