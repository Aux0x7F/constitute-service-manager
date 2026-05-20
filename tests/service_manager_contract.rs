use constitute_protocol::{
    SERVICE_MANAGER_OPERATION_RELEASE, SERVICE_MANAGER_OPERATION_RESTART,
    SERVICE_MANAGER_OPERATION_ROLLBACK, SERVICE_MANAGER_OPERATION_STATE_BLOCKED,
    SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED, SERVICE_MANAGER_POSTURE_BLOCKED,
    SERVICE_MANAGER_POSTURE_READY, validate_service_manager_operation_posture,
};
use constitute_service_manager::{
    blocked_operation_fixture, build_operation_posture, service_manager_lifecycle_fixture,
    validate_fixture,
};

#[test]
fn lifecycle_fixture_covers_manager_operations() {
    let fixture = service_manager_lifecycle_fixture(1_700_000_000).expect("fixture");
    assert_eq!(fixture.operations.len(), 10);
    assert_eq!(fixture.proof_digests.len(), 10);
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_READY);
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
