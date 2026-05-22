use constitute_fabric::{
    HostFabricMemberContributionSpec, HostFabricReductionInput, HostFabricRoleRequirement,
    HostFabricShadowParityInput, build_host_fabric_member_contribution,
    reduce_host_fabric_shadow_parity,
};
use constitute_protocol::{
    FABRIC_CONTRACT_TARGET_COMPATIBILITY_DEGRADED, FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED,
    FABRIC_CONTRACT_TARGET_SELECTED, FABRIC_CONTRACT_TARGET_SLOT_DEGRADED,
    FABRIC_CONTRACT_TARGET_SLOT_MISSING, FABRIC_CONTRACT_TARGET_SLOT_NOT_REQUIRED,
    FABRIC_FULFILLMENT_PLAN_BLOCKED, FABRIC_FULFILLMENT_PLAN_READY,
    FABRIC_MEMBER_CONTRIBUTION_RUNNING, FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION,
    FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER, SERVICE_MANAGER_OPERATION_RELEASE,
    SERVICE_MANAGER_OPERATION_RESTART, SERVICE_MANAGER_OPERATION_ROLLBACK,
    SERVICE_MANAGER_OPERATION_SECRET_READY, SERVICE_MANAGER_OPERATION_START,
    SERVICE_MANAGER_OPERATION_STATE_BLOCKED, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
    SERVICE_MANAGER_POSTURE_BLOCKED, SERVICE_MANAGER_POSTURE_READY,
    SERVICE_MANAGER_PROOF_STATE_BLOCKED, SURFACE_SECRET_BOUNDARY_BLOCKED, validate_contract_target,
    validate_contract_target_registry_posture, validate_host_fabric_fulfillment_plan,
    validate_host_fabric_member_contribution, validate_lifecycle_plan_posture,
    validate_service_manager_lab_proof, validate_service_manager_operation_posture,
};
use constitute_service_manager::{
    ServiceOperationRequest, apply_service_operation, blocked_operation_fixture,
    build_lab_proof_with_train, build_operation_posture, build_operation_posture_for_spec,
    build_release_contract, build_release_contract_with_refs, build_secret_boundary,
    build_train_digest, default_managed_service_spec, default_manager_state,
    lab_linux_target_fixture, load_manager_state, reduce_protected_service_manager_posture,
    save_manager_state, service_manager_lifecycle_fixture, service_manager_status,
    validate_fixture,
};

const DEFAULT_NOW: u64 = 1_700_000_000;

fn role_ref(role: &str) -> String {
    format!("role:{role}")
}

#[test]
fn lifecycle_fixture_covers_manager_operations() {
    let fixture = service_manager_lifecycle_fixture(1_700_000_000).expect("fixture");
    assert_eq!(fixture.operations.len(), 10);
    assert_eq!(fixture.proof_digests.len(), 10);
    assert_eq!(fixture.lab_proofs.len(), 1);
    assert_eq!(fixture.train_digests.len(), 1);
    assert_eq!(fixture.contract_targets.len(), 1);
    assert_eq!(fixture.target_registry_postures.len(), 1);
    assert_eq!(fixture.host_fabric_contributions.len(), 1);
    assert_eq!(fixture.lifecycle_plans.len(), 1);
    assert_eq!(fixture.host_fabric_fulfillment_plans.len(), 1);
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_READY);
    assert_eq!(
        fixture.posture.secret_boundary["state"],
        constitute_protocol::SURFACE_SECRET_BOUNDARY_RESOLVED
    );
    assert_eq!(fixture.posture.release_posture["state"], "releaseReady");
    assert_eq!(fixture.posture.rollback_posture["state"], "rollbackReady");
    validate_fixture(&fixture).expect("fixture validates");
    validate_host_fabric_member_contribution(&fixture.host_fabric_contributions[0])
        .expect("fabric contribution validates");
    validate_lifecycle_plan_posture(&fixture.lifecycle_plans[0]).expect("lifecycle plan validates");
    validate_host_fabric_fulfillment_plan(&fixture.host_fabric_fulfillment_plans[0])
        .expect("fulfillment plan validates");
    assert_eq!(
        fixture.host_fabric_contributions[0].role,
        constitute_protocol::FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER
    );
    assert_eq!(
        fixture.host_fabric_fulfillment_plans[0].state,
        constitute_protocol::FABRIC_FULFILLMENT_PLAN_READY
    );
    assert_eq!(
        fixture.contract_targets[0].state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_READY
    );
    assert_eq!(
        fixture.target_registry_postures[0].state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_READY
    );
    assert!(
        fixture.host_fabric_fulfillment_plans[0]
            .evidence_refs
            .contains(&fixture.target_registry_postures[0].registry_ref)
    );
    assert!(
        fixture
            .release_contract
            .content_index_refs
            .contains(&"content-index:source:lab-service".to_string())
    );
    assert!(
        fixture
            .release_contract
            .source_snapshot_refs
            .contains(&"source:snapshot:lab-service:current".to_string())
    );
    assert!(
        fixture
            .release_contract
            .source_operation_refs
            .contains(&"source:operation:lab-service:ref-update".to_string())
    );
    assert!(
        fixture
            .release_contract
            .project_refs
            .contains(&"project:constituency".to_string())
    );
    assert!(
        fixture
            .release_contract
            .build_run_refs
            .contains(&"build:run:lab-service:current".to_string())
    );
    assert!(
        fixture
            .release_contract
            .build_artifact_refs
            .contains(&"build:artifact:lab-service:module".to_string())
    );
    assert!(
        fixture
            .release_contract
            .release_candidate_refs
            .contains(&"release:candidate:lab-service:current".to_string())
    );
    assert!(
        fixture.host_fabric_contributions[0]
            .input_refs
            .contains(&"source:snapshot:lab-service:current".to_string())
    );
    assert!(
        fixture.host_fabric_contributions[0]
            .input_refs
            .contains(&"source:operation:lab-service:project-link".to_string())
    );
    assert!(
        fixture.host_fabric_contributions[0]
            .input_refs
            .contains(&"build-proof:lab-service:current".to_string())
    );
    assert!(
        fixture.host_fabric_contributions[0]
            .input_refs
            .contains(&"release:candidate:lab-service:current".to_string())
    );
    assert!(
        fixture.target_registry_postures[0]
            .source_refs
            .contains(&"source:operation:lab-service:ref-update".to_string())
    );
    assert!(
        fixture.target_registry_postures[0]
            .build_refs
            .contains(&"release:candidate:lab-service:current".to_string())
    );
    let content_index_slot = fixture.target_registry_postures[0]
        .slot_postures
        .iter()
        .find(|slot| slot.slot_ref == "slot:content-index")
        .expect("content-index slot");
    assert_eq!(
        content_index_slot.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE
    );
    let source_operation_slot = fixture.target_registry_postures[0]
        .slot_postures
        .iter()
        .find(|slot| slot.slot_ref == "slot:source-operation")
        .expect("source-operation slot");
    assert_eq!(
        source_operation_slot.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE
    );
    let release_candidate_slot = fixture.target_registry_postures[0]
        .slot_postures
        .iter()
        .find(|slot| slot.slot_ref == "slot:release-candidate")
        .expect("release-candidate slot");
    assert_eq!(
        release_candidate_slot.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE
    );

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
fn lab_linux_target_fixture_keeps_client_proof_protected() {
    let fixture = lab_linux_target_fixture(DEFAULT_NOW).expect("lab target fixture");
    validate_contract_target(&fixture.target).expect("target validates");
    validate_contract_target_registry_posture(&fixture.registry).expect("registry validates");
    validate_service_manager_lab_proof(&fixture.protected_lab_proof).expect("lab proof validates");

    assert_eq!(fixture.target.platform_ref, "platform:linux.lab");
    assert_eq!(fixture.target.state, FABRIC_CONTRACT_TARGET_SELECTED);
    assert_eq!(
        fixture.target.compatibility_state,
        FABRIC_CONTRACT_TARGET_COMPATIBILITY_DEGRADED
    );
    assert!(
        fixture
            .target
            .negative_slot_refs
            .contains(&"slot:browser-webrtc".to_string())
    );
    assert!(
        fixture
            .target
            .missing_slot_refs
            .contains(&"slot:runtime-client".to_string())
    );
    assert!(
        fixture
            .target
            .missing_slot_refs
            .contains(&"slot:lab-proof-automation".to_string())
    );
    assert_eq!(
        fixture.registry.state,
        FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED
    );
    assert_eq!(
        fixture.protected_lab_proof.state,
        SERVICE_MANAGER_PROOF_STATE_BLOCKED
    );
    assert!(
        fixture
            .protected_lab_proof
            .blocked_reasons
            .contains(&"blocked:lab-proof-protected-manual".to_string())
    );

    let runtime_slot = fixture
        .registry
        .slot_postures
        .iter()
        .find(|slot| slot.slot_ref == "slot:runtime-client")
        .expect("runtime client slot");
    assert_eq!(runtime_slot.state, FABRIC_CONTRACT_TARGET_SLOT_MISSING);
    let browser_slot = fixture
        .registry
        .slot_postures
        .iter()
        .find(|slot| slot.slot_ref == "slot:browser-webrtc")
        .expect("browser webrtc slot");
    assert_eq!(browser_slot.state, FABRIC_CONTRACT_TARGET_SLOT_NOT_REQUIRED);
    let rollback_slot = fixture
        .registry
        .slot_postures
        .iter()
        .find(|slot| slot.slot_ref == "slot:rollback")
        .expect("rollback slot");
    assert_eq!(rollback_slot.state, FABRIC_CONTRACT_TARGET_SLOT_DEGRADED);
}

#[test]
fn shadow_fabric_parity_blocks_missing_legacy_ready_contributor() {
    let fixture = service_manager_lifecycle_fixture(DEFAULT_NOW).expect("fixture");
    let contribution = fixture.host_fabric_contributions[0].clone();
    let parity = reduce_host_fabric_shadow_parity(HostFabricShadowParityInput {
        reduction: HostFabricReductionInput {
            plan_id: "fabric-plan:shadow:service-manager:gateway-gap".to_string(),
            fabric_ref: contribution.fabric_ref.clone(),
            host_ref: contribution.host_ref.clone(),
            contract_ref: "contract:host-fabric.shadow-service-manager@0.1.0".to_string(),
            required_roles: vec![
                HostFabricRoleRequirement {
                    role_ref: role_ref(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER),
                    min_ready: 1,
                },
                HostFabricRoleRequirement {
                    role_ref: role_ref(FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION),
                    min_ready: 1,
                },
            ],
            contributions: vec![contribution],
            lifecycle_plans: fixture.lifecycle_plans.clone(),
            materialization_budget_refs: vec![
                "materialization-budget:shadow-service-manager".to_string(),
            ],
            known_missing_role_refs: vec![],
            evidence_refs: vec!["evidence:legacy-posture:service-manager".to_string()],
            blocked_reasons: vec![],
            association_handoff_ref: Some(
                "handoff:substrate:lab-gateway:initial-owner".to_string(),
            ),
            observed_at: DEFAULT_NOW + 1_000,
            expires_at: Some(DEFAULT_NOW + 3_600),
        },
        legacy_ready_role_refs: vec![
            FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string(),
            FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION.to_string(),
        ],
        legacy_blocked_role_refs: vec![],
    })
    .expect("shadow parity reduces");

    assert_eq!(
        parity.reduction.fulfillment_plan.state,
        FABRIC_FULFILLMENT_PLAN_BLOCKED
    );
    assert!(parity.blocked_reasons.contains(&format!(
        "hostFabric:legacyDisagreement:missingRole:{}",
        role_ref(FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION)
    )));
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_READY);
}

#[test]
fn shadow_fabric_parity_accepts_current_contribution_knot_without_control_change() {
    let fixture = service_manager_lifecycle_fixture(DEFAULT_NOW).expect("fixture");
    let service_contribution = fixture.host_fabric_contributions[0].clone();
    let gateway_contribution =
        build_host_fabric_member_contribution(HostFabricMemberContributionSpec {
            contribution_id: "fabric-contribution:gatewayAssociation:shadow".to_string(),
            fabric_ref: service_contribution.fabric_ref.clone(),
            host_ref: service_contribution.host_ref.clone(),
            member_ref: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1"
                .to_string(),
            role: FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION.to_string(),
            state: FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string(),
            contract_ref: "contract:gateway.association@0.1.0".to_string(),
            subject_ref: "gateway:lab".to_string(),
            capability_refs: vec!["capability:gateway.association.fulfill".to_string()],
            grant_refs: vec!["grant:gateway.association:lab".to_string()],
            input_refs: vec!["target:local-workstation:dev".to_string()],
            output_refs: vec!["gateway:lab".to_string()],
            evidence_refs: vec!["evidence:gateway.association:shadow".to_string()],
            lifecycle_plan_refs: vec![],
            release_refs: vec![],
            resource_posture: None,
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({ "fixture": "gateway-association-shadow" }),
            observed_at: DEFAULT_NOW + 1_000,
            expires_at: Some(DEFAULT_NOW + 3_600),
        })
        .expect("gateway contribution");
    let parity = reduce_host_fabric_shadow_parity(HostFabricShadowParityInput {
        reduction: HostFabricReductionInput {
            plan_id: "fabric-plan:shadow:service-manager:ready".to_string(),
            fabric_ref: service_contribution.fabric_ref.clone(),
            host_ref: service_contribution.host_ref.clone(),
            contract_ref: "contract:host-fabric.shadow-service-manager@0.1.0".to_string(),
            required_roles: vec![
                HostFabricRoleRequirement {
                    role_ref: role_ref(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER),
                    min_ready: 1,
                },
                HostFabricRoleRequirement {
                    role_ref: role_ref(FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION),
                    min_ready: 1,
                },
            ],
            contributions: vec![service_contribution, gateway_contribution],
            lifecycle_plans: fixture.lifecycle_plans.clone(),
            materialization_budget_refs: vec![
                "materialization-budget:shadow-service-manager".to_string(),
            ],
            known_missing_role_refs: vec![],
            evidence_refs: vec!["evidence:legacy-posture:service-manager".to_string()],
            blocked_reasons: vec![],
            association_handoff_ref: Some(
                "handoff:substrate:lab-gateway:initial-owner".to_string(),
            ),
            observed_at: DEFAULT_NOW + 1_000,
            expires_at: Some(DEFAULT_NOW + 3_600),
        },
        legacy_ready_role_refs: vec![
            FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string(),
            FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION.to_string(),
        ],
        legacy_blocked_role_refs: vec![],
    })
    .expect("shadow parity reduces");

    assert_eq!(
        parity.reduction.fulfillment_plan.state,
        FABRIC_FULFILLMENT_PLAN_READY
    );
    assert!(parity.disagreement_role_refs.is_empty());
    assert_eq!(fixture.posture.state, SERVICE_MANAGER_POSTURE_READY);
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
            contract_targets: vec![],
            target_registry_postures: vec![],
            host_fabric_contributions: vec![],
            lifecycle_plans: vec![],
            host_fabric_fulfillment_plans: vec![],
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

#[test]
fn cli_emits_valid_lab_target_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args(["fixture", "lab-target"])
        .output()
        .expect("run cli");
    assert!(output.status.success());
    let fixture: constitute_service_manager::LabLinuxTargetFixture =
        serde_json::from_slice(&output.stdout).expect("fixture json");
    assert_eq!(fixture.target.platform_ref, "platform:linux.lab");
    assert_eq!(
        fixture.registry.state,
        FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED
    );
    validate_contract_target(&fixture.target).expect("target validates");
    validate_contract_target_registry_posture(&fixture.registry).expect("registry validates");
    validate_service_manager_lab_proof(&fixture.protected_lab_proof).expect("proof validates");
}

#[test]
fn dry_run_operation_persists_state_and_reduces_posture() {
    let mut state = default_manager_state(DEFAULT_NOW);
    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 10,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("apply operation");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED);
    assert_eq!(state.operations.len(), 1);
    assert_eq!(state.proof_digests.len(), 1);
    assert_eq!(state.contract_targets.len(), 1);
    assert_eq!(state.target_registry_postures.len(), 1);
    assert_eq!(state.host_fabric_contributions.len(), 1);
    assert_eq!(state.lifecycle_plans.len(), 1);
    assert_eq!(state.host_fabric_fulfillment_plans.len(), 1);
    assert_eq!(outcome.posture.state, SERVICE_MANAGER_POSTURE_READY);
    assert!(outcome.host_fabric_contribution.is_some());
    assert_eq!(
        outcome.lifecycle_plan.state,
        constitute_protocol::FABRIC_LIFECYCLE_PLAN_READY
    );
    assert_eq!(
        outcome.host_fabric_fulfillment_plan.state,
        constitute_protocol::FABRIC_FULFILLMENT_PLAN_READY
    );
    assert_eq!(
        outcome.contract_target.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_READY
    );
    assert_eq!(
        outcome.target_registry_posture.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_READY
    );
    assert_eq!(
        outcome.operation_posture.subject_ref,
        constitute_service_manager::DEFAULT_SUBJECT_REF
    );
}

#[test]
fn fabric_control_role_blocks_without_existing_fulfillment_plan() {
    let mut state = default_manager_state(DEFAULT_NOW);
    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 12,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: Some(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()),
        },
    )
    .expect("apply fabric-controlled operation");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
    assert_eq!(outcome.fabric_control_decision.state, "blocked");
    assert_eq!(
        outcome.fabric_control_decision.role_ref.as_deref(),
        Some("role:hostServiceAdapter")
    );
    assert!(
        outcome
            .blocked_reasons
            .contains(&"hostFabric:controlPlanMissing:role:hostServiceAdapter".to_string())
    );
}

#[test]
fn fabric_control_role_allows_operation_when_latest_plan_is_ready() {
    let mut state = default_manager_state(DEFAULT_NOW);
    let warmup = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 14,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("warm up fabric plan");
    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_RESTART.to_string(),
            requested_at: DEFAULT_NOW + 18,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: Some(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()),
        },
    )
    .expect("apply fabric-controlled operation");

    assert_eq!(
        warmup.host_fabric_fulfillment_plan.state,
        FABRIC_FULFILLMENT_PLAN_READY
    );
    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED);
    assert_eq!(outcome.fabric_control_decision.state, "ready");
    assert_eq!(
        outcome.fabric_control_decision.source_plan_ref.as_deref(),
        Some(warmup.host_fabric_fulfillment_plan.plan_id.as_str())
    );
}

#[test]
fn fabric_control_role_blocks_operation_when_latest_plan_is_blocked() {
    let mut state = default_manager_state(DEFAULT_NOW);
    apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 22,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("warm up fabric plan");
    let plan = state
        .host_fabric_fulfillment_plans
        .last_mut()
        .expect("fabric plan");
    plan.state = FABRIC_FULFILLMENT_PLAN_BLOCKED.to_string();
    plan.blocked_reasons = vec!["hostFabric:missingRole:role:gatewayAssociation".to_string()];

    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_RESTART.to_string(),
            requested_at: DEFAULT_NOW + 28,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: Some(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()),
        },
    )
    .expect("apply fabric-controlled operation");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
    assert_eq!(outcome.fabric_control_decision.state, "blocked");
    assert!(
        outcome
            .blocked_reasons
            .contains(&"hostFabric:controlBlocked:role:hostServiceAdapter".to_string())
    );
    assert!(
        outcome
            .blocked_reasons
            .contains(&"hostFabric:missingRole:role:gatewayAssociation".to_string())
    );
}

#[test]
fn operation_blocks_when_secret_boundary_is_unresolved() {
    let mut state = default_manager_state(DEFAULT_NOW);
    state.services[0].secret_refs.clear();

    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_SECRET_READY.to_string(),
            requested_at: DEFAULT_NOW + 20,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("apply blocked operation");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
    assert!(
        outcome
            .blocked_reasons
            .contains(&"secretBoundary:missingSecretRefs".to_string())
    );
    assert_eq!(
        outcome.proof_digest.state,
        SERVICE_MANAGER_PROOF_STATE_BLOCKED
    );
    assert_eq!(outcome.posture.state, SERVICE_MANAGER_POSTURE_BLOCKED);
}

#[test]
fn target_reduction_blocks_missing_runner_slot_before_host_fabric_ready() {
    let mut state = default_manager_state(DEFAULT_NOW);
    state.services[0].runner_ref = None;

    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 25,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("apply missing-runner operation");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
    assert_eq!(
        outcome.contract_target.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_BLOCKED
    );
    assert!(
        outcome
            .contract_target
            .missing_slot_refs
            .contains(&"slot:runner".to_string())
    );
    assert_eq!(
        outcome.target_registry_posture.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_BLOCKED
    );
    assert!(
        outcome
            .host_fabric_fulfillment_plan
            .missing_role_refs
            .contains(&"slot:runner".to_string())
    );
}

#[test]
fn promote_blocks_when_rollback_required_but_unavailable() {
    let mut state = default_manager_state(DEFAULT_NOW);
    state.services[0].rollback_ref = None;

    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: constitute_protocol::SERVICE_MANAGER_OPERATION_PROMOTE.to_string(),
            requested_at: DEFAULT_NOW + 30,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("apply blocked promote");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
    assert!(
        outcome
            .blocked_reasons
            .contains(&"rollbackRequired".to_string())
    );
    assert_eq!(outcome.posture.rollback_posture["state"], "blocked");
}

#[test]
fn blocked_rollback_can_report_missing_ref_as_preflight_posture() {
    let mut spec = default_managed_service_spec();
    spec.rollback_ref = None;
    let operation = build_operation_posture_for_spec(
        &spec,
        SERVICE_MANAGER_OPERATION_ROLLBACK,
        SERVICE_MANAGER_OPERATION_STATE_BLOCKED,
        DEFAULT_NOW + 40,
        vec!["rollbackRequired".to_string()],
    )
    .expect("blocked rollback posture");
    assert_eq!(operation.rollback_ref, None);
    assert!(validate_service_manager_operation_posture(&operation).is_ok());
}

#[test]
fn state_file_roundtrips_through_cli_contract_helpers() {
    let path = std::env::temp_dir().join(format!(
        "constitute-service-manager-state-{}-{}.json",
        std::process::id(),
        DEFAULT_NOW
    ));
    let mut state = default_manager_state(DEFAULT_NOW);
    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 50,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("apply operation");
    save_manager_state(&path, &state).expect("save state");
    let loaded = load_manager_state(&path, DEFAULT_NOW).expect("load state");
    let posture =
        service_manager_status(&loaded, "lab-service", DEFAULT_NOW + 60).expect("status posture");

    assert_eq!(loaded.operations.len(), 1);
    assert_eq!(posture.state, SERVICE_MANAGER_POSTURE_READY);
    assert_eq!(
        outcome.operation_posture.operation,
        SERVICE_MANAGER_OPERATION_START
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn cli_run_and_status_roundtrip_state_file() {
    let path = std::env::temp_dir().join(format!(
        "constitute-service-manager-cli-{}-{}.json",
        std::process::id(),
        DEFAULT_NOW
    ));
    let path_arg = path.to_string_lossy().to_string();

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args([
            "run",
            "--state",
            &path_arg,
            "--operation",
            SERVICE_MANAGER_OPERATION_START,
            "--at",
            "1700000100",
        ])
        .output()
        .expect("run cli");
    assert!(run.status.success());
    let outcome: constitute_service_manager::ServiceOperationOutcome =
        serde_json::from_slice(&run.stdout).expect("outcome json");
    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED);

    let controlled_run =
        std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
            .args([
                "run",
                "--state",
                &path_arg,
                "--operation",
                SERVICE_MANAGER_OPERATION_RESTART,
                "--at",
                "1700000150",
                "--fabric-control-role",
                FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER,
            ])
            .output()
            .expect("run controlled cli");
    assert!(controlled_run.status.success());
    let controlled_outcome: constitute_service_manager::ServiceOperationOutcome =
        serde_json::from_slice(&controlled_run.stdout).expect("controlled outcome json");
    assert_eq!(controlled_outcome.fabric_control_decision.state, "ready");
    assert_eq!(
        controlled_outcome.state,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
    );

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args(["status", "--state", &path_arg, "--at", "1700000200"])
        .output()
        .expect("status cli");
    assert!(status.status.success());
    let posture: constitute_protocol::ServiceManagerPostureRecord =
        serde_json::from_slice(&status.stdout).expect("posture json");
    assert_eq!(posture.state, SERVICE_MANAGER_POSTURE_READY);
    let _ = std::fs::remove_file(path);
}
