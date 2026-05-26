use constitute_fabric::{
    HostFabricMemberContributionSpec, HostFabricReductionInput, HostFabricRoleRequirement,
    HostFabricShadowParityInput, build_host_fabric_member_contribution,
    reduce_host_fabric_shadow_parity,
};
use constitute_protocol::{
    CARRIER_EDGE_NETWORK_LOCAL_NETWORK, FABRIC_ADAPTER_EXECUTION_BLOCKED,
    FABRIC_ADAPTER_EXECUTION_SKIPPED, FABRIC_ADAPTER_EXECUTION_SUCCEEDED,
    FABRIC_CONTRACT_TARGET_COMPATIBILITY_DEGRADED, FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED,
    FABRIC_CONTRACT_TARGET_SELECTED, FABRIC_CONTRACT_TARGET_SLOT_DEGRADED,
    FABRIC_CONTRACT_TARGET_SLOT_MISSING, FABRIC_CONTRACT_TARGET_SLOT_NOT_REQUIRED,
    FABRIC_FULFILLMENT_PLAN_BLOCKED, FABRIC_FULFILLMENT_PLAN_READY, FABRIC_LEGACY_CONTROL_BLOCKED,
    FABRIC_LEGACY_CONTROL_FALLBACK_AVAILABLE, FABRIC_LEGACY_CONTROL_LEGACY_DIRECT,
    FABRIC_LIFECYCLE_PHASE_BLOCKED, FABRIC_LIFECYCLE_PHASE_DEGRADED, FABRIC_LIFECYCLE_PHASE_LOAD,
    FABRIC_LIFECYCLE_PHASE_SUCCEEDED, FABRIC_LIFECYCLE_PLAN_BLOCKED,
    FABRIC_LIFECYCLE_PLAN_DEGRADED, FABRIC_MEMBER_CONTRIBUTION_RUNNING,
    FABRIC_MEMBER_ROLE_BUILD_PROCESSOR, FABRIC_MEMBER_ROLE_DOMAIN_SERVICE,
    FABRIC_MEMBER_ROLE_EXECUTION_FULFILLMENT, FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION,
    FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER, FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR,
    FABRIC_MEMBER_ROLE_RUNTIME, FABRIC_MEMBER_ROLE_SOURCE_CONTENT_INDEX,
    FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE, FABRIC_MEMBER_ROLE_SURFACE,
    SERVICE_MANAGER_OPERATION_HEALTH_CHECK, SERVICE_MANAGER_OPERATION_RELEASE,
    SERVICE_MANAGER_OPERATION_RESTART, SERVICE_MANAGER_OPERATION_ROLLBACK,
    SERVICE_MANAGER_OPERATION_SECRET_READY, SERVICE_MANAGER_OPERATION_START,
    SERVICE_MANAGER_OPERATION_STATE_BLOCKED, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
    SERVICE_MANAGER_POSTURE_BLOCKED, SERVICE_MANAGER_POSTURE_READY,
    SERVICE_MANAGER_PROOF_STATE_BLOCKED, SURFACE_SECRET_BOUNDARY_BLOCKED, validate_contract_target,
    validate_contract_target_registry_posture, validate_cybersec_mitigation_consumer_posture,
    validate_host_fabric_adapter_execution_evidence, validate_host_fabric_fulfillment_plan,
    validate_host_fabric_legacy_control_bridge, validate_host_fabric_member_contribution,
    validate_host_fabric_topology_projection, validate_lifecycle_plan_posture,
    validate_service_hardening_posture, validate_service_manager_lab_proof,
    validate_service_manager_operation_posture,
};
use constitute_service_manager::{
    DEFAULT_RUNNER_REF, LifecycleManifestAdmissionInput, ServiceOperationRequest,
    admit_lifecycle_manifest, apply_service_operation, blocked_operation_fixture,
    build_lab_proof_with_train, build_operation_posture, build_operation_posture_for_spec,
    build_release_contract, build_release_contract_with_refs, build_secret_boundary,
    build_train_digest, cybersec_processor_managed_service_spec, default_managed_service_spec,
    default_manager_state, fabric_transition_fixture, lab_linux_target_fixture, load_manager_state,
    reduce_protected_service_manager_posture, save_manager_state,
    service_manager_lifecycle_fixture, service_manager_status, validate_fabric_transition_fixture,
    validate_fixture,
};

const DEFAULT_NOW: u64 = 1_700_000_000;

fn role_ref(role: &str) -> String {
    format!("role:{role}")
}

fn admission_dependency_contribution(
    role: &str,
    suffix: &str,
) -> constitute_protocol::HostFabricMemberContribution {
    build_host_fabric_member_contribution(HostFabricMemberContributionSpec {
        contribution_id: format!("fabric-contribution:manifest-admission:{suffix}"),
        fabric_ref: "fabric:lab-gateway".to_string(),
        host_ref: "host:lab-service-manager".to_string(),
        member_ref: DEFAULT_RUNNER_REF.to_string(),
        participant_ref: format!("participant:manifest-admission:{suffix}"),
        role: role.to_string(),
        role_ref: role_ref(role),
        state: FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string(),
        contract_ref: format!("contract:manifest-admission.{suffix}@0.1.0"),
        subject_ref: format!("subject:manifest-admission:{suffix}"),
        module_refs: vec![format!("module:manifest-admission:{suffix}")],
        source_refs: vec![format!("content-index:manifest-admission:{suffix}")],
        capability_refs: vec![format!("capability:manifest-admission:{suffix}")],
        grant_refs: vec![format!("grant:manifest-admission:{suffix}")],
        input_refs: vec![format!("input:manifest-admission:{suffix}")],
        output_refs: vec![format!("output:manifest-admission:{suffix}")],
        evidence_refs: vec![format!("evidence:manifest-admission:{suffix}")],
        lifecycle_plan_refs: vec![],
        release_refs: vec![format!("release:manifest-admission:{suffix}")],
        resource_posture: None,
        blocked_reasons: vec![],
        safe_facts: serde_json::json!({ "fixture": "manifest-admission-dependency" }),
        observed_at: DEFAULT_NOW + 1_200,
        expires_at: Some(DEFAULT_NOW + 3_600),
    })
    .expect("dependency contribution")
}

fn native_loaded_lab_spec() -> constitute_service_manager::ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.native_module_load_required = true;
    spec.module_resolver_refs = vec!["module-resolver:native-dev:lab".to_string()];
    spec.module_refs = vec!["module:native-dev:lab-service".to_string()];
    spec.module_artifact_refs = vec!["artifact:native-dev:lab-service:abc123".to_string()];
    spec.module_materialization_refs =
        vec!["materialized:path:workspace-dev:lab-service".to_string()];
    spec.module_storage_refs = vec!["storage:materialized-local:lab-service".to_string()];
    spec
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
    assert_eq!(fixture.host_fabric_topology_projections.len(), 1);
    assert_eq!(fixture.service_hardening_postures.len(), 1);
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
    validate_host_fabric_topology_projection(&fixture.host_fabric_topology_projections[0])
        .expect("topology projection validates");
    validate_service_hardening_posture(&fixture.service_hardening_postures[0])
        .expect("service hardening posture validates");
    assert_eq!(
        fixture.host_fabric_contributions[0].role,
        constitute_protocol::FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER
    );
    assert_eq!(
        fixture.host_fabric_fulfillment_plans[0].state,
        constitute_protocol::FABRIC_FULFILLMENT_PLAN_READY
    );
    assert_eq!(
        fixture.host_fabric_topology_projections[0].source_plan_ref,
        fixture.host_fabric_fulfillment_plans[0].plan_id
    );
    assert_eq!(
        fixture.contract_targets[0].state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_READY
    );
    assert_eq!(
        fixture.target_registry_postures[0].state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_READY
    );
    assert_eq!(fixture.service_hardening_postures[0].state, "ready");
    assert_eq!(
        fixture.service_hardening_postures[0].service_ref,
        constitute_service_manager::DEFAULT_SUBJECT_REF
    );
    assert!(
        fixture.service_hardening_postures[0]
            .adapter_posture_refs
            .contains(&constitute_service_manager::DEFAULT_HOST_ADAPTER_REF.to_string())
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
fn native_module_load_refs_thread_through_service_lifecycle() {
    let spec = native_loaded_lab_spec();
    let operation = build_operation_posture_for_spec(
        &spec,
        SERVICE_MANAGER_OPERATION_START,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        DEFAULT_NOW + 12,
        vec![],
    )
    .expect("operation posture");
    let target = constitute_service_manager::build_contract_target_for_spec(
        &spec,
        &operation.operation,
        DEFAULT_NOW + 13,
        vec![],
    )
    .expect("contract target");
    let contribution = constitute_service_manager::build_host_fabric_member_contribution_for_spec(
        &spec,
        &operation,
        DEFAULT_NOW + 14,
        vec![],
    )
    .expect("contribution")
    .expect("contribution present");
    let lifecycle = constitute_service_manager::build_lifecycle_plan_for_spec(
        &spec,
        &operation,
        vec![contribution.contribution_id.clone()],
        DEFAULT_NOW + 15,
        vec![],
    )
    .expect("lifecycle");
    let registry = constitute_service_manager::build_contract_target_registry_posture_for_spec(
        &spec,
        &target,
        &operation,
        Some(&contribution),
        Some(&lifecycle),
        DEFAULT_NOW + 16,
        vec![],
    )
    .expect("registry");

    validate_contract_target(&target).expect("target validates");
    validate_host_fabric_member_contribution(&contribution).expect("contribution validates");
    validate_lifecycle_plan_posture(&lifecycle).expect("lifecycle validates");
    validate_contract_target_registry_posture(&registry).expect("registry validates");
    assert!(
        target
            .capability_slot_refs
            .contains(&"slot:module-resolver".to_string())
    );
    assert!(
        target
            .capability_slot_refs
            .contains(&"slot:module-storage".to_string())
    );
    assert!(
        contribution
            .module_refs
            .contains(&"module:native-dev:lab-service".to_string())
    );
    assert!(
        contribution
            .module_refs
            .contains(&"artifact:native-dev:lab-service:abc123".to_string())
    );
    assert!(
        contribution
            .input_refs
            .contains(&"storage:materialized-local:lab-service".to_string())
    );
    let load = lifecycle
        .phase_postures
        .iter()
        .find(|phase| phase.phase == FABRIC_LIFECYCLE_PHASE_LOAD)
        .expect("load phase");
    assert_eq!(load.state, FABRIC_LIFECYCLE_PHASE_SUCCEEDED);
    assert!(load.blocked_reasons.is_empty());
    assert!(
        load.output_refs
            .contains(&"module-resolver:native-dev:lab".to_string())
    );
    assert!(
        load.output_refs
            .contains(&"artifact:native-dev:lab-service:abc123".to_string())
    );
    assert!(registry.slot_postures.iter().any(|slot| {
        slot.slot_ref == "slot:module-storage"
            && slot.selected_fulfillment_ref.as_deref()
                == Some("storage:materialized-local:lab-service")
    }));
}

#[test]
fn native_module_load_conflicts_degrade_without_blocking_operation() {
    let mut spec = native_loaded_lab_spec();
    spec.module_conflict_refs = vec!["transition-conflict:lab-service:repo:dirty".to_string()];
    let operation = build_operation_posture_for_spec(
        &spec,
        SERVICE_MANAGER_OPERATION_START,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        DEFAULT_NOW + 22,
        vec![],
    )
    .expect("operation posture");
    let contribution = constitute_service_manager::build_host_fabric_member_contribution_for_spec(
        &spec,
        &operation,
        DEFAULT_NOW + 23,
        vec![],
    )
    .expect("contribution")
    .expect("contribution present");
    let lifecycle = constitute_service_manager::build_lifecycle_plan_for_spec(
        &spec,
        &operation,
        vec![contribution.contribution_id],
        DEFAULT_NOW + 24,
        vec![],
    )
    .expect("lifecycle");
    let load = lifecycle
        .phase_postures
        .iter()
        .find(|phase| phase.phase == FABRIC_LIFECYCLE_PHASE_LOAD)
        .expect("load phase");

    validate_lifecycle_plan_posture(&lifecycle).expect("lifecycle validates");
    assert_eq!(lifecycle.state, FABRIC_LIFECYCLE_PLAN_DEGRADED);
    assert_eq!(load.state, FABRIC_LIFECYCLE_PHASE_DEGRADED);
    assert!(load.blocked_reasons.is_empty());
    assert!(
        load.output_refs
            .contains(&"transition-conflict:lab-service:repo:dirty".to_string())
    );
}

#[test]
fn native_module_load_blocks_when_required_materialization_is_missing() {
    let mut state = default_manager_state(DEFAULT_NOW);
    let mut spec = native_loaded_lab_spec();
    spec.module_storage_refs = vec![];
    state.services = vec![spec];
    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_START.to_string(),
            requested_at: DEFAULT_NOW + 32,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: None,
        },
    )
    .expect("apply operation");
    let load = outcome
        .lifecycle_plan
        .phase_postures
        .iter()
        .find(|phase| phase.phase == FABRIC_LIFECYCLE_PHASE_LOAD)
        .expect("load phase");

    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
    assert!(
        outcome
            .blocked_reasons
            .contains(&"moduleLoad:missingStorageRef".to_string())
    );
    assert_eq!(load.state, FABRIC_LIFECYCLE_PHASE_BLOCKED);
    assert!(
        load.blocked_reasons
            .contains(&"moduleLoad:missingStorageRef".to_string())
    );
}

#[test]
fn service_manager_reports_mitigation_recommendation_consumer_posture() {
    let recommendation = constitute_protocol::CybersecMitigationRecommendationRecord {
        kind: Some(constitute_protocol::RECORD_CYBERSEC_MITIGATION_RECOMMENDATION.to_string()),
        recommendation_id: "cybersec:recommendation:service-hardening:retain-evidence".to_string(),
        finding_ref: "cybersec:finding:service-hardening".to_string(),
        processor_report_ref: "event-fabric-report:logging.cybersec.hardening".to_string(),
        recommender_ref: "processor:constitute-cybersec".to_string(),
        action_kind: "retainEvidence".to_string(),
        target_ref: "service:lab-managed".to_string(),
        state: "recommended".to_string(),
        authority_refs: vec!["authority:security-ops".to_string()],
        consumer_refs: vec!["constitute-service-manager".to_string()],
        evidence_refs: vec!["cybersec:finding:service-hardening".to_string()],
        safe_facts: serde_json::json!({ "recommendationOnly": true }),
        blocked_reasons: Vec::new(),
        issued_at: DEFAULT_NOW,
        expires_at: Some(DEFAULT_NOW + 600),
    };
    let posture =
        constitute_service_manager::mitigation::service_manager_mitigation_consumer_posture(
            &recommendation,
            vec!["authority:service-manager-mitigation".to_string()],
            DEFAULT_NOW + 1,
        )
        .expect("service-manager consumer posture");
    validate_cybersec_mitigation_consumer_posture(&posture).expect("posture validates");
    assert_eq!(posture.state, "actionable");
    assert_eq!(posture.consumer_ref, "constitute-service-manager");
    assert_eq!(posture.action_kind, "retainEvidence");
    assert_eq!(posture.safe_facts["hostEffectGated"], true);

    let waiting_authority =
        constitute_service_manager::mitigation::service_manager_mitigation_consumer_posture(
            &recommendation,
            Vec::new(),
            DEFAULT_NOW + 1,
        )
        .expect("waiting authority posture");
    assert_eq!(waiting_authority.state, "waitingAuthority");

    let mut unsupported = recommendation;
    unsupported.action_kind = "block".to_string();
    let posture =
        constitute_service_manager::mitigation::service_manager_mitigation_consumer_posture(
            &unsupported,
            vec!["authority:service-manager-mitigation".to_string()],
            DEFAULT_NOW + 1,
        )
        .expect("unsupported posture");
    assert_eq!(posture.state, "unsupported");
    assert_eq!(posture.blocked_reasons, vec!["unsupportedAction:block"]);

    let mut expired = unsupported;
    expired.action_kind = "retainEvidence".to_string();
    let posture =
        constitute_service_manager::mitigation::service_manager_mitigation_consumer_posture(
            &expired,
            vec!["authority:service-manager-mitigation".to_string()],
            DEFAULT_NOW + 700,
        )
        .expect("expired posture");
    assert_eq!(posture.state, "expired");
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
            participant_ref: "participant:gateway.association:shadow".to_string(),
            role: FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION.to_string(),
            role_ref: "role:gatewayAssociation".to_string(),
            state: FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string(),
            contract_ref: "contract:gateway.association@0.1.0".to_string(),
            subject_ref: "gateway:lab".to_string(),
            module_refs: vec!["module:gateway.association".to_string()],
            source_refs: vec!["content-index:source:constitute-gateway".to_string()],
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
            host_fabric_topology_projections: vec![],
            host_fabric_adapter_execution_evidence: vec![],
            service_hardening_postures: vec![],
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
fn cli_emits_valid_fabric_transition_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args(["fixture", "fabric-transition"])
        .output()
        .expect("run cli");
    assert!(output.status.success());
    let fixture: constitute_service_manager::FabricTransitionFixture =
        serde_json::from_slice(&output.stdout).expect("fixture json");
    assert_eq!(fixture.transition_state, FABRIC_FULFILLMENT_PLAN_READY);
    assert_eq!(
        fixture.aggregate_topology_projection.source_plan_ref,
        fixture.aggregate_fulfillment_plan.plan_id
    );
    assert_eq!(
        fixture.aggregate_topology_projection.role_postures.len(),
        fixture.services.len()
    );
    assert_eq!(
        fixture.carrier_edge_requirements.len(),
        fixture.services.len() - 1
    );
    assert_eq!(
        fixture.carrier_edge_selections.len(),
        fixture.services.len() - 1
    );
    assert!(
        fixture
            .carrier_edge_selections
            .iter()
            .all(|selection| selection.state
                == constitute_protocol::CARRIER_EDGE_SELECTION_ACTIONABLE)
    );
    assert!(fixture.carrier_edge_selections.iter().all(|selection| {
        selection.selected_adapter_ref.as_deref() == Some("adapter:gateway-association:websocket")
    }));
    assert!(fixture.carrier_edge_selections.iter().all(|selection| {
        selection.network_sensitivity.as_deref() == Some(CARRIER_EDGE_NETWORK_LOCAL_NETWORK)
    }));
    assert!(fixture.carrier_edge_selections.iter().all(|selection| {
        selection
            .session_binding_ref
            .as_deref()
            .unwrap_or_default()
            .starts_with("binding:gateway-association:")
    }));
    assert!(fixture.carrier_edge_requirements.iter().all(|requirement| {
        !requirement.proof_substrate_refs.is_empty()
            && !requirement.resource_posture_refs.is_empty()
    }));
    assert_eq!(
        fixture.carrier_edge_adapter_execution_evidence.len(),
        fixture.carrier_edge_selections.len()
    );
    assert!(
        fixture
            .carrier_edge_adapter_execution_evidence
            .iter()
            .all(|evidence| {
                evidence.state == FABRIC_ADAPTER_EXECUTION_SUCCEEDED
                    && evidence
                        .source_bridge_ref
                        .as_deref()
                        .unwrap_or_default()
                        .starts_with("binding:gateway-association:")
                    && evidence
                        .cleanup_refs
                        .iter()
                        .any(|reference| reference.starts_with("cleanup:carrier-edge-adapter:"))
            })
    );
    validate_fabric_transition_fixture(&fixture).expect("fixture validates");
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
    assert_eq!(state.host_fabric_topology_projections.len(), 1);
    assert_eq!(state.host_fabric_adapter_execution_evidence.len(), 1);
    assert_eq!(state.service_hardening_postures.len(), 1);
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
        outcome.host_fabric_topology_projection.source_plan_ref,
        outcome.host_fabric_fulfillment_plan.plan_id
    );
    assert_eq!(
        outcome.host_fabric_adapter_execution_evidence.state,
        FABRIC_ADAPTER_EXECUTION_SKIPPED
    );
    assert_eq!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_bridge_ref
            .as_deref(),
        Some(outcome.host_fabric_legacy_control_bridge.bridge_id.as_str())
    );
    validate_host_fabric_adapter_execution_evidence(
        &outcome.host_fabric_adapter_execution_evidence,
    )
    .expect("adapter execution evidence validates");
    assert_eq!(
        outcome.contract_target.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_READY
    );
    assert_eq!(
        outcome.target_registry_posture.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_READY
    );
    assert_eq!(outcome.service_hardening_posture.state, "ready");
    assert!(
        outcome
            .service_hardening_posture
            .evidence_refs
            .contains(&outcome.host_fabric_fulfillment_plan.plan_id)
    );
    validate_service_hardening_posture(&outcome.service_hardening_posture)
        .expect("service hardening posture validates");
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
    assert_eq!(outcome.fabric_control_decision.state, "waitingPlan");
    assert_eq!(
        outcome
            .fabric_control_decision
            .delegated_role_ref
            .as_deref(),
        Some("role:hostServiceAdapter")
    );
    assert_eq!(
        outcome.fabric_control_decision.kind.as_deref(),
        Some("hostFabric.control.decision")
    );
    assert!(
        outcome
            .blocked_reasons
            .contains(&"hostFabric:controlPlanMissing:role:hostServiceAdapter".to_string())
    );
    assert_eq!(
        outcome.host_fabric_adapter_execution_evidence.state,
        FABRIC_ADAPTER_EXECUTION_BLOCKED
    );
    assert!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_plan_ref
            .is_none()
    );
    assert!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_plan_observed_at
            .is_none()
    );
    assert!(
        outcome
            .host_fabric_adapter_execution_evidence
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
    assert_eq!(
        warmup.host_fabric_fulfillment_plan.action_authority_refs,
        vec![format!(
            "authority:host-fabric:{}",
            warmup.host_fabric_fulfillment_plan.contract_ref
        )]
    );
    assert_eq!(
        warmup.host_fabric_fulfillment_plan.delegated_role_refs,
        vec![role_ref(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER)]
    );
    assert_eq!(
        warmup.host_fabric_fulfillment_plan.fallback_refs,
        vec![format!(
            "fallback:host-fabric:{}",
            warmup.host_fabric_fulfillment_plan.plan_id
        )]
    );
    assert_eq!(
        warmup.host_fabric_fulfillment_plan.quarantine_refs,
        vec![format!(
            "quarantine:host-fabric:{}",
            warmup.host_fabric_fulfillment_plan.plan_id
        )]
    );
    assert_eq!(
        warmup.host_fabric_fulfillment_plan.rollback_refs,
        vec![format!(
            "rollback:host-fabric:{}",
            warmup.host_fabric_fulfillment_plan.plan_id
        )]
    );
    assert!(
        warmup
            .host_fabric_fulfillment_plan
            .evidence_requirement_refs
            .contains(&format!(
                "proof-requirement:host-fabric:{}",
                role_ref(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER)
            ))
    );
    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED);
    assert_eq!(outcome.fabric_control_decision.state, "ready");
    assert!(
        !outcome
            .fabric_control_decision
            .authorization_refs
            .is_empty()
    );
    assert_eq!(
        outcome.host_fabric_adapter_execution_evidence.state,
        FABRIC_ADAPTER_EXECUTION_SUCCEEDED
    );
    assert_eq!(
        outcome
            .host_fabric_adapter_execution_evidence
            .authorization_refs,
        outcome.fabric_control_decision.authorization_refs
    );
    assert_eq!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_decision_ref
            .as_deref(),
        Some(outcome.fabric_control_decision.decision_id.as_str())
    );
    assert_eq!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_plan_ref
            .as_deref(),
        Some(warmup.host_fabric_fulfillment_plan.plan_id.as_str())
    );
    assert!(
        outcome
            .host_fabric_adapter_execution_evidence
            .output_refs
            .contains(&format!(
                "evidence:host-adapter:{}:{}:dry-run-ok",
                outcome.service_id, outcome.operation
            ))
    );
    assert_eq!(
        outcome
            .fabric_control_decision
            .delegated_role_ref
            .as_deref(),
        Some("role:hostServiceAdapter")
    );
    assert_eq!(
        outcome.fabric_control_decision.source_plan_ref.as_deref(),
        Some(warmup.host_fabric_fulfillment_plan.plan_id.as_str())
    );
    assert_eq!(
        outcome.fabric_control_decision.source_plan_observed_at,
        Some(warmup.host_fabric_fulfillment_plan.observed_at)
    );
    assert_eq!(
        outcome.fabric_control_decision.source_plan_expires_at,
        warmup.host_fabric_fulfillment_plan.expires_at
    );
    assert_eq!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_plan_observed_at,
        Some(warmup.host_fabric_fulfillment_plan.observed_at)
    );
    assert_eq!(
        outcome
            .host_fabric_adapter_execution_evidence
            .source_plan_expires_at,
        warmup.host_fabric_fulfillment_plan.expires_at
    );
    assert!(
        outcome
            .host_fabric_adapter_execution_evidence
            .cleanup_refs
            .contains(&format!(
                "cleanup:service-manager:{}:{}",
                outcome.service_id, outcome.operation
            ))
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
    assert_eq!(outcome.service_hardening_posture.state, "blocked");
    assert!(
        outcome
            .service_hardening_posture
            .blocked_reasons
            .contains(&"secretBoundary:missingSecretRefs".to_string())
    );
}

#[test]
fn target_reduction_blocks_missing_execution_fulfillment_slot_before_host_fabric_ready() {
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
            .contains(&"slot:execution-fulfillment".to_string())
    );
    assert_eq!(
        outcome.target_registry_posture.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_BLOCKED
    );
    assert!(
        outcome
            .host_fabric_fulfillment_plan
            .missing_role_refs
            .contains(&"slot:execution-fulfillment".to_string())
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
fn cybersec_processor_spec_threads_processor_refs_through_lifecycle_fabric() {
    let spec = cybersec_processor_managed_service_spec();
    let operation = build_operation_posture_for_spec(
        &spec,
        SERVICE_MANAGER_OPERATION_START,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
        DEFAULT_NOW + 45,
        vec![],
    )
    .expect("cybersec operation posture");
    let target = constitute_service_manager::build_contract_target_for_spec(
        &spec,
        &operation.operation,
        DEFAULT_NOW + 46,
        vec![],
    )
    .expect("cybersec contract target");
    let contribution = constitute_service_manager::build_host_fabric_member_contribution_for_spec(
        &spec,
        &operation,
        DEFAULT_NOW + 47,
        vec![],
    )
    .expect("cybersec contribution")
    .expect("cybersec contribution present");
    let lifecycle = constitute_service_manager::build_lifecycle_plan_for_spec_with_roles(
        &spec,
        &operation,
        vec![contribution.contribution_id.clone()],
        vec![
            role_ref(FABRIC_MEMBER_ROLE_DOMAIN_SERVICE),
            role_ref(constitute_protocol::FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR),
            role_ref(constitute_protocol::FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE),
        ],
        DEFAULT_NOW + 48,
        vec![],
    )
    .expect("cybersec lifecycle");
    let registry = constitute_service_manager::build_contract_target_registry_posture_for_spec(
        &spec,
        &target,
        &operation,
        Some(&contribution),
        Some(&lifecycle),
        DEFAULT_NOW + 49,
        vec![],
    )
    .expect("cybersec registry");
    let fulfillment = constitute_service_manager::reduce_host_fabric_fulfillment_plan_for_spec(
        &spec,
        &operation,
        std::slice::from_ref(&contribution),
        std::slice::from_ref(&lifecycle),
        DEFAULT_NOW + 50,
        vec![],
        Some(&registry),
    )
    .expect("cybersec fulfillment");

    validate_contract_target(&target).expect("target validates");
    validate_host_fabric_member_contribution(&contribution).expect("contribution validates");
    validate_lifecycle_plan_posture(&lifecycle).expect("lifecycle validates");
    validate_contract_target_registry_posture(&registry).expect("registry validates");
    validate_host_fabric_fulfillment_plan(&fulfillment).expect("fulfillment validates");
    assert_eq!(
        target.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_READY
    );
    assert_eq!(
        registry.state,
        constitute_protocol::FABRIC_CONTRACT_TARGET_REGISTRY_READY
    );
    assert_eq!(fulfillment.state, FABRIC_FULFILLMENT_PLAN_READY);
    assert_eq!(contribution.role, FABRIC_MEMBER_ROLE_DOMAIN_SERVICE);
    assert_eq!(
        fulfillment.required_role_refs,
        vec![role_ref(FABRIC_MEMBER_ROLE_DOMAIN_SERVICE)]
    );
    assert!(
        target
            .capability_slot_refs
            .contains(&"slot:processor-contract".to_string())
    );
    assert!(
        target
            .capability_slot_refs
            .contains(&"slot:processor-seed".to_string())
    );
    assert!(
        contribution
            .input_refs
            .contains(&"processor-contract:logging.cybersec".to_string())
    );
    assert!(
        contribution
            .input_refs
            .contains(&"cybersec-seed:logging.default".to_string())
    );
    assert!(lifecycle.phase_postures.iter().any(|phase| {
        phase.phase == constitute_protocol::FABRIC_LIFECYCLE_PHASE_RUN
            && phase.dependency_refs.contains(
                &"lifecycle-dependency:constitute-cybersec:role:loggingProcessor".to_string(),
            )
            && phase
                .output_refs
                .contains(&"event-fabric-report:logging.cybersec.bootstrap".to_string())
    }));
    assert_eq!(lifecycle.dependency_edges.len(), 2);
    assert!(registry.slot_postures.iter().any(|slot| {
        slot.slot_ref == "slot:processor-report"
            && slot.selected_fulfillment_ref.as_deref()
                == Some("event-fabric-report:logging.cybersec.bootstrap")
    }));
}

#[test]
fn fabric_transition_fixture_models_current_services_as_distinct_roles() {
    let fixture = fabric_transition_fixture(DEFAULT_NOW).expect("fabric transition fixture");
    validate_fabric_transition_fixture(&fixture).expect("fixture validates");

    assert_eq!(fixture.family_ref, "branch-family:0x/fabric-transition");
    assert_eq!(fixture.services.len(), 9);
    assert_eq!(fixture.outcomes.len(), 9);
    assert_eq!(fixture.service_hardening_observations.len(), 9);
    assert_eq!(fixture.adapter_execution_evidence.len(), 9);
    assert_eq!(fixture.transition_state, FABRIC_FULFILLMENT_PLAN_READY);
    assert!(fixture.blocked_reasons.is_empty());
    assert!(fixture.shadow_parity.disagreement_role_refs.is_empty());
    assert!(fixture.shadow_parity.blocked_reasons.is_empty());
    assert!(fixture.outcomes.iter().all(|outcome| {
        outcome.host_fabric_legacy_control_bridge.state == FABRIC_LEGACY_CONTROL_LEGACY_DIRECT
    }));
    assert!(fixture.outcomes.iter().all(|outcome| {
        outcome.host_fabric_adapter_execution_evidence.state == FABRIC_ADAPTER_EXECUTION_SKIPPED
    }));

    let service_roles = fixture
        .services
        .iter()
        .map(|service| service.fabric_role.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_BUILD_PROCESSOR));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_EXECUTION_FULFILLMENT));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_RUNTIME));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_SURFACE));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR));
    assert!(service_roles.contains(FABRIC_MEMBER_ROLE_DOMAIN_SERVICE));

    let aggregate_roles = fixture
        .aggregate_fulfillment_plan
        .required_role_refs
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_BUILD_PROCESSOR)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_EXECUTION_FULFILLMENT)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_RUNTIME)));
    let runner_outcome = fixture
        .outcomes
        .iter()
        .find(|outcome| outcome.service_id == "constitute-runner")
        .expect("runner execution fulfillment outcome");
    assert_eq!(
        runner_outcome
            .host_fabric_contribution
            .as_ref()
            .unwrap()
            .role,
        FABRIC_MEMBER_ROLE_EXECUTION_FULFILLMENT
    );
    assert!(
        runner_outcome
            .target_registry_posture
            .slot_postures
            .iter()
            .any(|slot| {
                slot.slot_ref == "slot:execution-fulfillment"
                    && slot.selected_fulfillment_ref.as_deref()
                        == Some(&format!("member:{DEFAULT_RUNNER_REF}"))
            })
    );
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_SURFACE)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR)));
    assert!(aggregate_roles.contains(&role_ref(FABRIC_MEMBER_ROLE_DOMAIN_SERVICE)));
    assert_eq!(
        fixture
            .aggregate_fulfillment_plan
            .member_contribution_refs
            .len(),
        9
    );
    assert_eq!(
        fixture.aggregate_fulfillment_plan.action_authority_refs,
        vec![format!(
            "authority:host-fabric:{}",
            fixture.aggregate_fulfillment_plan.contract_ref
        )]
    );
    assert!(
        fixture
            .aggregate_fulfillment_plan
            .delegated_role_refs
            .contains(&role_ref(FABRIC_MEMBER_ROLE_RUNTIME))
    );
    assert_eq!(
        fixture.aggregate_fulfillment_plan.fallback_refs,
        vec![format!(
            "fallback:host-fabric:{}",
            fixture.aggregate_fulfillment_plan.plan_id
        )]
    );
    assert_eq!(
        fixture.aggregate_fulfillment_plan.quarantine_refs,
        vec![format!(
            "quarantine:host-fabric:{}",
            fixture.aggregate_fulfillment_plan.plan_id
        )]
    );
    assert_eq!(
        fixture.aggregate_fulfillment_plan.rollback_refs,
        vec![format!(
            "rollback:host-fabric:{}",
            fixture.aggregate_fulfillment_plan.plan_id
        )]
    );
    assert!(
        fixture
            .aggregate_fulfillment_plan
            .evidence_requirement_refs
            .contains(&format!(
                "proof-requirement:host-fabric:{}",
                role_ref(FABRIC_MEMBER_ROLE_BUILD_PROCESSOR)
            ))
    );
    assert_eq!(fixture.shadow_parity.agreement_role_refs.len(), 9);
    assert_eq!(fixture.aggregate_topology_projection.role_postures.len(), 9);
    assert!(
        fixture
            .shadow_parity
            .reduction
            .dependency_edge_refs
            .iter()
            .any(|reference| reference
                == "lifecycle-dependency:constitute-cybersec:role:loggingProcessor")
    );
    assert!(fixture.outcomes.iter().any(|outcome| {
        outcome.lifecycle_plan.dependency_edges.iter().any(|edge| {
            edge.source_ref == role_ref(FABRIC_MEMBER_ROLE_SURFACE)
                && edge.target_ref == role_ref(FABRIC_MEMBER_ROLE_RUNTIME)
        })
    }));
    assert_eq!(
        fixture
            .shadow_parity
            .reduction
            .fulfillment_plan
            .member_contribution_refs,
        fixture.aggregate_fulfillment_plan.member_contribution_refs
    );
    assert!(
        fixture
            .aggregate_fulfillment_plan
            .missing_role_refs
            .is_empty()
    );

    for observation in &fixture.service_hardening_observations {
        assert_eq!(
            observation.mitigation_consumer.consumer_ref,
            "constitute-service-manager"
        );
        assert_eq!(observation.mitigation_consumer.state, "actionable");
        assert_eq!(
            observation.mitigation_consumer.action_kind,
            "retainEvidence"
        );
        assert_eq!(
            observation.mitigation_recommendation.target_ref,
            observation.service_hardening_posture.posture_id
        );
        assert_eq!(
            observation.mitigation_consumer.safe_facts["hostEffectGated"],
            true
        );
    }
}

#[test]
fn lifecycle_manifest_admission_consumes_manifest_and_promotion_refs() {
    let lifecycle_manifest_seed = serde_json::json!({
        "kind": "lifecycle.manifest.seed",
        "manifestRef": "lifecycle:manifest:native-dev:constitute-build:abc123",
        "state": "degraded",
        "promotionState": "candidateReady",
        "targetRef": "lifecycle-target:native-dev:constitute-build:main",
        "candidateRefs": ["candidate:native-dev:constitute-build:abc123"],
        "sourceSnapshotRefs": ["source:snapshot:native-dev:constitute-build:abc123"],
        "contentIndexRefs": ["content-index:native-dev:constitute-build:abc123"],
        "buildRefs": ["build:contract:native-dev:constitute-build:abc123"],
        "buildRunRefs": ["build:run:native-dev:constitute-build:abc123"],
        "artifactRefs": ["build:artifact:native-dev:constitute-build:abc123"],
        "storageRefs": ["storage:object:module:native-dev:constitute-build:abc123"],
        "proofRefs": ["build:proof:native-dev:constitute-build:abc123"],
        "releaseCandidateRefs": ["release:candidate:native-dev:constitute-build:abc123"],
        "rollbackRefs": ["rollback:lifecycle:native-dev:constitute-build:abc123"],
        "cleanupRefs": ["cleanup:lifecycle:native-dev:constitute-build:abc123"],
        "proofGateRefs": ["proof-gate:native-build:projection-fulfilled"],
        "governanceRefs": ["governance:promotion:native-dev:operator-seed"],
        "conflictRefs": ["transition-conflict:constitute-build:repo:dirty"],
        "evidenceRefs": ["build:proof:native-dev:constitute-build:abc123"],
        "blockedReasons": [],
        "safeFacts": {
            "acceptedAsMain": false,
            "promotionModel": "candidate-ready-not-pr"
        }
    });
    let promotion_intent_posture = serde_json::json!({
        "kind": "contract.intention.posture",
        "intentionRef": "promotion:intent:native-dev:constitute-build:abc123",
        "state": "degraded",
        "canonicalHashRef": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "contentIndexRefs": ["content-index:native-dev:constitute-build:abc123"],
        "sourceGraphRefs": ["source-root:workspace-dev"],
        "sourceSnapshotRefs": ["source:snapshot:native-dev:constitute-build:abc123"],
        "branchRefs": ["branch:main"],
        "projectRefs": ["project:constituency"],
        "workItemRefs": ["work-item:native-lifecycle-promotion"],
        "buildRefs": ["build:contract:native-dev:constitute-build:abc123"],
        "releaseRefs": ["release:candidate:native-dev:constitute-build:abc123"],
        "rollbackRefs": ["rollback:lifecycle:native-dev:constitute-build:abc123"],
        "compatibilityRefs": ["compat:native-lifecycle:seed-v1"],
        "proofGateRefs": ["proof-gate:native-build:projection-fulfilled"],
        "reducerRefs": ["reducer:lifecycle-promotion:native-dev"],
        "evidenceRefs": ["build:proof:native-dev:constitute-build:abc123"],
        "blockedReasons": []
    });
    let outcome = admit_lifecycle_manifest(LifecycleManifestAdmissionInput {
        service_id: Some("constitute-build".to_string()),
        subject_ref: Some("service:build.processor".to_string()),
        module_ref: Some("module:native-dev:constitute-build".to_string()),
        operation: Some(SERVICE_MANAGER_OPERATION_RELEASE.to_string()),
        requested_at: Some(DEFAULT_NOW + 300),
        lifecycle_manifest_seed: lifecycle_manifest_seed.clone(),
        promotion_intent_posture: promotion_intent_posture.clone(),
        host_fabric_contributions: vec![
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_SOURCE_CONTENT_INDEX, "source"),
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_BUILD_PROCESSOR, "build"),
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE, "storage"),
            admission_dependency_contribution(
                FABRIC_MEMBER_ROLE_EXECUTION_FULFILLMENT,
                "execution",
            ),
        ],
    })
    .expect("manifest admission");

    assert_eq!(outcome.kind, "service-manager.lifecycle-manifest.admission");
    assert_eq!(outcome.state, "degraded");
    assert_eq!(
        outcome.lifecycle_manifest_ref,
        lifecycle_manifest_seed["manifestRef"]
    );
    assert_eq!(
        outcome.promotion_intent_ref,
        promotion_intent_posture["intentionRef"]
    );
    assert!(outcome.blocked_reasons.is_empty());
    assert_eq!(
        outcome.operation_outcome.state,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
    );
    assert_eq!(
        outcome.operation_outcome.lifecycle_plan.contract_ref,
        lifecycle_manifest_seed["manifestRef"]
    );
    assert_eq!(
        outcome.release_contract.content_index_refs,
        vec!["content-index:native-dev:constitute-build:abc123".to_string()]
    );
    assert_eq!(
        outcome.release_contract.build_run_refs,
        vec!["build:run:native-dev:constitute-build:abc123".to_string()]
    );
    assert!(
        outcome
            .release_contract
            .source_operation_refs
            .contains(&"promotion:intent:native-dev:constitute-build:abc123".to_string())
    );
    assert_eq!(
        outcome.selected_refs["releaseRef"],
        "release:candidate:native-dev:constitute-build:abc123"
    );
    assert_eq!(
        outcome.selected_refs["storageRefs"][0],
        "storage:object:module:native-dev:constitute-build:abc123"
    );
    assert_eq!(outcome.safe_facts["dependencyEdgeCount"], 4);
    assert_eq!(
        outcome.safe_facts["dependencyMissingRefs"],
        serde_json::json!([])
    );
    assert_eq!(outcome.safe_facts["serviceManagerOwnsSourceTruth"], false);
    assert_eq!(
        outcome.safe_facts["serviceManagerOwnsDependencyExecution"],
        false
    );
    assert_eq!(outcome.safe_facts["dependencyReductionDeferred"], false);
    assert!(
        outcome
            .operation_outcome
            .lifecycle_plan
            .dependency_edges
            .iter()
            .all(|edge| edge.state == "ready")
    );
}

#[test]
fn lifecycle_manifest_admission_blocks_missing_fabric_dependencies_without_deferring_reduction() {
    let lifecycle_manifest_seed = serde_json::json!({
        "kind": "lifecycle.manifest.seed",
        "manifestRef": "lifecycle:manifest:native-dev:missing-dependencies",
        "state": "ready",
        "targetRef": "lifecycle-target:native-dev:missing-dependencies:main",
        "sourceSnapshotRefs": ["source:snapshot:native-dev:missing-dependencies"],
        "contentIndexRefs": ["content-index:native-dev:missing-dependencies"],
        "buildRefs": ["build:contract:native-dev:missing-dependencies"],
        "buildRunRefs": ["build:run:native-dev:missing-dependencies"],
        "artifactRefs": ["build:artifact:native-dev:missing-dependencies"],
        "storageRefs": ["storage:object:module:native-dev:missing-dependencies"],
        "proofRefs": ["build:proof:native-dev:missing-dependencies"],
        "releaseCandidateRefs": ["release:candidate:native-dev:missing-dependencies"],
        "rollbackRefs": ["rollback:lifecycle:native-dev:missing-dependencies"],
        "blockedReasons": [],
        "safeFacts": {
            "acceptedAsMain": false
        }
    });
    let promotion_intent_posture = serde_json::json!({
        "kind": "contract.intention.posture",
        "intentionRef": "promotion:intent:native-dev:missing-dependencies",
        "state": "ready",
        "canonicalHashRef": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "contentIndexRefs": ["content-index:native-dev:missing-dependencies"],
        "sourceSnapshotRefs": ["source:snapshot:native-dev:missing-dependencies"],
        "branchRefs": ["branch:main"],
        "projectRefs": ["project:constituency"],
        "workItemRefs": ["work-item:native-lifecycle-promotion"],
        "buildRefs": ["build:contract:native-dev:missing-dependencies"],
        "releaseRefs": ["release:candidate:native-dev:missing-dependencies"],
        "rollbackRefs": ["rollback:lifecycle:native-dev:missing-dependencies"],
        "reducerRefs": ["reducer:lifecycle-promotion:native-dev"],
        "blockedReasons": []
    });
    let outcome = admit_lifecycle_manifest(LifecycleManifestAdmissionInput {
        service_id: Some("missing-dependency-service".to_string()),
        subject_ref: Some("service:missing-dependency".to_string()),
        module_ref: Some("module:native-dev:missing-dependencies".to_string()),
        operation: Some(SERVICE_MANAGER_OPERATION_RELEASE.to_string()),
        requested_at: Some(DEFAULT_NOW + 310),
        lifecycle_manifest_seed,
        promotion_intent_posture,
        host_fabric_contributions: vec![],
    })
    .expect("manifest admission");

    assert_eq!(outcome.state, "blocked");
    assert_eq!(
        outcome.operation_outcome.state,
        SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
    );
    assert_eq!(
        outcome.operation_outcome.lifecycle_plan.state,
        FABRIC_LIFECYCLE_PLAN_BLOCKED
    );
    assert_eq!(outcome.release_contract.state, "ready");
    assert_eq!(outcome.safe_facts["dependencyReductionDeferred"], false);
    assert_eq!(outcome.safe_facts["dependencyEdgeCount"], 4);
    assert_eq!(
        outcome
            .operation_outcome
            .lifecycle_plan
            .dependency_edges
            .iter()
            .filter(|edge| edge.state == "missing")
            .count(),
        4
    );
    assert!(
        outcome
            .blocked_reasons
            .iter()
            .any(|reason| reason == "lifecycleDependency:missing:role:sourceContentIndex")
    );
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
    assert_eq!(loaded.host_fabric_adapter_execution_evidence.len(), 1);
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
    let _ = std::fs::remove_file(&path);

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
    assert_eq!(
        outcome.host_fabric_legacy_control_bridge.state,
        FABRIC_LEGACY_CONTROL_LEGACY_DIRECT
    );
    assert!(
        outcome
            .host_fabric_legacy_control_bridge
            .source_decision_ref
            .is_none()
    );
    assert!(
        outcome
            .host_fabric_legacy_control_bridge
            .delegated_role_ref
            .is_none()
    );
    validate_host_fabric_legacy_control_bridge(&outcome.host_fabric_legacy_control_bridge)
        .expect("legacy direct bridge validates");
    assert_eq!(
        outcome.host_fabric_adapter_execution_evidence.state,
        FABRIC_ADAPTER_EXECUTION_SKIPPED
    );

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
        controlled_outcome.fabric_control_decision.safe_facts["controlMode"],
        "fabricPreflightLegacyFallback"
    );
    assert_eq!(
        controlled_outcome.fabric_control_decision.fallback_refs,
        vec!["fallback:service-manager:legacy-control".to_string()]
    );
    assert_eq!(
        controlled_outcome.fabric_control_decision.quarantine_refs,
        vec!["quarantine:service-manager:legacy-control:role:hostServiceAdapter".to_string()]
    );
    assert_eq!(
        controlled_outcome.host_fabric_legacy_control_bridge.state,
        FABRIC_LEGACY_CONTROL_FALLBACK_AVAILABLE
    );
    assert_eq!(
        controlled_outcome
            .host_fabric_legacy_control_bridge
            .source_decision_ref
            .as_deref(),
        Some(
            controlled_outcome
                .fabric_control_decision
                .decision_id
                .as_str()
        )
    );
    assert_eq!(
        controlled_outcome
            .host_fabric_legacy_control_bridge
            .quarantine_refs,
        controlled_outcome.fabric_control_decision.quarantine_refs
    );
    validate_host_fabric_legacy_control_bridge(
        &controlled_outcome.host_fabric_legacy_control_bridge,
    )
    .expect("legacy bridge validates");
    assert_eq!(
        controlled_outcome
            .host_fabric_adapter_execution_evidence
            .state,
        FABRIC_ADAPTER_EXECUTION_SUCCEEDED
    );
    assert_eq!(
        controlled_outcome
            .host_fabric_adapter_execution_evidence
            .source_bridge_ref
            .as_deref(),
        Some(
            controlled_outcome
                .host_fabric_legacy_control_bridge
                .bridge_id
                .as_str()
        )
    );
    validate_host_fabric_adapter_execution_evidence(
        &controlled_outcome.host_fabric_adapter_execution_evidence,
    )
    .expect("adapter execution evidence validates");
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

#[test]
fn cli_run_selects_current_fabric_service_from_default_state() {
    let path = std::env::temp_dir().join(format!(
        "constitute-service-manager-current-fabric-service-{}-{}.json",
        std::process::id(),
        DEFAULT_NOW
    ));
    let path_arg = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&path);

    let seed = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args([
            "run",
            "--state",
            &path_arg,
            "--service",
            "constitute-service-manager",
            "--operation",
            SERVICE_MANAGER_OPERATION_HEALTH_CHECK,
            "--at",
            "1700000000",
        ])
        .output()
        .expect("seed current fabric service cli");
    assert!(
        seed.status.success(),
        "{}",
        String::from_utf8_lossy(&seed.stderr)
    );

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args([
            "run",
            "--state",
            &path_arg,
            "--service",
            "constitute-service-manager",
            "--operation",
            SERVICE_MANAGER_OPERATION_HEALTH_CHECK,
            "--at",
            "1700000100",
            "--fabric-control-role",
            FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER,
        ])
        .output()
        .expect("run current fabric service cli");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let outcome: constitute_service_manager::ServiceOperationOutcome =
        serde_json::from_slice(&run.stdout).expect("outcome json");
    assert_eq!(outcome.service_id, "constitute-service-manager");
    assert_eq!(outcome.fabric_control_decision.state, "ready");
    assert_eq!(
        outcome.host_fabric_legacy_control_bridge.state,
        FABRIC_LEGACY_CONTROL_FALLBACK_AVAILABLE
    );
    assert_eq!(
        outcome.host_fabric_adapter_execution_evidence.state,
        FABRIC_ADAPTER_EXECUTION_SUCCEEDED
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn cli_admit_manifest_reads_manifest_admission_input() {
    let path = std::env::temp_dir().join(format!(
        "constitute-service-manager-admit-manifest-{}-{}.json",
        std::process::id(),
        DEFAULT_NOW
    ));
    let input = serde_json::json!({
        "serviceId": "constitute-build",
        "subjectRef": "service:build.processor",
        "operation": SERVICE_MANAGER_OPERATION_RELEASE,
        "requestedAt": DEFAULT_NOW + 350,
        "lifecycleManifestSeed": {
            "kind": "lifecycle.manifest.seed",
            "manifestRef": "lifecycle:manifest:native-dev:constitute-build:cli",
            "state": "ready",
            "targetRef": "lifecycle-target:native-dev:constitute-build:main",
            "sourceSnapshotRefs": ["source:snapshot:native-dev:constitute-build:cli"],
            "contentIndexRefs": ["content-index:native-dev:constitute-build:cli"],
            "buildRefs": ["build:contract:native-dev:constitute-build:cli"],
            "buildRunRefs": ["build:run:native-dev:constitute-build:cli"],
            "artifactRefs": ["build:artifact:native-dev:constitute-build:cli"],
            "proofRefs": ["build:proof:native-dev:constitute-build:cli"],
            "releaseCandidateRefs": ["release:candidate:native-dev:constitute-build:cli"],
            "rollbackRefs": ["rollback:lifecycle:native-dev:constitute-build:cli"],
            "proofGateRefs": ["proof-gate:native-build:projection-fulfilled"],
            "blockedReasons": [],
            "safeFacts": {
                "acceptedAsMain": false
            }
        },
        "promotionIntentPosture": {
            "kind": "contract.intention.posture",
            "intentionRef": "promotion:intent:native-dev:constitute-build:cli",
            "state": "ready",
            "canonicalHashRef": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "contentIndexRefs": ["content-index:native-dev:constitute-build:cli"],
            "sourceSnapshotRefs": ["source:snapshot:native-dev:constitute-build:cli"],
            "branchRefs": ["branch:main"],
            "projectRefs": ["project:constituency"],
            "workItemRefs": ["work-item:native-lifecycle-promotion"],
            "buildRefs": ["build:contract:native-dev:constitute-build:cli"],
            "releaseRefs": ["release:candidate:native-dev:constitute-build:cli"],
            "rollbackRefs": ["rollback:lifecycle:native-dev:constitute-build:cli"],
            "proofGateRefs": ["proof-gate:native-build:projection-fulfilled"],
            "reducerRefs": ["reducer:lifecycle-promotion:native-dev"],
            "blockedReasons": []
        },
        "hostFabricContributions": [
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_SOURCE_CONTENT_INDEX, "cli-source"),
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_BUILD_PROCESSOR, "cli-build"),
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE, "cli-storage"),
            admission_dependency_contribution(FABRIC_MEMBER_ROLE_EXECUTION_FULFILLMENT, "cli-execution")
        ]
    });
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&input).expect("input json"),
    )
    .expect("write input");
    let path_arg = path.to_string_lossy().to_string();
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_constitute-service-manager"))
        .args(["admit-manifest", "--input", &path_arg])
        .output()
        .expect("run cli");
    assert!(run.status.success());
    let outcome: constitute_service_manager::LifecycleManifestAdmissionOutcome =
        serde_json::from_slice(&run.stdout).expect("outcome json");
    assert_eq!(outcome.state, "ready");
    assert_eq!(
        outcome.operation_outcome.lifecycle_plan.contract_ref,
        "lifecycle:manifest:native-dev:constitute-build:cli"
    );
    assert_eq!(
        outcome.release_contract.build_run_refs,
        vec!["build:run:native-dev:constitute-build:cli".to_string()]
    );
    assert!(outcome.blocked_reasons.is_empty());
    let _ = std::fs::remove_file(path);
}

#[test]
fn fabric_control_blocks_expired_plan_before_adapter_execution() {
    let mut state = default_manager_state(DEFAULT_NOW);
    apply_service_operation(
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
    .expect("prepare control plan");

    let outcome = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_RESTART.to_string(),
            requested_at: DEFAULT_NOW + 5_000,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: Some(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()),
        },
    )
    .expect("expired control outcome");

    assert_eq!(outcome.fabric_control_decision.state, "blocked");
    assert_eq!(
        outcome.host_fabric_legacy_control_bridge.state,
        FABRIC_LEGACY_CONTROL_BLOCKED
    );
    assert_eq!(
        outcome.host_fabric_adapter_execution_evidence.state,
        FABRIC_ADAPTER_EXECUTION_BLOCKED
    );
    assert!(
        outcome
            .fabric_control_decision
            .blocked_reasons
            .iter()
            .any(|reason| { reason.starts_with("hostFabric:controlPlanExpired:") })
    );
    assert_eq!(outcome.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
}

#[test]
fn fabric_control_covers_rollback_and_missing_authority_posture() {
    let mut state = default_manager_state(DEFAULT_NOW);
    apply_service_operation(
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
    .expect("prepare control plan");

    let rollback = apply_service_operation(
        &mut state,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_ROLLBACK.to_string(),
            requested_at: DEFAULT_NOW + 20,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: Some(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()),
        },
    )
    .expect("rollback control");
    assert_eq!(rollback.fabric_control_decision.state, "ready");
    assert_eq!(
        rollback.host_fabric_legacy_control_bridge.state,
        FABRIC_LEGACY_CONTROL_FALLBACK_AVAILABLE
    );
    assert_eq!(
        rollback.fabric_control_decision.rollback_ref.as_deref(),
        Some("rollback:service-manager:lab-service")
    );
    assert_eq!(rollback.state, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED);

    let mut missing_authority = default_manager_state(DEFAULT_NOW);
    missing_authority.services[0].authority_refs.clear();
    let blocked = apply_service_operation(
        &mut missing_authority,
        ServiceOperationRequest {
            service_id: "lab-service".to_string(),
            operation: SERVICE_MANAGER_OPERATION_RESTART.to_string(),
            requested_at: DEFAULT_NOW + 30,
            dry_run: true,
            blocked_reason: None,
            fabric_control_role: Some(FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()),
        },
    )
    .expect("missing authority control");

    assert_eq!(blocked.fabric_control_decision.state, "blocked");
    assert_eq!(
        blocked.host_fabric_legacy_control_bridge.state,
        FABRIC_LEGACY_CONTROL_BLOCKED
    );
    assert!(
        blocked
            .fabric_control_decision
            .blocked_reasons
            .contains(&"hostFabric:controlAuthorityMissing".to_string())
    );
    assert!(
        blocked
            .blocked_reasons
            .contains(&"authorityRefs:missing".to_string())
    );
    assert_eq!(blocked.state, SERVICE_MANAGER_OPERATION_STATE_BLOCKED);
}
