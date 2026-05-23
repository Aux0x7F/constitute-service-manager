use anyhow::{Result, anyhow};
use constitute_fabric::{
    HostFabricReductionInput, HostFabricRoleRequirement, HostFabricShadowParity,
    HostFabricShadowParityInput, reduce_host_fabric, reduce_host_fabric_shadow_parity,
};
use constitute_protocol::{
    ContractTarget, ContractTargetRegistryPosture, ContractTargetSlotPosture,
    CybersecMitigationConsumerPostureRecord, CybersecMitigationRecommendationRecord,
    FABRIC_CONTRACT_TARGET_BLOCKED, FABRIC_CONTRACT_TARGET_COMPATIBILITY_DEGRADED,
    FABRIC_CONTRACT_TARGET_COMPATIBLE, FABRIC_CONTRACT_TARGET_INCOMPATIBLE,
    FABRIC_CONTRACT_TARGET_PLATFORM_FIT_COMPATIBLE, FABRIC_CONTRACT_TARGET_PLATFORM_FIT_DEGRADED,
    FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN, FABRIC_CONTRACT_TARGET_READY,
    FABRIC_CONTRACT_TARGET_REGISTRY_BLOCKED, FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED,
    FABRIC_CONTRACT_TARGET_REGISTRY_READY, FABRIC_CONTRACT_TARGET_SELECTED,
    FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE, FABRIC_CONTRACT_TARGET_SLOT_BLOCKED,
    FABRIC_CONTRACT_TARGET_SLOT_DEGRADED, FABRIC_CONTRACT_TARGET_SLOT_MISSING,
    FABRIC_CONTRACT_TARGET_SLOT_NOT_REQUIRED, FABRIC_CONTROL_DECISION_BLOCKED,
    FABRIC_CONTROL_DECISION_DEGRADED, FABRIC_CONTROL_DECISION_NOT_REQUESTED,
    FABRIC_CONTROL_DECISION_READY, FABRIC_CONTROL_DECISION_WAITING_PLAN,
    FABRIC_FULFILLMENT_PLAN_BLOCKED, FABRIC_FULFILLMENT_PLAN_DEGRADED,
    FABRIC_FULFILLMENT_PLAN_READY, FABRIC_LEGACY_CONTROL_BLOCKED,
    FABRIC_LEGACY_CONTROL_FALLBACK_AVAILABLE, FABRIC_LEGACY_CONTROL_LEGACY_DIRECT,
    FABRIC_LEGACY_CONTROL_QUARANTINED, FABRIC_LIFECYCLE_PHASE_BLOCKED,
    FABRIC_LIFECYCLE_PHASE_BUILD, FABRIC_LIFECYCLE_PHASE_CLEANUP, FABRIC_LIFECYCLE_PHASE_LOAD,
    FABRIC_LIFECYCLE_PHASE_NOT_REQUIRED, FABRIC_LIFECYCLE_PHASE_OBSERVE,
    FABRIC_LIFECYCLE_PHASE_READY, FABRIC_LIFECYCLE_PHASE_RELEASE, FABRIC_LIFECYCLE_PHASE_ROLLBACK,
    FABRIC_LIFECYCLE_PHASE_RUN, FABRIC_LIFECYCLE_PHASE_RUNNING, FABRIC_LIFECYCLE_PHASE_SOURCE,
    FABRIC_LIFECYCLE_PHASE_SUCCEEDED, FABRIC_LIFECYCLE_PLAN_BLOCKED, FABRIC_LIFECYCLE_PLAN_READY,
    FABRIC_MEMBER_CONTRIBUTION_BLOCKED, FABRIC_MEMBER_CONTRIBUTION_RUNNING,
    FABRIC_MEMBER_ROLE_BUILD_PROCESSOR, FABRIC_MEMBER_ROLE_DOMAIN_SERVICE,
    FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION, FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER,
    FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR, FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE,
    HostFabricControlDecision, HostFabricFulfillmentPlan, HostFabricLegacyControlBridge,
    HostFabricMemberContribution, LifecyclePhasePosture, LifecyclePlanPosture,
    RECORD_CONTRACT_TARGET, RECORD_CONTRACT_TARGET_REGISTRY_POSTURE,
    RECORD_CYBERSEC_MITIGATION_RECOMMENDATION, RECORD_HOST_FABRIC_CONTROL_DECISION,
    RECORD_HOST_FABRIC_FULFILLMENT_PLAN, RECORD_HOST_FABRIC_LEGACY_CONTROL_BRIDGE,
    RECORD_HOST_FABRIC_MEMBER_CONTRIBUTION, RECORD_LIFECYCLE_PLAN_POSTURE, RECORD_RESOURCE_POSTURE,
    RECORD_SERVICE_HARDENING_POSTURE, RECORD_SERVICE_MANAGER_LAB_PROOF,
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
    ServiceHardeningPostureRecord, ServiceManagerLabProofRecord,
    ServiceManagerOperationPostureRecord, ServiceManagerPostureRecord,
    ServiceManagerProofDigestRecord, ServiceManagerReleaseContractRecord,
    ServiceManagerSecretBoundaryRecord, ServiceManagerTrainDigestRecord, validate_contract_target,
    validate_contract_target_registry_posture, validate_cybersec_mitigation_consumer_posture,
    validate_cybersec_mitigation_recommendation, validate_host_fabric_control_decision,
    validate_host_fabric_fulfillment_plan, validate_host_fabric_legacy_control_bridge,
    validate_host_fabric_member_contribution, validate_lifecycle_plan_posture,
    validate_service_hardening_posture, validate_service_manager_lab_proof,
    validate_service_manager_operation_posture, validate_service_manager_posture,
    validate_service_manager_proof_digest, validate_service_manager_release_contract,
    validate_service_manager_secret_boundary, validate_service_manager_train_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub mod mitigation;

pub const DEFAULT_MANAGER_ID: &str = "manager:lab-service";
pub const DEFAULT_SUBJECT_REF: &str = "service:lab-managed";
pub const DEFAULT_MANAGER_REF: &str = "member:service-manager:lab";
pub const DEFAULT_REQUESTER_REF: &str = "identity:operator";
pub const DEFAULT_RUNNER_REF: &str =
    "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1";
pub const DEFAULT_FABRIC_REF: &str = "fabric:lab-gateway";
pub const DEFAULT_HOST_ADAPTER_REF: &str = "contract:host-service-adapter.service-manager@0.1.0";
pub const DEFAULT_LIFECYCLE_CONTRACT_REF: &str = "contract:lifecycle.host-service-adapter@0.1.0";
pub const DEFAULT_ASSOCIATION_HANDOFF_REF: &str = "handoff:substrate:lab-gateway:initial-owner";

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
    pub contract_targets: Vec<ContractTarget>,
    pub target_registry_postures: Vec<ContractTargetRegistryPosture>,
    pub host_fabric_contributions: Vec<HostFabricMemberContribution>,
    pub lifecycle_plans: Vec<LifecyclePlanPosture>,
    pub host_fabric_fulfillment_plans: Vec<HostFabricFulfillmentPlan>,
    pub service_hardening_postures: Vec<ServiceHardeningPostureRecord>,
    pub posture: ServiceManagerPostureRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabLinuxTargetFixture {
    pub target: ContractTarget,
    pub registry: ContractTargetRegistryPosture,
    pub release_contract: ServiceManagerReleaseContractRecord,
    pub protected_lab_proof: ServiceManagerLabProofRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FabricTransitionFixture {
    pub family_ref: String,
    pub fabric_ref: String,
    pub host_ref: String,
    pub services: Vec<ManagedServiceSpec>,
    pub outcomes: Vec<ServiceOperationOutcome>,
    pub service_hardening_observations: Vec<ServiceManagerHardeningObservation>,
    pub aggregate_fulfillment_plan: HostFabricFulfillmentPlan,
    pub shadow_parity: HostFabricShadowParity,
    pub transition_state: String,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerHardeningObservation {
    pub service_id: String,
    pub service_hardening_posture: ServiceHardeningPostureRecord,
    pub mitigation_recommendation: CybersecMitigationRecommendationRecord,
    pub mitigation_consumer: CybersecMitigationConsumerPostureRecord,
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
    #[serde(default = "default_fabric_ref")]
    pub fabric_ref: String,
    #[serde(default = "default_host_adapter_ref")]
    pub host_adapter_ref: String,
    #[serde(default = "default_lifecycle_contract_ref")]
    pub lifecycle_contract_ref: String,
    #[serde(default = "default_fabric_role")]
    pub fabric_role: String,
    #[serde(default = "default_association_handoff_ref")]
    pub association_handoff_ref: Option<String>,
    pub app_contract_ref: Option<String>,
    pub version: Option<String>,
    pub build_ref: Option<String>,
    #[serde(default)]
    pub content_index_refs: Vec<String>,
    #[serde(default)]
    pub source_graph_refs: Vec<String>,
    #[serde(default)]
    pub source_snapshot_refs: Vec<String>,
    #[serde(default)]
    pub source_operation_refs: Vec<String>,
    #[serde(default)]
    pub project_refs: Vec<String>,
    #[serde(default)]
    pub work_item_refs: Vec<String>,
    #[serde(default)]
    pub build_run_refs: Vec<String>,
    #[serde(default)]
    pub build_artifact_refs: Vec<String>,
    #[serde(default)]
    pub build_proof_refs: Vec<String>,
    #[serde(default)]
    pub release_candidate_refs: Vec<String>,
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
    #[serde(default)]
    pub materialization_budget_refs: Vec<String>,
    #[serde(default)]
    pub processor_contract_refs: Vec<String>,
    #[serde(default)]
    pub processor_role_refs: Vec<String>,
    #[serde(default)]
    pub processor_seed_refs: Vec<String>,
    #[serde(default)]
    pub processor_report_refs: Vec<String>,
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
    #[serde(default)]
    pub contract_targets: Vec<ContractTarget>,
    #[serde(default)]
    pub target_registry_postures: Vec<ContractTargetRegistryPosture>,
    #[serde(default)]
    pub host_fabric_contributions: Vec<HostFabricMemberContribution>,
    #[serde(default)]
    pub lifecycle_plans: Vec<LifecyclePlanPosture>,
    #[serde(default)]
    pub host_fabric_fulfillment_plans: Vec<HostFabricFulfillmentPlan>,
    #[serde(default)]
    pub host_fabric_legacy_control_bridges: Vec<HostFabricLegacyControlBridge>,
    #[serde(default)]
    pub service_hardening_postures: Vec<ServiceHardeningPostureRecord>,
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
    pub fabric_control_role: Option<String>,
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
    pub contract_target: ContractTarget,
    pub target_registry_posture: ContractTargetRegistryPosture,
    pub host_fabric_contribution: Option<HostFabricMemberContribution>,
    pub lifecycle_plan: LifecyclePlanPosture,
    pub host_fabric_fulfillment_plan: HostFabricFulfillmentPlan,
    pub host_fabric_legacy_control_bridge: HostFabricLegacyControlBridge,
    pub service_hardening_posture: ServiceHardeningPostureRecord,
    pub fabric_control_decision: HostFabricControlDecision,
    pub posture: ServiceManagerPostureRecord,
}

fn default_fabric_ref() -> String {
    DEFAULT_FABRIC_REF.to_string()
}

fn default_host_adapter_ref() -> String {
    DEFAULT_HOST_ADAPTER_REF.to_string()
}

fn default_lifecycle_contract_ref() -> String {
    DEFAULT_LIFECYCLE_CONTRACT_REF.to_string()
}

fn default_fabric_role() -> String {
    FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string()
}

fn default_association_handoff_ref() -> Option<String> {
    Some(DEFAULT_ASSOCIATION_HANDOFF_REF.to_string())
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
        fabric_ref: DEFAULT_FABRIC_REF.to_string(),
        host_adapter_ref: DEFAULT_HOST_ADAPTER_REF.to_string(),
        lifecycle_contract_ref: DEFAULT_LIFECYCLE_CONTRACT_REF.to_string(),
        fabric_role: FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER.to_string(),
        association_handoff_ref: Some(DEFAULT_ASSOCIATION_HANDOFF_REF.to_string()),
        app_contract_ref: Some("app-contract:lab-managed@0.1.0".to_string()),
        version: Some("0.1.0".to_string()),
        build_ref: Some("build:lab-service:current".to_string()),
        content_index_refs: vec!["content-index:source:lab-service".to_string()],
        source_graph_refs: vec!["source:graph:lab-service".to_string()],
        source_snapshot_refs: vec!["source:snapshot:lab-service:current".to_string()],
        source_operation_refs: vec![
            "source:operation:lab-service:ref-update".to_string(),
            "source:operation:lab-service:project-link".to_string(),
        ],
        project_refs: vec!["project:constituency".to_string()],
        work_item_refs: vec!["work-item:service-manager:lifecycle".to_string()],
        build_run_refs: vec!["build:run:lab-service:current".to_string()],
        build_artifact_refs: vec!["build:artifact:lab-service:module".to_string()],
        build_proof_refs: vec!["build-proof:lab-service:current".to_string()],
        release_candidate_refs: vec!["release:candidate:lab-service:current".to_string()],
        release_ref: Some("release:lab-service:current".to_string()),
        rollback_ref: Some("rollback:lab-service:previous".to_string()),
        rollback_required: true,
        compatibility_refs: vec!["protocol:service-manager:v1".to_string()],
        secret_refs: vec!["secret-ref:lab-service:runtime".to_string()],
        access_group_refs: vec!["access-group:ops:service-manager".to_string()],
        authority_refs: vec!["authority:ops-admin".to_string()],
        grant_refs: vec!["grant:service-manager:lab-service".to_string()],
        materialization_budget_refs: vec!["materialization-budget:service-manager".to_string()],
        processor_contract_refs: vec![],
        processor_role_refs: vec![],
        processor_seed_refs: vec![],
        processor_report_refs: vec![],
        resource_profile_ref: "resource-profile:service-manager".to_string(),
        resource_memory_mib: 512,
        resource_cpu_pct: 25,
        retention_refs: vec!["retention:service-manager:90d".to_string()],
    }
}

pub fn cybersec_processor_managed_service_spec() -> ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.service_id = "constitute-cybersec".to_string();
    spec.subject_ref = "subject:cybersec.processor".to_string();
    spec.fabric_role = FABRIC_MEMBER_ROLE_DOMAIN_SERVICE.to_string();
    spec.host_adapter_ref = "contract:domain-service.cybersec@0.1.0".to_string();
    spec.lifecycle_contract_ref = "contract:lifecycle.domain-service@0.1.0".to_string();
    spec.app_contract_ref = Some("app:contract:constitute-cybersec@0.1.0".to_string());
    spec.build_ref = Some("build:constitute-cybersec:processor".to_string());
    spec.content_index_refs = vec!["content-index:source:constitute-cybersec".to_string()];
    spec.source_graph_refs = vec!["source:graph:constitute-cybersec".to_string()];
    spec.source_snapshot_refs = vec!["source:snapshot:constitute-cybersec:current".to_string()];
    spec.source_operation_refs =
        vec!["source:operation:constitute-cybersec:ref-update".to_string()];
    spec.project_refs = vec!["project:constituency:cybersec".to_string()];
    spec.work_item_refs = vec!["work-item:cybersec-processor".to_string()];
    spec.build_run_refs = vec!["build:run:constitute-cybersec:processor".to_string()];
    spec.build_artifact_refs = vec!["build:artifact:constitute-cybersec:processor".to_string()];
    spec.build_proof_refs = vec!["build-proof:constitute-cybersec:processor".to_string()];
    spec.release_candidate_refs =
        vec!["release:candidate:constitute-cybersec:processor".to_string()];
    spec.release_ref = Some("release:constitute-cybersec:processor".to_string());
    spec.rollback_ref = Some("rollback:constitute-cybersec:processor".to_string());
    spec.access_group_refs = vec!["access-group:logging.cybersec.default".to_string()];
    spec.grant_refs = vec!["grant:runner:constitute-cybersec:processor".to_string()];
    spec.materialization_budget_refs =
        vec!["materialization-budget:cybersec.processor".to_string()];
    spec.processor_contract_refs = vec!["processor-contract:logging.cybersec".to_string()];
    spec.processor_role_refs = vec!["role:cybersec.processor".to_string()];
    spec.processor_seed_refs = vec!["cybersec-seed:logging.default".to_string()];
    spec.processor_report_refs = vec!["event-fabric-report:logging.cybersec.bootstrap".to_string()];
    spec.retention_refs = vec!["retention:cybersec:logging.default".to_string()];
    spec
}

pub fn service_manager_host_adapter_managed_service_spec() -> ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.service_id = "constitute-service-manager".to_string();
    spec.subject_ref = "service:service-manager.host-adapter".to_string();
    spec.app_contract_ref = Some("app:contract:constitute-service-manager@0.1.0".to_string());
    spec.build_ref = Some("build:constitute-service-manager:host-adapter".to_string());
    spec.content_index_refs = vec!["content-index:source:constitute-service-manager".to_string()];
    spec.source_graph_refs = vec!["source:graph:constitute-service-manager".to_string()];
    spec.source_snapshot_refs =
        vec!["source:snapshot:constitute-service-manager:current".to_string()];
    spec.source_operation_refs = vec![
        "source:operation:constitute-service-manager:ref-update".to_string(),
        "source:operation:constitute-service-manager:project-link".to_string(),
    ];
    spec.project_refs = vec!["project:constituency:service-manager".to_string()];
    spec.work_item_refs = vec!["work-item:fabric-transition:service-manager".to_string()];
    spec.build_run_refs = vec!["build:run:constitute-service-manager:host-adapter".to_string()];
    spec.build_artifact_refs =
        vec!["build:artifact:constitute-service-manager:host-adapter".to_string()];
    spec.build_proof_refs = vec!["build-proof:constitute-service-manager:host-adapter".to_string()];
    spec.release_candidate_refs =
        vec!["release:candidate:constitute-service-manager:host-adapter".to_string()];
    spec.release_ref = Some("release:constitute-service-manager:host-adapter".to_string());
    spec.rollback_ref = Some("rollback:constitute-service-manager:host-adapter".to_string());
    spec.grant_refs = vec!["grant:service-manager:host-adapter".to_string()];
    spec.retention_refs = vec!["retention:service-manager:host-adapter".to_string()];
    spec
}

pub fn gateway_association_managed_service_spec() -> ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.service_id = "constitute-gateway".to_string();
    spec.subject_ref = "service:gateway.association".to_string();
    spec.fabric_role = FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION.to_string();
    spec.host_adapter_ref = "contract:gateway.association@0.1.0".to_string();
    spec.lifecycle_contract_ref = "contract:lifecycle.gateway-association@0.1.0".to_string();
    spec.app_contract_ref = Some("app:contract:constitute-gateway@0.1.0".to_string());
    spec.build_ref = Some("build:constitute-gateway:association".to_string());
    spec.content_index_refs = vec!["content-index:source:constitute-gateway".to_string()];
    spec.source_graph_refs = vec!["source:graph:constitute-gateway".to_string()];
    spec.source_snapshot_refs = vec!["source:snapshot:constitute-gateway:current".to_string()];
    spec.source_operation_refs = vec![
        "source:operation:constitute-gateway:ref-update".to_string(),
        "source:operation:constitute-gateway:project-link".to_string(),
    ];
    spec.project_refs = vec!["project:constituency:gateway".to_string()];
    spec.work_item_refs = vec!["work-item:fabric-transition:gateway".to_string()];
    spec.build_run_refs = vec!["build:run:constitute-gateway:association".to_string()];
    spec.build_artifact_refs = vec!["build:artifact:constitute-gateway:association".to_string()];
    spec.build_proof_refs = vec!["build-proof:constitute-gateway:association".to_string()];
    spec.release_candidate_refs =
        vec!["release:candidate:constitute-gateway:association".to_string()];
    spec.release_ref = Some("release:constitute-gateway:association".to_string());
    spec.rollback_ref = Some("rollback:constitute-gateway:association".to_string());
    spec.grant_refs = vec!["grant:gateway:association".to_string()];
    spec.retention_refs = vec!["retention:gateway:association".to_string()];
    spec
}

pub fn logging_processor_managed_service_spec() -> ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.service_id = "constitute-logging".to_string();
    spec.subject_ref = "service:logging.processor".to_string();
    spec.fabric_role = FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR.to_string();
    spec.host_adapter_ref = "contract:logging.processor@0.1.0".to_string();
    spec.lifecycle_contract_ref = "contract:lifecycle.logging-processor@0.1.0".to_string();
    spec.app_contract_ref = Some("app:contract:constitute-logging@0.1.0".to_string());
    spec.build_ref = Some("build:constitute-logging:processor".to_string());
    spec.content_index_refs = vec!["content-index:source:constitute-logging".to_string()];
    spec.source_graph_refs = vec!["source:graph:constitute-logging".to_string()];
    spec.source_snapshot_refs = vec!["source:snapshot:constitute-logging:current".to_string()];
    spec.source_operation_refs = vec![
        "source:operation:constitute-logging:ref-update".to_string(),
        "source:operation:constitute-logging:project-link".to_string(),
    ];
    spec.project_refs = vec!["project:constituency:logging".to_string()];
    spec.work_item_refs = vec!["work-item:fabric-transition:logging".to_string()];
    spec.build_run_refs = vec!["build:run:constitute-logging:processor".to_string()];
    spec.build_artifact_refs = vec!["build:artifact:constitute-logging:processor".to_string()];
    spec.build_proof_refs = vec!["build-proof:constitute-logging:processor".to_string()];
    spec.release_candidate_refs =
        vec!["release:candidate:constitute-logging:processor".to_string()];
    spec.release_ref = Some("release:constitute-logging:processor".to_string());
    spec.rollback_ref = Some("rollback:constitute-logging:processor".to_string());
    spec.access_group_refs = vec!["access-group:event-fabric.logging.default".to_string()];
    spec.grant_refs = vec!["grant:logging:processor".to_string()];
    spec.materialization_budget_refs = vec!["materialization-budget:logging.processor".to_string()];
    spec.processor_contract_refs = vec!["processor-contract:logging.default".to_string()];
    spec.processor_role_refs = vec!["role:logging.processor".to_string()];
    spec.processor_seed_refs = vec!["logging-seed:event-fabric.default".to_string()];
    spec.processor_report_refs = vec!["event-fabric-report:logging.default".to_string()];
    spec.retention_refs = vec!["retention:logging:default".to_string()];
    spec
}

pub fn storage_fulfillment_managed_service_spec() -> ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.service_id = "constitute-storage".to_string();
    spec.subject_ref = "service:storage.journal-cache".to_string();
    spec.fabric_role = FABRIC_MEMBER_ROLE_STORAGE_JOURNAL_CACHE.to_string();
    spec.host_adapter_ref = "contract:storage.journal-cache@0.1.0".to_string();
    spec.lifecycle_contract_ref = "contract:lifecycle.storage-journal-cache@0.1.0".to_string();
    spec.app_contract_ref = Some("app:contract:constitute-storage@0.1.0".to_string());
    spec.build_ref = Some("build:constitute-storage:journal-cache".to_string());
    spec.content_index_refs = vec!["content-index:source:constitute-storage".to_string()];
    spec.source_graph_refs = vec!["source:graph:constitute-storage".to_string()];
    spec.source_snapshot_refs = vec!["source:snapshot:constitute-storage:current".to_string()];
    spec.source_operation_refs = vec!["source:operation:constitute-storage:ref-update".to_string()];
    spec.project_refs = vec!["project:constituency:storage".to_string()];
    spec.work_item_refs = vec!["work-item:fabric-transition:storage".to_string()];
    spec.build_run_refs = vec!["build:run:constitute-storage:journal-cache".to_string()];
    spec.build_artifact_refs = vec!["build:artifact:constitute-storage:journal-cache".to_string()];
    spec.build_proof_refs = vec!["build-proof:constitute-storage:journal-cache".to_string()];
    spec.release_candidate_refs =
        vec!["release:candidate:constitute-storage:journal-cache".to_string()];
    spec.release_ref = Some("release:constitute-storage:journal-cache".to_string());
    spec.rollback_ref = Some("rollback:constitute-storage:journal-cache".to_string());
    spec.access_group_refs = vec!["access-group:storage.fabric.default".to_string()];
    spec.grant_refs = vec!["grant:storage:journal-cache".to_string()];
    spec.materialization_budget_refs =
        vec!["materialization-budget:storage.journal-cache".to_string()];
    spec.retention_refs = vec!["retention:storage:journal-cache".to_string()];
    spec
}

pub fn build_processor_managed_service_spec() -> ManagedServiceSpec {
    let mut spec = default_managed_service_spec();
    spec.service_id = "constitute-build".to_string();
    spec.subject_ref = "service:build.processor".to_string();
    spec.fabric_role = FABRIC_MEMBER_ROLE_BUILD_PROCESSOR.to_string();
    spec.host_adapter_ref = "contract:build.processor@0.1.0".to_string();
    spec.lifecycle_contract_ref = "contract:lifecycle.build-processor@0.1.0".to_string();
    spec.app_contract_ref = Some("app:contract:constitute-build@0.1.0".to_string());
    spec.build_ref = Some("build:constitute-build:processor".to_string());
    spec.content_index_refs = vec!["content-index:source:constitute-build".to_string()];
    spec.source_graph_refs = vec!["source:graph:constitute-build".to_string()];
    spec.source_snapshot_refs = vec!["source:snapshot:constitute-build:current".to_string()];
    spec.source_operation_refs = vec!["source:operation:constitute-build:ref-update".to_string()];
    spec.project_refs = vec!["project:constituency:build".to_string()];
    spec.work_item_refs = vec!["work-item:fabric-transition:build".to_string()];
    spec.build_run_refs = vec!["build:run:constitute-build:processor".to_string()];
    spec.build_artifact_refs = vec!["build:artifact:constitute-build:processor".to_string()];
    spec.build_proof_refs = vec!["build-proof:constitute-build:processor".to_string()];
    spec.release_candidate_refs = vec!["release:candidate:constitute-build:processor".to_string()];
    spec.release_ref = Some("release:constitute-build:processor".to_string());
    spec.rollback_ref = Some("rollback:constitute-build:processor".to_string());
    spec.access_group_refs = vec!["access-group:build.fabric.default".to_string()];
    spec.grant_refs = vec!["grant:build:processor".to_string()];
    spec.materialization_budget_refs = vec!["materialization-budget:build.processor".to_string()];
    spec.processor_contract_refs = vec!["processor-contract:build.fulfillment".to_string()];
    spec.processor_role_refs = vec!["role:build.processor".to_string()];
    spec.processor_report_refs = vec!["event-fabric-report:build.processor".to_string()];
    spec.retention_refs = vec!["retention:build:processor".to_string()];
    spec
}

pub fn current_fabric_transition_service_specs() -> Vec<ManagedServiceSpec> {
    vec![
        service_manager_host_adapter_managed_service_spec(),
        gateway_association_managed_service_spec(),
        storage_fulfillment_managed_service_spec(),
        build_processor_managed_service_spec(),
        logging_processor_managed_service_spec(),
        cybersec_processor_managed_service_spec(),
    ]
}

pub fn default_manager_state(issued_at: u64) -> ServiceManagerState {
    ServiceManagerState {
        services: vec![default_managed_service_spec()],
        operations: vec![],
        proof_digests: vec![],
        contract_targets: vec![],
        target_registry_postures: vec![],
        host_fabric_contributions: vec![],
        lifecycle_plans: vec![],
        host_fabric_fulfillment_plans: vec![],
        host_fabric_legacy_control_bridges: vec![],
        service_hardening_postures: vec![],
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

fn release_contract_blockers_for_spec(spec: &ManagedServiceSpec) -> Vec<String> {
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
    if spec.source_operation_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingSourceOperationRefs".to_string());
    }
    if spec.build_run_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingBuildRunRefs".to_string());
    }
    if spec.build_artifact_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingBuildArtifactRefs".to_string());
    }
    if spec.build_proof_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingBuildProofRefs".to_string());
    }
    if spec.release_candidate_refs.is_empty() {
        blocked_reasons.push("releaseContract:missingReleaseCandidateRefs".to_string());
    }
    normalize_blockers(blocked_reasons)
}

fn release_ready_for_spec(spec: &ManagedServiceSpec) -> bool {
    release_contract_blockers_for_spec(spec).is_empty()
}

pub fn build_release_contract_for_spec(
    spec: &ManagedServiceSpec,
    issued_at: u64,
    proof_digest_refs: Vec<String>,
    lab_proof_refs: Vec<String>,
) -> ServiceManagerReleaseContractRecord {
    let blocked_reasons = release_contract_blockers_for_spec(spec);
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
        content_index_refs: spec.content_index_refs.clone(),
        source_graph_refs: spec.source_graph_refs.clone(),
        source_snapshot_refs: spec.source_snapshot_refs.clone(),
        source_operation_refs: spec.source_operation_refs.clone(),
        project_refs: spec.project_refs.clone(),
        work_item_refs: spec.work_item_refs.clone(),
        build_run_refs: spec.build_run_refs.clone(),
        build_artifact_refs: spec.build_artifact_refs.clone(),
        build_proof_refs: spec.build_proof_refs.clone(),
        release_candidate_refs: spec.release_candidate_refs.clone(),
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
            "version": spec.version,
            "contentIndexRefs": spec.content_index_refs,
            "sourceGraphRefs": spec.source_graph_refs,
            "sourceSnapshotRefs": spec.source_snapshot_refs,
            "sourceOperationRefs": spec.source_operation_refs,
            "projectRefs": spec.project_refs,
            "workItemRefs": spec.work_item_refs,
            "buildRunRefs": spec.build_run_refs,
            "buildArtifactRefs": spec.build_artifact_refs,
            "buildProofRefs": spec.build_proof_refs,
            "releaseCandidateRefs": spec.release_candidate_refs
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
            "state": if release_ready_for_spec(spec) { "releaseReady" } else { "blocked" },
            "buildRef": spec.build_ref,
            "contentIndexRefs": spec.content_index_refs,
            "sourceGraphRefs": spec.source_graph_refs,
            "sourceSnapshotRefs": spec.source_snapshot_refs,
            "sourceOperationRefs": spec.source_operation_refs,
            "projectRefs": spec.project_refs,
            "workItemRefs": spec.work_item_refs,
            "buildRunRefs": spec.build_run_refs,
            "buildArtifactRefs": spec.build_artifact_refs,
            "buildProofRefs": spec.build_proof_refs,
            "releaseCandidateRefs": spec.release_candidate_refs,
            "releaseRef": spec.release_ref,
            "rollbackRef": spec.rollback_ref,
            "blockedReasons": release_contract_blockers_for_spec(spec)
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

fn host_fabric_contribution_id(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
) -> String {
    format!(
        "fabric-contribution:{}:{}",
        spec.service_id, operation.operation_id
    )
}

fn lifecycle_plan_id(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
) -> String {
    format!(
        "lifecycle-plan:{}:{}",
        spec.service_id, operation.operation_id
    )
}

fn host_fabric_fulfillment_plan_id(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
) -> String {
    format!("fabric-plan:{}:{}", spec.service_id, operation.operation_id)
}

fn host_fabric_contract_blockers(spec: &ManagedServiceSpec) -> Vec<String> {
    let mut blocked_reasons = Vec::new();
    if spec.fabric_ref.trim().is_empty() {
        blocked_reasons.push("fabricRef:missing".to_string());
    }
    if spec.fabric_role.trim().is_empty() {
        blocked_reasons.push("fabricRole:missing".to_string());
    }
    if spec.host_ref.as_deref().unwrap_or_default().is_empty() {
        blocked_reasons.push("hostRef:missing".to_string());
    }
    if spec.runner_ref.as_deref().unwrap_or_default().is_empty() {
        blocked_reasons.push("memberRef:missing".to_string());
    }
    if spec.host_adapter_ref.trim().is_empty() {
        blocked_reasons.push("hostAdapterRef:missing".to_string());
    }
    if spec.lifecycle_contract_ref.trim().is_empty() {
        blocked_reasons.push("lifecycleContractRef:missing".to_string());
    }
    blocked_reasons
}

fn contract_target_ref(spec: &ManagedServiceSpec) -> String {
    format!("contract-target:{}", spec.service_id)
}

fn contract_target_registry_ref(spec: &ManagedServiceSpec) -> String {
    format!("contract-target-registry:{}", spec.service_id)
}

fn contract_target_contract_ref(spec: &ManagedServiceSpec) -> String {
    spec.app_contract_ref
        .clone()
        .unwrap_or_else(|| spec.host_adapter_ref.clone())
}

fn optional_ref(value: &Option<String>) -> Vec<String> {
    value
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .into_iter()
        .collect()
}

fn source_input_refs(spec: &ManagedServiceSpec) -> Vec<String> {
    let mut refs = optional_ref(&spec.app_contract_ref);
    refs.extend(spec.source_graph_refs.clone());
    refs.extend(spec.source_snapshot_refs.clone());
    refs.extend(spec.content_index_refs.clone());
    refs.extend(spec.source_operation_refs.clone());
    refs
}

fn host_fabric_module_refs(spec: &ManagedServiceSpec) -> Vec<String> {
    let mut refs = vec![
        spec.host_adapter_ref.clone(),
        spec.lifecycle_contract_ref.clone(),
    ];
    refs.extend(optional_ref(&spec.app_contract_ref));
    refs.extend(spec.build_artifact_refs.clone());
    refs.extend(spec.processor_contract_refs.clone());
    refs.sort();
    refs.dedup();
    refs
}

fn build_input_refs(spec: &ManagedServiceSpec) -> Vec<String> {
    let mut refs = optional_ref(&spec.build_ref);
    refs.extend(spec.build_run_refs.clone());
    refs.extend(spec.build_artifact_refs.clone());
    refs.extend(spec.build_proof_refs.clone());
    refs.extend(spec.release_candidate_refs.clone());
    refs
}

fn project_input_refs(spec: &ManagedServiceSpec) -> Vec<String> {
    let mut refs = spec.project_refs.clone();
    refs.extend(spec.work_item_refs.clone());
    refs
}

fn processor_input_refs(spec: &ManagedServiceSpec) -> Vec<String> {
    let mut refs = spec.processor_contract_refs.clone();
    refs.extend(spec.processor_role_refs.clone());
    refs.extend(spec.processor_seed_refs.clone());
    refs.extend(spec.processor_report_refs.clone());
    refs
}

fn processor_required(spec: &ManagedServiceSpec) -> bool {
    !processor_input_refs(spec).is_empty()
}

fn first_ref(values: &[String]) -> Option<String> {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
}

fn lifecycle_input_refs(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
) -> Vec<String> {
    let mut refs = vec![operation.operation_id.clone()];
    refs.extend(source_input_refs(spec));
    refs.extend(build_input_refs(spec));
    refs.extend(optional_ref(&spec.release_ref));
    refs.extend(optional_ref(&spec.rollback_ref));
    refs.extend(project_input_refs(spec));
    refs.extend(processor_input_refs(spec));
    refs
}

fn contract_target_capability_slot_refs(spec: &ManagedServiceSpec, operation: &str) -> Vec<String> {
    let mut refs = vec![
        "slot:host-service-adapter".to_string(),
        "slot:lifecycle-contract".to_string(),
        "slot:source".to_string(),
        "slot:content-index".to_string(),
        "slot:source-graph".to_string(),
        "slot:source-operation".to_string(),
        "slot:build".to_string(),
        "slot:build-run".to_string(),
        "slot:build-artifact".to_string(),
        "slot:build-proof".to_string(),
        "slot:release-candidate".to_string(),
        "slot:project-work".to_string(),
        "slot:release".to_string(),
        "slot:runner".to_string(),
    ];
    if processor_required(spec) {
        refs.extend([
            "slot:processor-contract".to_string(),
            "slot:processor-role".to_string(),
            "slot:processor-seed".to_string(),
            "slot:processor-report".to_string(),
        ]);
    }
    if rollback_required_for(operation) && spec.rollback_required {
        refs.push("slot:rollback".to_string());
    }
    refs
}

fn contract_target_missing_slot_refs(spec: &ManagedServiceSpec, operation: &str) -> Vec<String> {
    let mut refs = Vec::new();
    if spec.host_ref.as_deref().unwrap_or_default().is_empty() {
        refs.push("slot:host".to_string());
    }
    if spec.host_adapter_ref.trim().is_empty() {
        refs.push("slot:host-service-adapter".to_string());
    }
    if spec.lifecycle_contract_ref.trim().is_empty() {
        refs.push("slot:lifecycle-contract".to_string());
    }
    if spec.app_contract_ref.is_none() {
        refs.push("slot:source".to_string());
    }
    if spec.source_graph_refs.is_empty() {
        refs.push("slot:source-graph".to_string());
    }
    if spec.source_operation_refs.is_empty() {
        refs.push("slot:source-operation".to_string());
    }
    if spec.content_index_refs.is_empty() {
        refs.push("slot:content-index".to_string());
    }
    if spec.build_ref.is_none() {
        refs.push("slot:build".to_string());
    }
    if spec.build_run_refs.is_empty() {
        refs.push("slot:build-run".to_string());
    }
    if spec.build_artifact_refs.is_empty() {
        refs.push("slot:build-artifact".to_string());
    }
    if spec.build_proof_refs.is_empty() {
        refs.push("slot:build-proof".to_string());
    }
    if spec.release_candidate_refs.is_empty() {
        refs.push("slot:release-candidate".to_string());
    }
    if spec.project_refs.is_empty() && spec.work_item_refs.is_empty() {
        refs.push("slot:project-work".to_string());
    }
    if spec.release_ref.is_none() {
        refs.push("slot:release".to_string());
    }
    if spec.runner_ref.as_deref().unwrap_or_default().is_empty() {
        refs.push("slot:runner".to_string());
    }
    if processor_required(spec) {
        if spec.processor_contract_refs.is_empty() {
            refs.push("slot:processor-contract".to_string());
        }
        if spec.processor_role_refs.is_empty() {
            refs.push("slot:processor-role".to_string());
        }
        if spec.processor_seed_refs.is_empty() {
            refs.push("slot:processor-seed".to_string());
        }
        if spec.processor_report_refs.is_empty() {
            refs.push("slot:processor-report".to_string());
        }
    }
    if rollback_required_for(operation) && spec.rollback_required && spec.rollback_ref.is_none() {
        refs.push("slot:rollback".to_string());
    }
    normalize_blockers(refs)
}

pub fn build_contract_target_for_spec(
    spec: &ManagedServiceSpec,
    operation: &str,
    issued_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ContractTarget> {
    let missing_slot_refs = contract_target_missing_slot_refs(spec, operation);
    let mut blocked_reasons = blocked_reasons;
    for slot_ref in &missing_slot_refs {
        blocked_reasons.push(format!("targetSlot:missing:{slot_ref}"));
    }
    let blocked_reasons = normalize_blockers(blocked_reasons);
    let blocked = !blocked_reasons.is_empty() || !missing_slot_refs.is_empty();
    let target = ContractTarget {
        kind: Some(RECORD_CONTRACT_TARGET.to_string()),
        target_ref: contract_target_ref(spec),
        contract_ref: contract_target_contract_ref(spec),
        profile_ref: spec
            .host_ref
            .clone()
            .map(|host| format!("host-profile:{host}"))
            .unwrap_or_else(|| "host-profile:unresolved".to_string()),
        platform_ref: "platform:host-service".to_string(),
        state: if blocked {
            FABRIC_CONTRACT_TARGET_BLOCKED
        } else {
            FABRIC_CONTRACT_TARGET_READY
        }
        .to_string(),
        compatibility_state: if blocked {
            FABRIC_CONTRACT_TARGET_INCOMPATIBLE
        } else {
            FABRIC_CONTRACT_TARGET_COMPATIBLE
        }
        .to_string(),
        host_ref: spec.host_ref.clone(),
        substrate_ref: Some("substrate:host-service".to_string()),
        modifier_refs: vec!["modifier:service-manager".to_string()],
        branch_refs: Vec::new(),
        subbranch_refs: Vec::new(),
        capability_slot_refs: contract_target_capability_slot_refs(spec, operation),
        adapter_pack_ref: Some("adapter-pack:host-service".to_string()),
        adapter_refs: if spec.host_adapter_ref.trim().is_empty() {
            Vec::new()
        } else {
            vec![spec.host_adapter_ref.clone()]
        },
        negative_slot_refs: Vec::new(),
        missing_slot_refs,
        degraded_slot_refs: Vec::new(),
        proof_profile_refs: vec!["proof-profile:service-manager:lifecycle".to_string()],
        proof_refs: Vec::new(),
        compatibility_refs: spec.compatibility_refs.clone(),
        evidence_refs: vec![format!("evidence:contract-target:{}", spec.service_id)],
        blocked_reasons,
        target_audience: "operator".to_string(),
        safe_facts: json!({
            "serviceId": spec.service_id,
            "operation": operation,
            "processorInputRefs": processor_input_refs(spec)
        }),
        issued_at,
        expires_at: Some(issued_at + 3600),
    };
    validate_contract_target(&target)?;
    Ok(target)
}

fn normalize_blockers(mut blocked_reasons: Vec<String>) -> Vec<String> {
    blocked_reasons.sort();
    blocked_reasons.dedup();
    blocked_reasons
}

pub fn build_host_fabric_member_contribution_for_spec(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<Option<HostFabricMemberContribution>> {
    let member_ref = match spec.runner_ref.as_deref().filter(|value| !value.is_empty()) {
        Some(member_ref) => member_ref.to_string(),
        None => return Ok(None),
    };
    let mut blocked_reasons = blocked_reasons;
    blocked_reasons.extend(host_fabric_contract_blockers(spec));
    let blocked_reasons = normalize_blockers(blocked_reasons);
    let state = if blocked_reasons.is_empty() {
        FABRIC_MEMBER_CONTRIBUTION_RUNNING
    } else {
        FABRIC_MEMBER_CONTRIBUTION_BLOCKED
    };
    let contribution = HostFabricMemberContribution {
        kind: Some(RECORD_HOST_FABRIC_MEMBER_CONTRIBUTION.to_string()),
        contribution_id: host_fabric_contribution_id(spec, operation),
        fabric_ref: spec.fabric_ref.clone(),
        host_ref: spec.host_ref.clone().unwrap_or_default(),
        member_ref,
        participant_ref: spec.manager_ref.clone(),
        role: fabric_role_for_spec(spec).to_string(),
        role_ref: fabric_role_ref_for_spec(spec),
        state: state.to_string(),
        contract_ref: spec.host_adapter_ref.clone(),
        subject_ref: spec.subject_ref.clone(),
        module_refs: host_fabric_module_refs(spec),
        source_refs: source_input_refs(spec),
        capability_refs: vec![constitute_protocol::CAPABILITY_SERVICE_MANAGE.to_string()],
        grant_refs: spec.grant_refs.clone(),
        input_refs: lifecycle_input_refs(spec, operation),
        output_refs: vec![format!("output:service-manager:{}", operation.operation_id)],
        evidence_refs: operation.evidence_refs.clone(),
        lifecycle_plan_refs: vec![lifecycle_plan_id(spec, operation)],
        release_refs: spec.release_ref.clone().into_iter().collect(),
        resource_posture: operation.resource_posture.clone(),
        blocked_reasons,
        safe_facts: json!({
            "role": fabric_role_for_spec(spec),
            "operation": operation.operation,
            "serviceId": spec.service_id,
            "sourceInputRefs": source_input_refs(spec),
            "buildInputRefs": build_input_refs(spec),
            "projectInputRefs": project_input_refs(spec),
            "processorInputRefs": processor_input_refs(spec)
        }),
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_host_fabric_member_contribution(&contribution)?;
    Ok(Some(contribution))
}

fn lifecycle_phase(
    phase: &str,
    state: &str,
    evidence_ref: String,
    output_refs: Vec<String>,
    blocked_reasons: Vec<String>,
) -> LifecyclePhasePosture {
    LifecyclePhasePosture {
        phase: phase.to_string(),
        state: state.to_string(),
        evidence_refs: vec![evidence_ref],
        output_refs,
        blocked_reasons,
        safe_facts: json!({ "phase": phase, "state": state }),
    }
}

pub fn build_lifecycle_plan_for_spec(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
    member_contribution_refs: Vec<String>,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<LifecyclePlanPosture> {
    let mut blocked_reasons = blocked_reasons;
    blocked_reasons.extend(host_fabric_contract_blockers(spec));
    if member_contribution_refs.is_empty() {
        blocked_reasons.push("hostFabric:missingMemberContribution".to_string());
    }
    let blocked_reasons = normalize_blockers(blocked_reasons);
    let plan_state = if blocked_reasons.is_empty() {
        FABRIC_LIFECYCLE_PLAN_READY
    } else {
        FABRIC_LIFECYCLE_PLAN_BLOCKED
    };
    let build_blockers = if spec.build_ref.is_some() {
        vec![]
    } else {
        vec!["buildRef:missing".to_string()]
    };
    let mut release_blockers = Vec::new();
    if spec.release_ref.is_none() {
        release_blockers.push("releaseRef:missing".to_string());
    }
    if spec.release_candidate_refs.is_empty() {
        release_blockers.push("releaseCandidateRefs:missing".to_string());
    }
    let rollback_blockers = if rollback_required_for(&operation.operation)
        && spec.rollback_required
        && spec.rollback_ref.is_none()
    {
        vec!["rollbackRequired".to_string()]
    } else {
        vec![]
    };
    let run_state = if matches!(
        operation.operation.as_str(),
        SERVICE_MANAGER_OPERATION_START
            | SERVICE_MANAGER_OPERATION_RESTART
            | SERVICE_MANAGER_OPERATION_HEALTH_CHECK
            | SERVICE_MANAGER_OPERATION_PROMOTE
    ) && operation.state == SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED
    {
        FABRIC_LIFECYCLE_PHASE_RUNNING
    } else if operation.operation == SERVICE_MANAGER_OPERATION_STOP {
        FABRIC_LIFECYCLE_PHASE_NOT_REQUIRED
    } else {
        FABRIC_LIFECYCLE_PHASE_READY
    };
    let phases = vec![
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_SOURCE,
            FABRIC_LIFECYCLE_PHASE_READY,
            format!("evidence:source:{}", spec.service_id),
            source_input_refs(spec),
            vec![],
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_BUILD,
            if build_blockers.is_empty() {
                FABRIC_LIFECYCLE_PHASE_READY
            } else {
                FABRIC_LIFECYCLE_PHASE_BLOCKED
            },
            format!("evidence:build:{}", spec.service_id),
            build_input_refs(spec),
            build_blockers,
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_RELEASE,
            if release_blockers.is_empty() {
                FABRIC_LIFECYCLE_PHASE_READY
            } else {
                FABRIC_LIFECYCLE_PHASE_BLOCKED
            },
            format!("evidence:release:{}", spec.service_id),
            {
                let mut refs = optional_ref(&spec.release_ref);
                refs.extend(spec.release_candidate_refs.clone());
                refs
            },
            release_blockers,
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_LOAD,
            FABRIC_LIFECYCLE_PHASE_SUCCEEDED,
            format!("evidence:load:{}", spec.service_id),
            vec![operation.operation_id.clone()],
            vec![],
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_RUN,
            run_state,
            format!("evidence:run:{}", spec.service_id),
            {
                let mut refs = vec![operation.operation_id.clone()];
                refs.extend(processor_input_refs(spec));
                refs
            },
            vec![],
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_OBSERVE,
            FABRIC_LIFECYCLE_PHASE_READY,
            format!("evidence:observe:{}", spec.service_id),
            operation.evidence_refs.clone(),
            vec![],
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_ROLLBACK,
            if rollback_blockers.is_empty() {
                FABRIC_LIFECYCLE_PHASE_READY
            } else {
                FABRIC_LIFECYCLE_PHASE_BLOCKED
            },
            format!("evidence:rollback:{}", spec.service_id),
            spec.rollback_ref.clone().into_iter().collect(),
            rollback_blockers,
        ),
        lifecycle_phase(
            FABRIC_LIFECYCLE_PHASE_CLEANUP,
            FABRIC_LIFECYCLE_PHASE_NOT_REQUIRED,
            format!("evidence:cleanup:{}", spec.service_id),
            vec![],
            vec![],
        ),
    ];
    let lifecycle = LifecyclePlanPosture {
        kind: Some(RECORD_LIFECYCLE_PLAN_POSTURE.to_string()),
        lifecycle_plan_id: lifecycle_plan_id(spec, operation),
        subject_ref: spec.subject_ref.clone(),
        contract_ref: spec.lifecycle_contract_ref.clone(),
        state: plan_state.to_string(),
        lifecycle_contract_refs: vec![spec.lifecycle_contract_ref.clone()],
        phase_postures: phases,
        member_contribution_refs,
        evidence_refs: {
            let mut refs = vec![format!("evidence:lifecycle-plan:{}", spec.service_id)];
            refs.extend(spec.build_proof_refs.clone());
            refs
        },
        release_refs: spec.release_ref.clone().into_iter().collect(),
        blocked_reasons,
        safe_facts: json!({
            "serviceId": spec.service_id,
            "operation": operation.operation,
            "state": plan_state,
            "sourceInputRefs": source_input_refs(spec),
            "buildInputRefs": build_input_refs(spec),
            "projectInputRefs": project_input_refs(spec),
            "processorInputRefs": processor_input_refs(spec)
        }),
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_lifecycle_plan_posture(&lifecycle)?;
    Ok(lifecycle)
}

fn target_slot_posture(
    slot_ref: &str,
    state: &str,
    platform_fit_state: &str,
    candidate_fulfillment_refs: Vec<String>,
    selected_fulfillment_ref: Option<String>,
    evidence_refs: Vec<String>,
    blocked_reasons: Vec<String>,
) -> ContractTargetSlotPosture {
    ContractTargetSlotPosture {
        slot_ref: slot_ref.to_string(),
        state: state.to_string(),
        platform_fit_state: platform_fit_state.to_string(),
        candidate_fulfillment_refs,
        selected_fulfillment_ref,
        source_refs: Vec::new(),
        build_refs: Vec::new(),
        platform_refs: vec!["platform:host-service".to_string()],
        adapter_refs: Vec::new(),
        proof_requirement_refs: Vec::new(),
        proof_refs: Vec::new(),
        evidence_refs,
        blocked_reasons,
        safe_facts: json!({ "slot": slot_ref, "state": state }),
    }
}

fn refs(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[allow(clippy::too_many_arguments)]
fn lab_target_slot(
    slot_ref: &str,
    state: &str,
    platform_fit_state: &str,
    candidate_fulfillment_refs: Vec<String>,
    selected_fulfillment_ref: Option<&str>,
    source_refs: Vec<String>,
    build_refs: Vec<String>,
    platform_refs: Vec<String>,
    adapter_refs: Vec<String>,
    proof_requirement_refs: Vec<String>,
    proof_refs: Vec<String>,
    evidence_refs: Vec<String>,
    blocked_reasons: Vec<String>,
    safe_facts: Value,
) -> ContractTargetSlotPosture {
    ContractTargetSlotPosture {
        slot_ref: slot_ref.to_string(),
        state: state.to_string(),
        platform_fit_state: platform_fit_state.to_string(),
        candidate_fulfillment_refs,
        selected_fulfillment_ref: selected_fulfillment_ref.map(str::to_string),
        source_refs,
        build_refs,
        platform_refs,
        adapter_refs,
        proof_requirement_refs,
        proof_refs,
        evidence_refs,
        blocked_reasons,
        safe_facts,
    }
}

pub fn lab_linux_target_fixture(issued_at: u64) -> Result<LabLinuxTargetFixture> {
    let release_contract = build_release_contract_with_refs(
        issued_at,
        vec![],
        vec!["lab-proof:service-manager:lab-linux-protected".to_string()],
    );
    let protected_lab_proof = build_lab_proof_with_train(
        "lab-proof:service-manager:lab-linux-protected",
        "train:lab-linux:protected-target",
        &release_contract,
        SERVICE_MANAGER_PROOF_STATE_BLOCKED,
        issued_at + 300,
        vec!["blocked:lab-proof-protected-manual".to_string()],
    )?;
    let missing_slot_refs = refs(&[
        "slot:runtime-client",
        "slot:nvr-surface",
        "slot:lab-proof-automation",
    ]);
    let degraded_slot_refs = refs(&["slot:rollback"]);
    let negative_slot_refs = refs(&["slot:browser-webrtc"]);
    let target = ContractTarget {
        kind: Some(RECORD_CONTRACT_TARGET.to_string()),
        target_ref: "contract-target:home-linux-lab:msa-transition".to_string(),
        contract_ref: "app:contract:constitute-nvr@0.1.0".to_string(),
        profile_ref: "host-profile:home".to_string(),
        platform_ref: "platform:linux.lab".to_string(),
        state: FABRIC_CONTRACT_TARGET_SELECTED.to_string(),
        compatibility_state: FABRIC_CONTRACT_TARGET_COMPATIBILITY_DEGRADED.to_string(),
        host_ref: Some("host:lab-gateway".to_string()),
        substrate_ref: Some("substrate:home-dev".to_string()),
        modifier_refs: refs(&["modifier:home", "modifier:dev"]),
        branch_refs: refs(&["branch:0x/msa-transition"]),
        subbranch_refs: refs(&["subbranch:target-contract"]),
        capability_slot_refs: refs(&[
            "slot:gateway",
            "slot:storage",
            "slot:service-manager",
            "slot:nvr-service",
            "slot:runtime-client",
            "slot:nvr-surface",
            "slot:browser-webrtc",
            "slot:rollback",
            "slot:lab-proof-automation",
        ]),
        adapter_pack_ref: Some("adapter-pack:linux-lab-dev".to_string()),
        adapter_refs: refs(&[
            "adapter:host-service:linux",
            "adapter:gateway:linux",
            "adapter:storage:local",
        ]),
        negative_slot_refs,
        missing_slot_refs,
        degraded_slot_refs,
        proof_profile_refs: refs(&[
            "proof-profile:service-manager-lab",
            "proof-profile:gateway-native-smoke",
            "proof-profile:nvr-smoke-5s",
        ]),
        proof_refs: refs(&["proof:service-manager-cargo-test:20260522"]),
        compatibility_refs: refs(&["compat:runtime-2.56", "compat:branch-family:msa-transition"]),
        evidence_refs: refs(&[
            "evidence:lab-target:service-manager-fixture",
            "evidence:service-manager:target-reducer",
            "lab-proof:service-manager:lab-linux-protected",
        ]),
        blocked_reasons: vec![],
        target_audience: "developer".to_string(),
        safe_facts: json!({
            "profile": "home-dev",
            "platform": "linux.lab",
            "proofAutomation": "manualProtected"
        }),
        issued_at,
        expires_at: Some(issued_at + 86_400),
    };
    validate_contract_target(&target)?;

    let slot_postures = vec![
        lab_target_slot(
            "slot:gateway",
            FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_COMPATIBLE,
            refs(&["fulfillment:gateway:lab-dev"]),
            Some("fulfillment:gateway:lab-dev"),
            vec![],
            vec![],
            refs(&["platform:linux.lab"]),
            refs(&["adapter:gateway:linux"]),
            vec![],
            vec![],
            refs(&["evidence:gateway:lab:configured"]),
            vec![],
            json!({ "role": "gateway" }),
        ),
        lab_target_slot(
            "slot:storage",
            FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_COMPATIBLE,
            refs(&["fulfillment:storage:lab-local"]),
            Some("fulfillment:storage:lab-local"),
            vec![],
            vec![],
            refs(&["platform:linux.lab"]),
            refs(&["adapter:storage:local"]),
            refs(&["proof-requirement:storage-availability"]),
            vec![],
            refs(&["evidence:storage:lab:configured"]),
            vec![],
            json!({ "role": "storage" }),
        ),
        lab_target_slot(
            "slot:service-manager",
            FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_COMPATIBLE,
            refs(&["fulfillment:service-manager:lab"]),
            Some("fulfillment:service-manager:lab"),
            vec![],
            refs(&["build:lab:service-manager"]),
            refs(&["platform:linux.lab"]),
            refs(&["adapter:host-service:linux"]),
            vec![],
            refs(&["proof:service-manager-cargo-test:20260522"]),
            refs(&["evidence:service-manager:target-reducer"]),
            vec![],
            json!({ "role": "service-manager" }),
        ),
        lab_target_slot(
            "slot:nvr-service",
            FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_COMPATIBLE,
            refs(&["fulfillment:nvr-service:lab-network"]),
            Some("fulfillment:nvr-service:lab-network"),
            vec![],
            refs(&["build:lab:nvr-service"]),
            refs(&["platform:linux.lab"]),
            vec![],
            refs(&["proof-requirement:nvr-service-live"]),
            vec![],
            refs(&["evidence:nvr-service:lab:configured"]),
            vec![],
            json!({ "role": "nvr-service" }),
        ),
        lab_target_slot(
            "slot:runtime-client",
            FABRIC_CONTRACT_TARGET_SLOT_MISSING,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN,
            vec![],
            None,
            refs(&["content-index:runtime-surface-client"]),
            vec![],
            vec![],
            vec![],
            refs(&["proof-requirement:client-target-selected"]),
            vec![],
            refs(&["evidence:runtime-client:client-target-unselected"]),
            refs(&["blocked:lab-client-target-unselected"]),
            json!({ "reason": "lab host target does not include a proved local client" }),
        ),
        lab_target_slot(
            "slot:nvr-surface",
            FABRIC_CONTRACT_TARGET_SLOT_MISSING,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN,
            vec![],
            None,
            refs(&["content-index:nvr-surface"]),
            vec![],
            vec![],
            vec![],
            refs(&["proof-requirement:surface-load"]),
            vec![],
            refs(&["evidence:nvr-surface:client-target-unselected"]),
            refs(&["blocked:lab-client-target-unselected"]),
            json!({ "reason": "surface proof belongs to a client target" }),
        ),
        lab_target_slot(
            "slot:browser-webrtc",
            FABRIC_CONTRACT_TARGET_SLOT_NOT_REQUIRED,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN,
            vec![],
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            refs(&["evidence:target:browser-webrtc:not-host-slot"]),
            vec![],
            json!({ "reason": "lab host target" }),
        ),
        lab_target_slot(
            "slot:rollback",
            FABRIC_CONTRACT_TARGET_SLOT_DEGRADED,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_DEGRADED,
            refs(&["fulfillment:rollback:manual"]),
            Some("fulfillment:rollback:manual"),
            vec![],
            vec![],
            refs(&["platform:linux.lab"]),
            vec![],
            refs(&["proof-requirement:rollback-automation"]),
            vec![],
            refs(&["evidence:rollback:manual"]),
            vec![],
            json!({ "reason": "manual rollback only" }),
        ),
        lab_target_slot(
            "slot:lab-proof-automation",
            FABRIC_CONTRACT_TARGET_SLOT_MISSING,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN,
            vec![],
            None,
            vec![],
            vec![],
            refs(&["platform:linux.lab"]),
            vec![],
            refs(&[
                "proof-requirement:bootstrap",
                "proof-requirement:secrets",
                "proof-requirement:rollback",
                "proof-requirement:lab-live",
            ]),
            vec![],
            refs(&["lab-proof:service-manager:lab-linux-protected"]),
            refs(&["blocked:lab-proof-protected-manual"]),
            json!({ "reason": "lab proof remains protected until bootstrap, secrets, and rollback contracts automate it" }),
        ),
    ];
    let registry = ContractTargetRegistryPosture {
        kind: Some(RECORD_CONTRACT_TARGET_REGISTRY_POSTURE.to_string()),
        registry_ref: "contract-target-registry:home-linux-lab:msa-transition".to_string(),
        target_ref: target.target_ref.clone(),
        contract_ref: target.contract_ref.clone(),
        state: FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED.to_string(),
        candidate_fulfillment_refs: slot_postures
            .iter()
            .flat_map(|slot| slot.candidate_fulfillment_refs.clone())
            .collect(),
        source_refs: refs(&[
            "content-index:nvr-surface",
            "content-index:runtime-surface-client",
        ]),
        build_refs: refs(&[
            "build:lab:gateway",
            "build:lab:service-manager",
            "build:lab:nvr-service",
        ]),
        adapter_refs: target.adapter_refs.clone(),
        proof_requirement_refs: refs(&[
            "proof-requirement:bootstrap",
            "proof-requirement:secrets",
            "proof-requirement:rollback",
            "proof-requirement:lab-live",
            "proof-requirement:client-target-selected",
        ]),
        proof_refs: target.proof_refs.clone(),
        evidence_refs: target.evidence_refs.clone(),
        blocked_reasons: vec![],
        safe_facts: target.safe_facts.clone(),
        slot_postures,
        observed_at: issued_at,
        expires_at: Some(issued_at + 86_400),
    };
    validate_contract_target_registry_posture(&registry)?;
    Ok(LabLinuxTargetFixture {
        target,
        registry,
        release_contract,
        protected_lab_proof,
    })
}

fn target_slot_from_optional_ref(
    slot_ref: &str,
    candidate_ref: Option<String>,
    evidence_ref: String,
) -> ContractTargetSlotPosture {
    match candidate_ref.filter(|value| !value.trim().is_empty()) {
        Some(candidate_ref) => target_slot_posture(
            slot_ref,
            FABRIC_CONTRACT_TARGET_SLOT_AVAILABLE,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_COMPATIBLE,
            vec![candidate_ref.clone()],
            Some(candidate_ref),
            vec![evidence_ref],
            vec![],
        ),
        None => target_slot_posture(
            slot_ref,
            FABRIC_CONTRACT_TARGET_SLOT_MISSING,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN,
            Vec::new(),
            None,
            vec![evidence_ref],
            vec![format!("targetSlot:missing:{slot_ref}")],
        ),
    }
}

pub fn build_contract_target_registry_posture_for_spec(
    spec: &ManagedServiceSpec,
    target: &ContractTarget,
    operation: &ServiceManagerOperationPostureRecord,
    host_fabric_contribution: Option<&HostFabricMemberContribution>,
    lifecycle_plan: Option<&LifecyclePlanPosture>,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ContractTargetRegistryPosture> {
    validate_contract_target(target)?;
    let mut slot_postures = Vec::new();
    slot_postures.push(target_slot_from_optional_ref(
        "slot:host-service-adapter",
        host_fabric_contribution
            .map(|contribution| contribution.contribution_id.clone())
            .or_else(|| {
                (!spec.host_adapter_ref.trim().is_empty()).then(|| spec.host_adapter_ref.clone())
            }),
        format!("evidence:host-service-adapter:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:lifecycle-contract",
        lifecycle_plan
            .map(|plan| plan.lifecycle_plan_id.clone())
            .or_else(|| {
                (!spec.lifecycle_contract_ref.trim().is_empty())
                    .then(|| spec.lifecycle_contract_ref.clone())
            }),
        format!("evidence:lifecycle-contract:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:source",
        spec.app_contract_ref.clone(),
        format!("evidence:source:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:source-graph",
        first_ref(&spec.source_graph_refs),
        format!("evidence:source-graph:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:source-operation",
        first_ref(&spec.source_operation_refs),
        format!("evidence:source-operation:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:content-index",
        first_ref(&spec.content_index_refs),
        format!("evidence:content-index:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:build",
        spec.build_ref.clone(),
        format!("evidence:build:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:build-run",
        first_ref(&spec.build_run_refs),
        format!("evidence:build-run:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:build-artifact",
        first_ref(&spec.build_artifact_refs),
        format!("evidence:build-artifact:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:build-proof",
        first_ref(&spec.build_proof_refs),
        format!("evidence:build-proof:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:release-candidate",
        first_ref(&spec.release_candidate_refs),
        format!("evidence:release-candidate:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:project-work",
        first_ref(&project_input_refs(spec)),
        format!("evidence:project-work:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:release",
        spec.release_ref.clone(),
        format!("evidence:release:{}", spec.service_id),
    ));
    slot_postures.push(target_slot_from_optional_ref(
        "slot:runner",
        spec.runner_ref
            .as_ref()
            .filter(|runner_ref| !runner_ref.trim().is_empty())
            .map(|runner_ref| format!("member:{runner_ref}")),
        format!("evidence:runner:{}", spec.service_id),
    ));
    if processor_required(spec) {
        slot_postures.push(target_slot_from_optional_ref(
            "slot:processor-contract",
            first_ref(&spec.processor_contract_refs),
            format!("evidence:processor-contract:{}", spec.service_id),
        ));
        slot_postures.push(target_slot_from_optional_ref(
            "slot:processor-role",
            first_ref(&spec.processor_role_refs),
            format!("evidence:processor-role:{}", spec.service_id),
        ));
        slot_postures.push(target_slot_from_optional_ref(
            "slot:processor-seed",
            first_ref(&spec.processor_seed_refs),
            format!("evidence:processor-seed:{}", spec.service_id),
        ));
        slot_postures.push(target_slot_from_optional_ref(
            "slot:processor-report",
            first_ref(&spec.processor_report_refs),
            format!("evidence:processor-report:{}", spec.service_id),
        ));
    }
    if rollback_required_for(&operation.operation) && spec.rollback_required {
        slot_postures.push(target_slot_from_optional_ref(
            "slot:rollback",
            spec.rollback_ref.clone(),
            format!("evidence:rollback:{}", spec.service_id),
        ));
    } else {
        slot_postures.push(target_slot_posture(
            "slot:rollback",
            FABRIC_CONTRACT_TARGET_SLOT_NOT_REQUIRED,
            FABRIC_CONTRACT_TARGET_PLATFORM_FIT_UNKNOWN,
            Vec::new(),
            None,
            vec![format!("evidence:rollback:{}", spec.service_id)],
            vec![],
        ));
    }

    let mut top_blockers = normalize_blockers(blocked_reasons);
    for slot in &slot_postures {
        if matches!(
            slot.state.as_str(),
            FABRIC_CONTRACT_TARGET_SLOT_MISSING | FABRIC_CONTRACT_TARGET_SLOT_BLOCKED
        ) {
            top_blockers.push(format!("targetSlot:{}:{}", slot.state, slot.slot_ref));
            top_blockers.extend(slot.blocked_reasons.clone());
        }
    }
    let top_blockers = normalize_blockers(top_blockers);
    let degraded = slot_postures.iter().any(|slot| {
        slot.state == FABRIC_CONTRACT_TARGET_SLOT_BLOCKED
            || slot.state == FABRIC_CONTRACT_TARGET_SLOT_MISSING
    });
    let candidate_fulfillment_refs = slot_postures
        .iter()
        .flat_map(|slot| slot.candidate_fulfillment_refs.clone())
        .collect::<Vec<_>>();
    let registry = ContractTargetRegistryPosture {
        kind: Some(RECORD_CONTRACT_TARGET_REGISTRY_POSTURE.to_string()),
        registry_ref: contract_target_registry_ref(spec),
        target_ref: target.target_ref.clone(),
        contract_ref: target.contract_ref.clone(),
        state: if top_blockers.is_empty() {
            if degraded {
                FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED
            } else {
                FABRIC_CONTRACT_TARGET_REGISTRY_READY
            }
        } else {
            FABRIC_CONTRACT_TARGET_REGISTRY_BLOCKED
        }
        .to_string(),
        slot_postures,
        candidate_fulfillment_refs,
        source_refs: source_input_refs(spec),
        build_refs: build_input_refs(spec),
        adapter_refs: if spec.host_adapter_ref.trim().is_empty() {
            Vec::new()
        } else {
            vec![spec.host_adapter_ref.clone()]
        },
        proof_requirement_refs: vec!["proof-requirement:service-manager:lifecycle".to_string()],
        proof_refs: {
            let mut refs = vec![format!("proof:operation:{}", operation.operation_id)];
            refs.extend(spec.build_proof_refs.clone());
            refs
        },
        evidence_refs: vec![format!("evidence:target-registry:{}", spec.service_id)],
        blocked_reasons: top_blockers,
        safe_facts: json!({
            "serviceId": spec.service_id,
            "operation": operation.operation,
            "sourceInputRefs": source_input_refs(spec),
            "buildInputRefs": build_input_refs(spec),
            "projectInputRefs": project_input_refs(spec),
            "processorInputRefs": processor_input_refs(spec)
        }),
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_contract_target_registry_posture(&registry)?;
    Ok(registry)
}

pub fn build_host_fabric_fulfillment_plan_for_spec(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
    member_contribution_refs: Vec<String>,
    lifecycle_plan_refs: Vec<String>,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<HostFabricFulfillmentPlan> {
    build_host_fabric_fulfillment_plan_for_spec_with_target(
        spec,
        operation,
        member_contribution_refs,
        lifecycle_plan_refs,
        observed_at,
        blocked_reasons,
        None,
    )
}

pub fn build_host_fabric_fulfillment_plan_for_spec_with_target(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
    member_contribution_refs: Vec<String>,
    lifecycle_plan_refs: Vec<String>,
    observed_at: u64,
    blocked_reasons: Vec<String>,
    target_registry_posture: Option<&ContractTargetRegistryPosture>,
) -> Result<HostFabricFulfillmentPlan> {
    let mut blocked_reasons = blocked_reasons;
    blocked_reasons.extend(host_fabric_contract_blockers(spec));
    if let Some(registry) = target_registry_posture {
        validate_contract_target_registry_posture(registry)?;
        blocked_reasons.extend(target_registry_blockers(registry));
    }
    let required_role_ref = fabric_role_ref_for_spec(spec);
    let mut missing_role_refs = if member_contribution_refs.is_empty() {
        vec![required_role_ref.clone()]
    } else {
        vec![]
    };
    if let Some(registry) = target_registry_posture {
        missing_role_refs.extend(target_registry_missing_slot_refs(registry));
    }
    if !missing_role_refs.is_empty() {
        blocked_reasons.push(format!("hostFabric:missingFabricRole:{required_role_ref}"));
    }
    let blocked_reasons = normalize_blockers(blocked_reasons);
    let degraded = target_registry_posture.is_some_and(target_registry_degraded);
    let state = if !blocked_reasons.is_empty() {
        FABRIC_FULFILLMENT_PLAN_BLOCKED
    } else if degraded {
        FABRIC_FULFILLMENT_PLAN_DEGRADED
    } else {
        FABRIC_FULFILLMENT_PLAN_READY
    };
    let materialization_budget_refs = if spec.materialization_budget_refs.is_empty() {
        vec!["materialization-budget:service-manager".to_string()]
    } else {
        spec.materialization_budget_refs.clone()
    };
    let plan = HostFabricFulfillmentPlan {
        kind: Some(RECORD_HOST_FABRIC_FULFILLMENT_PLAN.to_string()),
        plan_id: host_fabric_fulfillment_plan_id(spec, operation),
        fabric_ref: spec.fabric_ref.clone(),
        host_ref: spec.host_ref.clone().unwrap_or_default(),
        contract_ref: spec.host_adapter_ref.clone(),
        state: state.to_string(),
        required_role_refs: vec![required_role_ref],
        member_contribution_refs,
        missing_role_refs,
        lifecycle_plan_refs,
        materialization_budget_refs,
        association_handoff_ref: spec.association_handoff_ref.clone(),
        evidence_refs: vec![
            format!("evidence:host-fabric-plan:{}", spec.service_id),
            target_registry_posture
                .map(|registry| registry.registry_ref.clone())
                .unwrap_or_default(),
        ]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect(),
        blocked_reasons,
        safe_facts: json!({
            "serviceId": spec.service_id,
            "operation": operation.operation,
            "role": fabric_role_for_spec(spec),
            "state": state,
            "targetRegistryRef": target_registry_posture.map(|registry| registry.registry_ref.clone())
        }),
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_host_fabric_fulfillment_plan(&plan)?;
    Ok(plan)
}

pub fn reduce_host_fabric_fulfillment_plan_for_spec(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
    host_fabric_contributions: &[HostFabricMemberContribution],
    lifecycle_plans: &[LifecyclePlanPosture],
    observed_at: u64,
    blocked_reasons: Vec<String>,
    target_registry_posture: Option<&ContractTargetRegistryPosture>,
) -> Result<HostFabricFulfillmentPlan> {
    let mut blocked_reasons = blocked_reasons;
    blocked_reasons.extend(host_fabric_contract_blockers(spec));
    if let Some(registry) = target_registry_posture {
        validate_contract_target_registry_posture(registry)?;
        blocked_reasons.extend(target_registry_blockers(registry));
    }
    let materialization_budget_refs = if spec.materialization_budget_refs.is_empty() {
        vec!["materialization-budget:service-manager".to_string()]
    } else {
        spec.materialization_budget_refs.clone()
    };
    let known_missing_role_refs = target_registry_posture
        .map(target_registry_missing_slot_refs)
        .unwrap_or_default();
    let mut evidence_refs = vec![format!("evidence:host-fabric-plan:{}", spec.service_id)];
    if let Some(registry) = target_registry_posture {
        evidence_refs.push(registry.registry_ref.clone());
    }
    let reduction = reduce_host_fabric(HostFabricReductionInput {
        plan_id: host_fabric_fulfillment_plan_id(spec, operation),
        fabric_ref: spec.fabric_ref.clone(),
        host_ref: spec.host_ref.clone().unwrap_or_default(),
        contract_ref: spec.host_adapter_ref.clone(),
        required_roles: vec![HostFabricRoleRequirement {
            role_ref: fabric_role_ref_for_spec(spec),
            min_ready: 1,
        }],
        contributions: host_fabric_contributions.to_vec(),
        lifecycle_plans: lifecycle_plans.to_vec(),
        materialization_budget_refs,
        known_missing_role_refs,
        evidence_refs,
        blocked_reasons,
        association_handoff_ref: spec.association_handoff_ref.clone(),
        observed_at,
        expires_at: Some(observed_at + 3600),
    })?;
    Ok(reduction.fulfillment_plan)
}

pub fn build_service_hardening_posture_for_spec(
    spec: &ManagedServiceSpec,
    operation: &ServiceManagerOperationPostureRecord,
    host_fabric_fulfillment_plan: &HostFabricFulfillmentPlan,
    observed_at: u64,
    blocked_reasons: Vec<String>,
) -> Result<ServiceHardeningPostureRecord> {
    validate_service_manager_operation_posture(operation)?;
    validate_host_fabric_fulfillment_plan(host_fabric_fulfillment_plan)?;
    let mut blocked_reasons = blocked_reasons;
    blocked_reasons.extend(host_fabric_contract_blockers(spec));
    blocked_reasons.extend(host_fabric_fulfillment_plan.blocked_reasons.clone());
    let blocked_reasons = normalize_blockers(blocked_reasons);
    let state = if !blocked_reasons.is_empty() {
        "blocked"
    } else if host_fabric_fulfillment_plan.state == FABRIC_FULFILLMENT_PLAN_DEGRADED {
        "degraded"
    } else {
        "ready"
    };
    let mut evidence_refs = vec![
        operation.operation_id.clone(),
        host_fabric_fulfillment_plan.plan_id.clone(),
        format!("evidence:service-hardening:{}", spec.service_id),
    ];
    evidence_refs.extend(operation.evidence_refs.clone());
    evidence_refs.extend(host_fabric_fulfillment_plan.evidence_refs.clone());
    evidence_refs.sort();
    evidence_refs.dedup();

    let posture = ServiceHardeningPostureRecord {
        kind: Some(RECORD_SERVICE_HARDENING_POSTURE.to_string()),
        posture_id: format!(
            "service-hardening:{}:{}:{}",
            spec.service_id, operation.operation, observed_at
        ),
        service_ref: spec.subject_ref.clone(),
        observer_ref: spec.manager_ref.clone(),
        state: state.to_string(),
        process_policy_refs: vec![format!("process-policy:{}", spec.service_id)],
        launch_policy_refs: vec![format!("launch-policy:{}", spec.service_id)],
        restart_policy_refs: vec![format!("restart-policy:{}", spec.service_id)],
        adapter_posture_refs: vec![spec.host_adapter_ref.clone()],
        firewall_posture_refs: vec![format!("firewall-posture:{}", spec.service_id)],
        signal_observation_refs: Vec::new(),
        evidence_refs,
        safe_facts: json!({
            "serviceId": spec.service_id,
            "managerId": spec.manager_id,
            "operation": operation.operation,
            "operationState": operation.state,
            "fabricPlanState": host_fabric_fulfillment_plan.state,
            "hostAdapterRef": spec.host_adapter_ref,
            "lifecycleContractRef": spec.lifecycle_contract_ref,
            "fabricRef": spec.fabric_ref,
            "associationHandoffRef": spec.association_handoff_ref,
        }),
        blocked_reasons,
        observed_at,
        expires_at: Some(observed_at + 3600),
    };
    validate_service_hardening_posture(&posture)?;
    Ok(posture)
}

pub fn build_service_manager_hardening_observation(
    outcome: &ServiceOperationOutcome,
    observed_at: u64,
) -> Result<ServiceManagerHardeningObservation> {
    validate_service_hardening_posture(&outcome.service_hardening_posture)?;
    validate_service_manager_operation_posture(&outcome.operation_posture)?;
    validate_service_manager_proof_digest(&outcome.proof_digest)?;
    let expires_at = observed_at.saturating_add(3_600);
    let mitigation_recommendation = CybersecMitigationRecommendationRecord {
        kind: Some(RECORD_CYBERSEC_MITIGATION_RECOMMENDATION.to_string()),
        recommendation_id: format!(
            "cybersec:recommendation:service-hardening:{}:{}",
            outcome.service_id, observed_at
        ),
        finding_ref: outcome.service_hardening_posture.posture_id.clone(),
        processor_report_ref: format!(
            "event-fabric-report:service-hardening:{}",
            outcome.service_id
        ),
        recommender_ref: "processor:constitute-cybersec".to_string(),
        action_kind: "retainEvidence".to_string(),
        target_ref: outcome.service_hardening_posture.posture_id.clone(),
        state: "recommended".to_string(),
        authority_refs: vec!["authority:cybersec-recommendation".to_string()],
        consumer_refs: vec![
            mitigation::SERVICE_MANAGER_MITIGATION_CONSUMER_REF.to_string(),
            "host.lifecycle".to_string(),
        ],
        evidence_refs: vec![
            outcome.service_hardening_posture.posture_id.clone(),
            outcome.operation_posture.operation_id.clone(),
            outcome.proof_digest.digest_id.clone(),
        ],
        safe_facts: json!({
            "recommendationOnly": true,
            "targetClass": "serviceHardeningObservation",
            "hostEffectGated": true
        }),
        blocked_reasons: Vec::new(),
        issued_at: observed_at,
        expires_at: Some(expires_at),
    };
    validate_cybersec_mitigation_recommendation(&mitigation_recommendation)?;
    let mitigation_consumer = mitigation::service_manager_mitigation_consumer_posture(
        &mitigation_recommendation,
        vec!["authority:service-manager-mitigation".to_string()],
        observed_at.saturating_add(1),
    )?;
    validate_cybersec_mitigation_consumer_posture(&mitigation_consumer)?;

    Ok(ServiceManagerHardeningObservation {
        service_id: outcome.service_id.clone(),
        service_hardening_posture: outcome.service_hardening_posture.clone(),
        mitigation_recommendation,
        mitigation_consumer,
    })
}

fn target_registry_blockers(registry: &ContractTargetRegistryPosture) -> Vec<String> {
    let mut blockers = registry.blocked_reasons.clone();
    for slot in &registry.slot_postures {
        if matches!(
            slot.state.as_str(),
            FABRIC_CONTRACT_TARGET_SLOT_MISSING | FABRIC_CONTRACT_TARGET_SLOT_BLOCKED
        ) {
            blockers.push(format!("targetSlot:{}:{}", slot.state, slot.slot_ref));
            blockers.extend(slot.blocked_reasons.clone());
        }
    }
    normalize_blockers(blockers)
}

fn target_registry_missing_slot_refs(registry: &ContractTargetRegistryPosture) -> Vec<String> {
    registry
        .slot_postures
        .iter()
        .filter(|slot| {
            matches!(
                slot.state.as_str(),
                FABRIC_CONTRACT_TARGET_SLOT_MISSING | FABRIC_CONTRACT_TARGET_SLOT_BLOCKED
            )
        })
        .map(|slot| slot.slot_ref.clone())
        .collect()
}

fn target_registry_degraded(registry: &ContractTargetRegistryPosture) -> bool {
    registry.state == FABRIC_CONTRACT_TARGET_REGISTRY_DEGRADED
        || registry.slot_postures.iter().any(|slot| {
            slot.state == FABRIC_CONTRACT_TARGET_SLOT_BLOCKED
                || slot.state == FABRIC_CONTRACT_TARGET_SLOT_MISSING
        })
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
            "state": if release_ready_for_spec(spec) { "releaseReady" } else { "blocked" },
            "appContractRef": spec.app_contract_ref,
            "version": spec.version,
            "buildRef": spec.build_ref,
            "contentIndexRefs": spec.content_index_refs,
            "sourceGraphRefs": spec.source_graph_refs,
            "sourceSnapshotRefs": spec.source_snapshot_refs,
            "sourceOperationRefs": spec.source_operation_refs,
            "projectRefs": spec.project_refs,
            "workItemRefs": spec.work_item_refs,
            "buildRunRefs": spec.build_run_refs,
            "buildArtifactRefs": spec.build_artifact_refs,
            "buildProofRefs": spec.build_proof_refs,
            "releaseCandidateRefs": spec.release_candidate_refs,
            "releaseRef": spec.release_ref,
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": release_contract_blockers_for_spec(spec)
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
        "contentIndexRefs": release_contract.content_index_refs,
        "sourceGraphRefs": release_contract.source_graph_refs,
        "sourceSnapshotRefs": release_contract.source_snapshot_refs,
        "sourceOperationRefs": release_contract.source_operation_refs,
        "projectRefs": release_contract.project_refs,
        "workItemRefs": release_contract.work_item_refs,
        "buildRunRefs": release_contract.build_run_refs,
        "buildArtifactRefs": release_contract.build_artifact_refs,
        "buildProofRefs": release_contract.build_proof_refs,
        "releaseCandidateRefs": release_contract.release_candidate_refs,
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
    let fabric_control_decision = reduce_fabric_control_decision(state, &spec, &request)?;
    let host_fabric_legacy_control_bridge =
        build_host_fabric_legacy_control_bridge(&spec, &request, &fabric_control_decision)?;
    let mut blocked_reasons = operation_blocked_reasons(&spec, &request);
    blocked_reasons.extend(fabric_control_decision.blocked_reasons.clone());
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
    let contract_target = build_contract_target_for_spec(
        &spec,
        &operation_posture.operation,
        request.requested_at + 85,
        blocked_reasons.clone(),
    )?;
    let host_fabric_contribution = build_host_fabric_member_contribution_for_spec(
        &spec,
        &operation_posture,
        request.requested_at + 90,
        blocked_reasons.clone(),
    )?;
    let member_contribution_refs = host_fabric_contribution
        .as_ref()
        .map(|contribution| vec![contribution.contribution_id.clone()])
        .unwrap_or_default();
    let lifecycle_plan = build_lifecycle_plan_for_spec(
        &spec,
        &operation_posture,
        member_contribution_refs.clone(),
        request.requested_at + 100,
        blocked_reasons.clone(),
    )?;
    let target_registry_posture = build_contract_target_registry_posture_for_spec(
        &spec,
        &contract_target,
        &operation_posture,
        host_fabric_contribution.as_ref(),
        Some(&lifecycle_plan),
        request.requested_at + 105,
        blocked_reasons.clone(),
    )?;
    let host_fabric_contributions = host_fabric_contribution
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    let host_fabric_fulfillment_plan = reduce_host_fabric_fulfillment_plan_for_spec(
        &spec,
        &operation_posture,
        &host_fabric_contributions,
        std::slice::from_ref(&lifecycle_plan),
        request.requested_at + 110,
        blocked_reasons.clone(),
        Some(&target_registry_posture),
    )?;
    let service_hardening_posture = build_service_hardening_posture_for_spec(
        &spec,
        &operation_posture,
        &host_fabric_fulfillment_plan,
        request.requested_at + 115,
        blocked_reasons.clone(),
    )?;
    state.operations.push(operation_posture.clone());
    state.proof_digests.push(proof_digest.clone());
    state.contract_targets.push(contract_target.clone());
    state
        .target_registry_postures
        .push(target_registry_posture.clone());
    if let Some(contribution) = &host_fabric_contribution {
        state.host_fabric_contributions.push(contribution.clone());
    }
    state.lifecycle_plans.push(lifecycle_plan.clone());
    state
        .host_fabric_fulfillment_plans
        .push(host_fabric_fulfillment_plan.clone());
    state
        .host_fabric_legacy_control_bridges
        .push(host_fabric_legacy_control_bridge.clone());
    state
        .service_hardening_postures
        .push(service_hardening_posture.clone());
    state.updated_at = request.requested_at + 115;
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
        contract_target,
        target_registry_posture,
        host_fabric_contribution,
        lifecycle_plan,
        host_fabric_fulfillment_plan,
        host_fabric_legacy_control_bridge,
        service_hardening_posture,
        fabric_control_decision,
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
    if spec.fabric_ref.trim().is_empty() {
        blocked_reasons.push("fabricRef:missing".to_string());
    }
    if spec.fabric_role.trim().is_empty() {
        blocked_reasons.push("fabricRole:missing".to_string());
    }
    if spec.host_adapter_ref.trim().is_empty() {
        blocked_reasons.push("hostAdapterRef:missing".to_string());
    }
    if spec.lifecycle_contract_ref.trim().is_empty() {
        blocked_reasons.push("lifecycleContractRef:missing".to_string());
    }
    blocked_reasons
}

fn reduce_fabric_control_decision(
    state: &ServiceManagerState,
    spec: &ManagedServiceSpec,
    request: &ServiceOperationRequest,
) -> Result<HostFabricControlDecision> {
    let host_ref = spec.host_ref.as_deref().unwrap_or_default();
    let operation_ref = format!(
        "service-manager:operation:{}:{}:{}",
        request.service_id, request.operation, request.requested_at
    );
    let base_decision = |state: &str,
                         delegated_role_ref: Option<String>,
                         source_plan_ref: Option<String>,
                         plan_state: Option<String>,
                         blocked_reasons: Vec<String>,
                         evidence_refs: Vec<String>|
     -> HostFabricControlDecision {
        let control_mode = if delegated_role_ref.is_some() {
            "fabricPreflightLegacyFallback"
        } else {
            "legacyDirect"
        };
        let quarantine_refs = delegated_role_ref
            .as_ref()
            .map(|role| format!("quarantine:service-manager:legacy-control:{role}"))
            .into_iter()
            .collect::<Vec<_>>();
        HostFabricControlDecision {
            kind: Some(RECORD_HOST_FABRIC_CONTROL_DECISION.to_string()),
            decision_id: format!(
                "hostFabric:controlDecision:{}:{}:{}",
                request.service_id, request.operation, request.requested_at
            ),
            fabric_ref: spec.fabric_ref.clone(),
            host_ref: host_ref.to_string(),
            operation_ref: operation_ref.clone(),
            subject_ref: request.service_id.clone(),
            control_owner_ref: spec.fabric_ref.clone(),
            delegated_role_ref,
            state: state.to_string(),
            source_plan_ref,
            plan_state,
            execution_delegation_ref: Some(format!(
                "delegation:service-manager:{}:{}",
                request.service_id, request.operation
            )),
            fallback_refs: vec!["fallback:service-manager:legacy-control".to_string()],
            quarantine_refs,
            rollback_ref: Some(format!("rollback:service-manager:{}", request.service_id)),
            blocked_reasons,
            evidence_refs,
            safe_facts: json!({
                "controlMode": control_mode,
                "operation": request.operation,
                "dryRun": request.dry_run,
            }),
            observed_at: request.requested_at,
            expires_at: Some(request.requested_at + 300),
        }
    };
    let Some(role) = request.fabric_control_role.as_deref() else {
        let decision = base_decision(
            FABRIC_CONTROL_DECISION_NOT_REQUESTED,
            None,
            None,
            None,
            vec![],
            vec!["evidence:fabric-control:not-requested".to_string()],
        );
        validate_host_fabric_control_decision(&decision)?;
        return Ok(decision);
    };
    let role_ref = fabric_role_ref(role);
    if spec.authority_refs.is_empty() {
        let decision = base_decision(
            FABRIC_CONTROL_DECISION_BLOCKED,
            Some(role_ref),
            None,
            None,
            vec!["hostFabric:controlAuthorityMissing".to_string()],
            vec!["evidence:fabric-control:missing-authority".to_string()],
        );
        validate_host_fabric_control_decision(&decision)?;
        return Ok(decision);
    }
    let latest_plan = state
        .host_fabric_fulfillment_plans
        .iter()
        .rev()
        .find(|plan| {
            plan.fabric_ref == spec.fabric_ref
                && plan.host_ref == host_ref
                && plan.required_role_refs.contains(&role_ref)
        });
    let Some(plan) = latest_plan else {
        let blocked = vec![format!("hostFabric:controlPlanMissing:{role_ref}")];
        let decision = base_decision(
            FABRIC_CONTROL_DECISION_WAITING_PLAN,
            Some(role_ref),
            None,
            None,
            blocked,
            vec!["evidence:fabric-control:missing-plan".to_string()],
        );
        validate_host_fabric_control_decision(&decision)?;
        return Ok(decision);
    };
    validate_host_fabric_fulfillment_plan(plan)?;
    let mut blocked_reasons = Vec::new();
    if plan
        .expires_at
        .is_some_and(|expires_at| expires_at <= request.requested_at)
    {
        blocked_reasons.push(format!("hostFabric:controlPlanExpired:{}", plan.plan_id));
    }
    if plan.missing_role_refs.contains(&role_ref) {
        blocked_reasons.push(format!("hostFabric:controlRoleMissing:{role_ref}"));
    }
    match plan.state.as_str() {
        FABRIC_FULFILLMENT_PLAN_READY => {}
        FABRIC_FULFILLMENT_PLAN_DEGRADED => {
            blocked_reasons.push(format!("hostFabric:controlDegraded:{role_ref}"));
        }
        FABRIC_FULFILLMENT_PLAN_BLOCKED => {
            blocked_reasons.push(format!("hostFabric:controlBlocked:{role_ref}"));
            blocked_reasons.extend(plan.blocked_reasons.clone());
        }
        other => {
            blocked_reasons.push(format!("hostFabric:controlUnknown:{role_ref}:{other}"));
        }
    }
    blocked_reasons.sort();
    blocked_reasons.dedup();
    let state = if blocked_reasons.is_empty() {
        FABRIC_CONTROL_DECISION_READY
    } else if plan.state == FABRIC_FULFILLMENT_PLAN_DEGRADED {
        FABRIC_CONTROL_DECISION_DEGRADED
    } else {
        FABRIC_CONTROL_DECISION_BLOCKED
    };
    let mut evidence_refs = plan.evidence_refs.clone();
    evidence_refs.push(format!("evidence:fabric-control:{}", plan.plan_id));
    evidence_refs.sort();
    evidence_refs.dedup();
    let decision = base_decision(
        state,
        Some(role_ref),
        Some(plan.plan_id.clone()),
        Some(plan.state.clone()),
        blocked_reasons,
        evidence_refs,
    );
    validate_host_fabric_control_decision(&decision)?;
    Ok(decision)
}

fn build_host_fabric_legacy_control_bridge(
    spec: &ManagedServiceSpec,
    request: &ServiceOperationRequest,
    decision: &HostFabricControlDecision,
) -> Result<HostFabricLegacyControlBridge> {
    let state = if request.fabric_control_role.is_none() {
        FABRIC_LEGACY_CONTROL_LEGACY_DIRECT
    } else if decision.state == FABRIC_CONTROL_DECISION_READY {
        FABRIC_LEGACY_CONTROL_FALLBACK_AVAILABLE
    } else if matches!(
        decision.state.as_str(),
        FABRIC_CONTROL_DECISION_WAITING_PLAN | FABRIC_CONTROL_DECISION_DEGRADED
    ) {
        FABRIC_LEGACY_CONTROL_QUARANTINED
    } else {
        FABRIC_LEGACY_CONTROL_BLOCKED
    };
    let mut evidence_refs = decision.evidence_refs.clone();
    evidence_refs.push(format!("evidence:legacy-control:{}", decision.decision_id));
    evidence_refs.sort();
    evidence_refs.dedup();
    let bridge = HostFabricLegacyControlBridge {
        kind: Some(RECORD_HOST_FABRIC_LEGACY_CONTROL_BRIDGE.to_string()),
        bridge_id: format!(
            "hostFabric:legacyControlBridge:{}:{}:{}",
            request.service_id, request.operation, request.requested_at
        ),
        fabric_ref: spec.fabric_ref.clone(),
        host_ref: spec.host_ref.clone().unwrap_or_default(),
        legacy_owner_ref: spec.manager_ref.clone(),
        subject_ref: request.service_id.clone(),
        operation_ref: decision.operation_ref.clone(),
        state: state.to_string(),
        source_decision_ref: if request.fabric_control_role.is_some() {
            Some(decision.decision_id.clone())
        } else {
            None
        },
        delegated_role_ref: decision.delegated_role_ref.clone(),
        fallback_refs: decision.fallback_refs.clone(),
        quarantine_refs: decision.quarantine_refs.clone(),
        blocked_reasons: if state == FABRIC_LEGACY_CONTROL_BLOCKED {
            decision.blocked_reasons.clone()
        } else {
            vec![]
        },
        evidence_refs,
        safe_facts: json!({
            "controlMode": decision.safe_facts.get("controlMode").cloned().unwrap_or(Value::Null),
            "operation": request.operation,
            "fabricControlRequested": request.fabric_control_role.is_some(),
        }),
        observed_at: decision.observed_at,
        expires_at: decision.expires_at,
    };
    validate_host_fabric_legacy_control_bridge(&bridge)?;
    Ok(bridge)
}

fn fabric_role_ref(role: &str) -> String {
    let trimmed = role.trim();
    if trimmed.starts_with("role:") {
        trimmed.to_string()
    } else {
        format!("role:{trimmed}")
    }
}

fn fabric_role_for_spec(spec: &ManagedServiceSpec) -> &str {
    let trimmed = spec.fabric_role.trim();
    if trimmed.is_empty() {
        FABRIC_MEMBER_ROLE_HOST_SERVICE_ADAPTER
    } else {
        trimmed
    }
}

fn fabric_role_ref_for_spec(spec: &ManagedServiceSpec) -> String {
    fabric_role_ref(fabric_role_for_spec(spec))
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
    blocked_reasons.extend(release_contract_blockers_for_spec(spec));
    blocked_reasons = normalize_blockers(blocked_reasons);
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
            "state": if release_ready_for_spec(spec) { "releaseReady" } else { "blocked" },
            "appContractRef": spec.app_contract_ref,
            "version": spec.version,
            "buildRef": spec.build_ref,
            "contentIndexRefs": spec.content_index_refs,
            "sourceGraphRefs": spec.source_graph_refs,
            "sourceSnapshotRefs": spec.source_snapshot_refs,
            "sourceOperationRefs": spec.source_operation_refs,
            "projectRefs": spec.project_refs,
            "workItemRefs": spec.work_item_refs,
            "buildRunRefs": spec.build_run_refs,
            "buildArtifactRefs": spec.build_artifact_refs,
            "buildProofRefs": spec.build_proof_refs,
            "releaseCandidateRefs": spec.release_candidate_refs,
            "releaseRef": spec.release_ref,
            "rollbackRef": spec.rollback_ref,
            "rollbackRequired": spec.rollback_required,
            "blockedReasons": release_contract_blockers_for_spec(spec)
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
    let spec = default_managed_service_spec();
    let lifecycle_operation = operations
        .iter()
        .find(|operation| operation.operation == SERVICE_MANAGER_OPERATION_START)
        .expect("start operation")
        .clone();
    let contract_target = build_contract_target_for_spec(
        &spec,
        &lifecycle_operation.operation,
        issued_at + 4990,
        vec![],
    )?;
    let host_fabric_contribution = build_host_fabric_member_contribution_for_spec(
        &spec,
        &lifecycle_operation,
        issued_at + 5000,
        vec![],
    )?
    .ok_or_else(|| anyhow!("default lifecycle fixture requires host-fabric member contribution"))?;
    let lifecycle_plan = build_lifecycle_plan_for_spec(
        &spec,
        &lifecycle_operation,
        vec![host_fabric_contribution.contribution_id.clone()],
        issued_at + 5010,
        vec![],
    )?;
    let target_registry_posture = build_contract_target_registry_posture_for_spec(
        &spec,
        &contract_target,
        &lifecycle_operation,
        Some(&host_fabric_contribution),
        Some(&lifecycle_plan),
        issued_at + 5015,
        vec![],
    )?;
    let host_fabric_fulfillment_plan = reduce_host_fabric_fulfillment_plan_for_spec(
        &spec,
        &lifecycle_operation,
        std::slice::from_ref(&host_fabric_contribution),
        std::slice::from_ref(&lifecycle_plan),
        issued_at + 5020,
        vec![],
        Some(&target_registry_posture),
    )?;
    let service_hardening_posture = build_service_hardening_posture_for_spec(
        &spec,
        &lifecycle_operation,
        &host_fabric_fulfillment_plan,
        issued_at + 5025,
        vec![],
    )?;
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
        contract_targets: vec![contract_target],
        target_registry_postures: vec![target_registry_posture],
        host_fabric_contributions: vec![host_fabric_contribution],
        lifecycle_plans: vec![lifecycle_plan],
        host_fabric_fulfillment_plans: vec![host_fabric_fulfillment_plan],
        service_hardening_postures: vec![service_hardening_posture],
        posture,
    };
    validate_fixture(&fixture)?;
    Ok(fixture)
}

pub fn fabric_transition_fixture(issued_at: u64) -> Result<FabricTransitionFixture> {
    let services = current_fabric_transition_service_specs();
    let fabric_ref = services
        .first()
        .map(|service| service.fabric_ref.clone())
        .unwrap_or_else(default_fabric_ref);
    let host_ref = services
        .first()
        .and_then(|service| service.host_ref.clone())
        .unwrap_or_else(|| "host:lab-service-manager".to_string());
    let mut state = ServiceManagerState {
        services: services.clone(),
        operations: vec![],
        proof_digests: vec![],
        contract_targets: vec![],
        target_registry_postures: vec![],
        host_fabric_contributions: vec![],
        lifecycle_plans: vec![],
        host_fabric_fulfillment_plans: vec![],
        host_fabric_legacy_control_bridges: vec![],
        service_hardening_postures: vec![],
        posture: None,
        updated_at: issued_at,
    };

    let mut outcomes = Vec::new();
    for (index, service) in services.iter().enumerate() {
        let outcome = apply_service_operation(
            &mut state,
            ServiceOperationRequest {
                service_id: service.service_id.clone(),
                operation: SERVICE_MANAGER_OPERATION_START.to_string(),
                requested_at: issued_at + 100 + (index as u64 * 250),
                dry_run: true,
                blocked_reason: None,
                fabric_control_role: None,
            },
        )?;
        outcomes.push(outcome);
    }

    let required_roles = services
        .iter()
        .map(fabric_role_ref_for_spec)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|role_ref| HostFabricRoleRequirement {
            role_ref,
            min_ready: 1,
        })
        .collect::<Vec<_>>();
    let reduction_input = HostFabricReductionInput {
        plan_id: "fabric-plan:fabric-transition:current-services".to_string(),
        fabric_ref: fabric_ref.clone(),
        host_ref: host_ref.clone(),
        contract_ref: "contract:host-fabric.fabric-transition@0.1.0".to_string(),
        required_roles,
        contributions: state.host_fabric_contributions.clone(),
        lifecycle_plans: state.lifecycle_plans.clone(),
        materialization_budget_refs: vec!["materialization-budget:fabric-transition".to_string()],
        known_missing_role_refs: vec![],
        evidence_refs: vec!["evidence:fabric-transition:current-services".to_string()],
        blocked_reasons: vec![],
        association_handoff_ref: Some(DEFAULT_ASSOCIATION_HANDOFF_REF.to_string()),
        observed_at: issued_at + 2_000,
        expires_at: Some(issued_at + 5_600),
    };
    let shadow_parity = reduce_host_fabric_shadow_parity(HostFabricShadowParityInput {
        reduction: reduction_input,
        legacy_ready_role_refs: services
            .iter()
            .map(|service| service.fabric_role.clone())
            .collect(),
        legacy_blocked_role_refs: vec![],
    })?;
    let aggregate_fulfillment_plan = shadow_parity.reduction.fulfillment_plan.clone();
    let service_hardening_observations = outcomes
        .iter()
        .enumerate()
        .map(|(index, outcome)| {
            build_service_manager_hardening_observation(
                outcome,
                issued_at + 2_100 + (index as u64 * 10),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let fixture = FabricTransitionFixture {
        family_ref: "branch-family:0x/fabric-transition".to_string(),
        fabric_ref,
        host_ref,
        services,
        transition_state: aggregate_fulfillment_plan.state.clone(),
        blocked_reasons: aggregate_fulfillment_plan.blocked_reasons.clone(),
        aggregate_fulfillment_plan,
        shadow_parity,
        outcomes,
        service_hardening_observations,
    };
    validate_fabric_transition_fixture(&fixture)?;
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
    let spec = default_managed_service_spec();
    let contract_target = build_contract_target_for_spec(
        &spec,
        &operation.operation,
        requested_at + 210,
        vec![reason.to_string()],
    )?;
    let host_fabric_contribution = build_host_fabric_member_contribution_for_spec(
        &spec,
        &operation,
        requested_at + 220,
        vec![reason.to_string()],
    )?
    .into_iter()
    .collect::<Vec<_>>();
    let member_contribution_refs = host_fabric_contribution
        .iter()
        .map(|contribution| contribution.contribution_id.clone())
        .collect::<Vec<_>>();
    let lifecycle_plan = build_lifecycle_plan_for_spec(
        &spec,
        &operation,
        member_contribution_refs.clone(),
        requested_at + 230,
        vec![reason.to_string()],
    )?;
    let target_registry_posture = build_contract_target_registry_posture_for_spec(
        &spec,
        &contract_target,
        &operation,
        host_fabric_contribution.first(),
        Some(&lifecycle_plan),
        requested_at + 235,
        vec![reason.to_string()],
    )?;
    let host_fabric_fulfillment_plan = reduce_host_fabric_fulfillment_plan_for_spec(
        &spec,
        &operation,
        &host_fabric_contribution,
        std::slice::from_ref(&lifecycle_plan),
        requested_at + 240,
        vec![reason.to_string()],
        Some(&target_registry_posture),
    )?;
    let service_hardening_posture = build_service_hardening_posture_for_spec(
        &spec,
        &operation,
        &host_fabric_fulfillment_plan,
        requested_at + 245,
        vec![reason.to_string()],
    )?;
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
        contract_targets: vec![contract_target],
        target_registry_postures: vec![target_registry_posture],
        host_fabric_contributions: host_fabric_contribution,
        lifecycle_plans: vec![lifecycle_plan],
        host_fabric_fulfillment_plans: vec![host_fabric_fulfillment_plan],
        service_hardening_postures: vec![service_hardening_posture],
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
    for target in &fixture.contract_targets {
        validate_contract_target(target)?;
    }
    for registry in &fixture.target_registry_postures {
        validate_contract_target_registry_posture(registry)?;
    }
    for contribution in &fixture.host_fabric_contributions {
        validate_host_fabric_member_contribution(contribution)?;
    }
    for lifecycle_plan in &fixture.lifecycle_plans {
        validate_lifecycle_plan_posture(lifecycle_plan)?;
    }
    for fulfillment_plan in &fixture.host_fabric_fulfillment_plans {
        validate_host_fabric_fulfillment_plan(fulfillment_plan)?;
    }
    for service_hardening_posture in &fixture.service_hardening_postures {
        validate_service_hardening_posture(service_hardening_posture)?;
    }
    validate_service_manager_posture(&fixture.posture)
}

pub fn validate_fabric_transition_fixture(fixture: &FabricTransitionFixture) -> Result<()> {
    validate_host_fabric_fulfillment_plan(&fixture.aggregate_fulfillment_plan)?;
    validate_host_fabric_fulfillment_plan(&fixture.shadow_parity.reduction.fulfillment_plan)?;
    for outcome in &fixture.outcomes {
        validate_service_manager_operation_posture(&outcome.operation_posture)?;
        validate_service_manager_proof_digest(&outcome.proof_digest)?;
        validate_contract_target(&outcome.contract_target)?;
        validate_contract_target_registry_posture(&outcome.target_registry_posture)?;
        if let Some(contribution) = &outcome.host_fabric_contribution {
            validate_host_fabric_member_contribution(contribution)?;
        }
        validate_lifecycle_plan_posture(&outcome.lifecycle_plan)?;
        validate_host_fabric_fulfillment_plan(&outcome.host_fabric_fulfillment_plan)?;
        validate_host_fabric_legacy_control_bridge(&outcome.host_fabric_legacy_control_bridge)?;
        validate_service_hardening_posture(&outcome.service_hardening_posture)?;
        validate_service_manager_posture(&outcome.posture)?;
    }
    for observation in &fixture.service_hardening_observations {
        validate_service_hardening_posture(&observation.service_hardening_posture)?;
        validate_cybersec_mitigation_recommendation(&observation.mitigation_recommendation)?;
        validate_cybersec_mitigation_consumer_posture(&observation.mitigation_consumer)?;
    }
    Ok(())
}
