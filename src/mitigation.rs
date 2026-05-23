use anyhow::Result;
use constitute_protocol::{
    CybersecMitigationConsumerPostureRecord, CybersecMitigationRecommendationRecord,
    RECORD_CYBERSEC_MITIGATION_CONSUMER_POSTURE, validate_cybersec_mitigation_consumer_posture,
    validate_cybersec_mitigation_recommendation,
};
use serde_json::json;

pub const SERVICE_MANAGER_MITIGATION_CONSUMER_REF: &str = "constitute-service-manager";

const SERVICE_MANAGER_SUPPORTED_MITIGATION_ACTIONS: &[&str] = &[
    "observe",
    "requestEvidence",
    "retainEvidence",
    "degrade",
    "notify",
];

pub fn service_manager_supported_mitigation_actions() -> Vec<String> {
    SERVICE_MANAGER_SUPPORTED_MITIGATION_ACTIONS
        .iter()
        .map(|action| (*action).to_string())
        .collect()
}

pub fn service_manager_mitigation_consumer_posture(
    recommendation: &CybersecMitigationRecommendationRecord,
    authority_refs: Vec<String>,
    observed_at: u64,
) -> Result<CybersecMitigationConsumerPostureRecord> {
    validate_cybersec_mitigation_recommendation(recommendation)?;

    let supported_actions = service_manager_supported_mitigation_actions();
    let targeted = recommendation.consumer_refs.is_empty()
        || recommendation.consumer_refs.iter().any(|consumer| {
            matches!(
                consumer.as_str(),
                SERVICE_MANAGER_MITIGATION_CONSUMER_REF
                    | "service-manager"
                    | "host-service-adapter"
                    | "host.lifecycle"
            )
        });
    let supports_action = supported_actions
        .iter()
        .any(|action| action == &recommendation.action_kind);
    let mut blocked_reasons = Vec::new();

    let state = if recommendation
        .expires_at
        .is_some_and(|expires_at| expires_at <= observed_at)
    {
        "expired"
    } else if !targeted {
        blocked_reasons.push("notTargetedToServiceManager".to_string());
        "unsupported"
    } else if !supports_action {
        blocked_reasons.push(format!("unsupportedAction:{}", recommendation.action_kind));
        "unsupported"
    } else if authority_refs.is_empty() {
        "waitingAuthority"
    } else {
        "actionable"
    };

    let posture = CybersecMitigationConsumerPostureRecord {
        kind: Some(RECORD_CYBERSEC_MITIGATION_CONSUMER_POSTURE.to_string()),
        posture_id: format!(
            "cybersec:mitigation-consumer:service-manager:{}",
            recommendation.recommendation_id
        ),
        recommendation_ref: recommendation.recommendation_id.clone(),
        finding_ref: recommendation.finding_ref.clone(),
        processor_report_ref: recommendation.processor_report_ref.clone(),
        consumer_ref: SERVICE_MANAGER_MITIGATION_CONSUMER_REF.to_string(),
        action_kind: recommendation.action_kind.clone(),
        target_ref: recommendation.target_ref.clone(),
        state: state.to_string(),
        authority_refs,
        supported_action_kinds: supported_actions,
        evidence_refs: vec![recommendation.recommendation_id.clone()],
        blocked_reasons,
        safe_facts: json!({
            "recommendationOnly": true,
            "enforcementOwner": "service-manager.consumer",
            "consumerTargeted": targeted,
            "actionSupported": supports_action,
            "hostEffectGated": true
        }),
        observed_at,
        expires_at: recommendation
            .expires_at
            .filter(|expires_at| *expires_at > observed_at),
    };
    validate_cybersec_mitigation_consumer_posture(&posture)?;
    Ok(posture)
}
