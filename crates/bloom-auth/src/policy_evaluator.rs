use bloom_auth_api::{
    AuthApiError, PetalPolicySnapshot, PolicyCheckClass, PolicyCheckResult, PolicyDecision,
    PolicyEvaluator,
};

pub struct DefaultPolicyEvaluator;

impl DefaultPolicyEvaluator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultPolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PolicyEvaluator for DefaultPolicyEvaluator {
    async fn evaluate(
        &self,
        _snapshot: &PetalPolicySnapshot,
        checks: &[PolicyCheckResult],
        _now_ms: u64,
    ) -> Result<PolicyDecision, AuthApiError> {
        if checks
            .iter()
            .any(|c| c.rule_class == PolicyCheckClass::Hard && c.outcome != "pass")
        {
            return Ok(PolicyDecision {
                hard_violation: true,
                step_up_required: false,
                exceeded_ceiling: None,
            });
        }

        for check in checks {
            if check.rule_class == PolicyCheckClass::StepUp
                && check.outcome != "pass"
                && check.step_up_ceiling.is_some()
            {
                return Ok(PolicyDecision {
                    hard_violation: false,
                    step_up_required: false,
                    exceeded_ceiling: Some(format!("rule {} exceeds ceiling", check.rule_id)),
                });
            }
        }

        let step_up_required = checks
            .iter()
            .any(|c| c.rule_class == PolicyCheckClass::StepUp && c.outcome != "pass");

        Ok(PolicyDecision {
            hard_violation: false,
            step_up_required,
            exceeded_ceiling: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn snapshot() -> PetalPolicySnapshot {
        PetalPolicySnapshot {
            policy_version: 1,
            wallet: "my-wallet".into(),
            petal_id: "test-petal".into(),
            petal_digest: "abc123".into(),
            caps: BTreeMap::new(),
            hard_rules: Vec::new(),
            step_up_rules: Vec::new(),
            config: BTreeMap::new(),
            budget_state: BTreeMap::new(),
            session_scope: None,
        }
    }

    fn check(
        rule_id: &str,
        class: PolicyCheckClass,
        outcome: &str,
        ceiling: Option<serde_json::Value>,
    ) -> PolicyCheckResult {
        PolicyCheckResult {
            rule_id: rule_id.into(),
            rule_class: class,
            outcome: outcome.into(),
            message: "test".into(),
            step_up_ceiling: ceiling,
        }
    }

    #[tokio::test]
    async fn hard_violation_is_non_escalatable() {
        let d = DefaultPolicyEvaluator::new()
            .evaluate(
                &snapshot(),
                &[check("r1", PolicyCheckClass::Hard, "fail", None)],
                0,
            )
            .await
            .unwrap();
        assert!(d.hard_violation);
        assert!(!d.step_up_required);
        assert!(d.exceeded_ceiling.is_none());
    }

    #[tokio::test]
    async fn step_up_required_without_ceiling() {
        let d = DefaultPolicyEvaluator::new()
            .evaluate(
                &snapshot(),
                &[check("r1", PolicyCheckClass::StepUp, "fail", None)],
                0,
            )
            .await
            .unwrap();
        assert!(!d.hard_violation);
        assert!(d.step_up_required);
        assert!(d.exceeded_ceiling.is_none());
    }

    #[tokio::test]
    async fn step_up_ceiling_exceeded_denies() {
        let d = DefaultPolicyEvaluator::new()
            .evaluate(
                &snapshot(),
                &[check(
                    "r1",
                    PolicyCheckClass::StepUp,
                    "fail",
                    Some(serde_json::json!(100)),
                )],
                0,
            )
            .await
            .unwrap();
        assert!(!d.hard_violation);
        assert!(!d.step_up_required);
        assert!(d.exceeded_ceiling.is_some());
        assert!(d.is_denied());
    }

    #[tokio::test]
    async fn hard_wins_over_step_up() {
        let checks = vec![
            check("hard1", PolicyCheckClass::Hard, "fail", None),
            check("soft1", PolicyCheckClass::StepUp, "fail", None),
        ];
        let d = DefaultPolicyEvaluator::new()
            .evaluate(&snapshot(), &checks, 0)
            .await
            .unwrap();
        assert!(d.hard_violation);
        assert!(!d.step_up_required);
    }

    #[tokio::test]
    async fn informational_checks_never_block() {
        let d = DefaultPolicyEvaluator::new()
            .evaluate(
                &snapshot(),
                &[check("r1", PolicyCheckClass::Informational, "fail", None)],
                0,
            )
            .await
            .unwrap();
        assert!(!d.hard_violation && !d.step_up_required && d.exceeded_ceiling.is_none());
    }

    #[tokio::test]
    async fn pass_outcomes_produce_pass_through() {
        let checks = vec![
            check("r1", PolicyCheckClass::Hard, "pass", None),
            check(
                "r2",
                PolicyCheckClass::StepUp,
                "pass",
                Some(serde_json::json!(100)),
            ),
        ];
        let d = DefaultPolicyEvaluator::new()
            .evaluate(&snapshot(), &checks, 0)
            .await
            .unwrap();
        assert!(!d.hard_violation && !d.step_up_required && d.exceeded_ceiling.is_none());
    }

    #[tokio::test]
    async fn empty_checks_returns_pass_through() {
        let d = DefaultPolicyEvaluator::new()
            .evaluate(&snapshot(), &[], 0)
            .await
            .unwrap();
        assert_eq!(d, PolicyDecision::pass_through());
    }
}
