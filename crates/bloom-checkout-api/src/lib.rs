//! Machine's closed checkout schema. This crate has no browser or custody code.
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowseRequest {
    Open { url: String },
    Snapshot,
    Click { element_ref: String },
    Type { element_ref: String, text: String },
    Select { element_ref: String, value: String },
    Back,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Browse {
        request: BrowseRequest,
    },
    /// With `card_id`, Bloom fills that saved card. Without one, Bloom clicks
    /// the merchant's pay button and the merchant charges the payment method
    /// saved in the buyer's account there. `take_over` instead hands the
    /// browser to the human (a login, a code, saved travelers) and buys
    /// nothing itself.
    Checkout {
        operation_id: String,
        #[serde(default)]
        card_id: Option<String>,
        agent_description: String,
        #[serde(default)]
        take_over: bool,
        /// With `take_over`, an earlier card or site checkout whose result is
        /// unknown. The person checks the shop or bank in the private view;
        /// only their Done there marks it checked and allows another payment
        /// at that shop.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolves: Option<String>,
    },
    Status {
        operation_id: String,
    },
    Cancel {
        operation_id: String,
    },
    /// The 50 most recent checkout requests, newest first.
    History,
}

/// One checkout request as the purchase history shows it.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    /// Unix seconds when the agent asked.
    pub created: u64,
    /// `card`, `site` or `take_over`.
    pub kind: String,
    pub description: String,
    /// The shop's origin, when Bloom could read the page.
    pub shop: Option<String>,
    /// The total read during preparation; status must be checked separately
    /// for approval and payment. Failed requests can also carry a total.
    pub total_minor: Option<u64>,
    pub currency: Option<String>,
    /// What the shop charges once any trial or intro price ends, and how
    /// often, when the page stated it during preparation.
    /// Bloom cannot cap what the shop takes later; cancelling is done with
    /// the shop.
    pub renewal_minor: Option<u64>,
    /// `day`, `week`, `month` or `year`.
    pub renewal_period: Option<String>,
    /// The first date that price applies, `YYYY-MM-DD`.
    pub renewal_starts_on: Option<String>,
    pub status: Status,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub operation_id: String,
    pub state: String,
    pub ceremony_url: Option<String>,
    /// Entry point for reopening a private view with the claiming browser's
    /// origin-bound session key.
    /// Contains no capability; only the browser that claimed it has access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_url: Option<String>,
    pub filled_fields: Vec<String>,
    pub outcome: Option<Outcome>,
    /// Checkout could not hand the browser back, so shopping stays paused.
    #[serde(default, skip_serializing_if = "skip_false")]
    pub paused: bool,
    /// Why Checkout left the payment to the person, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<PreparationReason>,
}

/// Why Checkout could not prepare the payment itself, so the person finishes
/// it in the private view. The codes belong to Checkout: no merchant text,
/// field value or saved value reaches the agent through them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationReason {
    /// The total, currency or charge terms could not be read, or the page
    /// has no recognizable payment action. Complete the page before retrying.
    FactsUnreadable,
    /// More than one distinct payment action remains. Choose privately;
    /// trying buttons is not a safe discovery method.
    PaymentActionAmbiguous,
    /// Installment choices, or a subscription's later price, period or first
    /// charge date, do not identify one clear charge schedule.
    ChargeTermsUnreadable,
    /// The card fields are missing, duplicated or in an unexpected shape.
    FieldsUnsupported,
    /// A frame that would receive the card is not a reviewed payment host.
    ReceivingOriginUnreviewed,
}

impl std::fmt::Display for PreparationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FactsUnreadable => "facts_unreadable",
            Self::PaymentActionAmbiguous => "payment_action_ambiguous",
            Self::ChargeTermsUnreadable => "charge_terms_unreadable",
            Self::FieldsUnsupported => "fields_unsupported",
            Self::ReceivingOriginUnreviewed => "receiving_origin_unreviewed",
        })
    }
}

// Carried on the preparation error so the service can report the code without
// reading the message.
impl std::error::Error for PreparationReason {}

fn skip_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub state: String,
    pub source: String,
    pub confirmation_reached: bool,
    pub order_id: Option<String>,
    pub merchant_reported_total_minor: Option<u64>,
    pub currency: Option<String>,
    /// Set when a person marks an unresolved result checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum BrowseResponse {
    Snapshot(Snapshot),
    Action(Action),
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub state: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub url: String,
    pub text: String,
    pub elements: Vec<Element>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Element {
    #[serde(rename = "ref")]
    pub element_ref: String,
    pub frame_origin: Option<String>,
    pub role: String,
    pub label: String,
    /// Short text around a repeated control, such as its fare card or month.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(rename = "type")]
    pub input_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SelectOption>>,
    /// Field contents, except card and password fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    /// A link's http(s) origin and path, without query or fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preparation_reasons_survive_status_and_history_roundtrips() {
        // Machine clients and VFS deserialize this same packaged contract.
        // Existing persisted broad reasons remain readable; unknown codes
        // are rejected rather than displayed as merchant-controlled text.
        for code in [
            "facts_unreadable",
            "payment_action_ambiguous",
            "charge_terms_unreadable",
            "fields_unsupported",
            "receiving_origin_unreviewed",
        ] {
            let status = json!({"operation_id":"fixture", "state":"manual_required", "ceremony_url":null, "filled_fields":[], "outcome":null, "reason":code});
            let parsed: Status = serde_json::from_value(status.clone()).unwrap();
            assert_eq!(parsed.reason.unwrap().to_string(), code);
            assert_eq!(serde_json::to_value(parsed).unwrap(), status);
            let entry = json!({"created":0, "kind":"card", "description":"Fixture", "shop":null, "total_minor":null, "currency":null, "renewal_minor":null, "renewal_period":null, "renewal_starts_on":null, "status":status});
            let parsed: HistoryEntry = serde_json::from_value(entry.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), entry);
        }
        assert!(serde_json::from_value::<PreparationReason>(json!("merchant text")).is_err());
    }
}
