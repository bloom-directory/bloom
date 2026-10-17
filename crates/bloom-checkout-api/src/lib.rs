//! Machine's closed checkout schema. This crate has no browser or custody code.
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowseRequest {
    Open {
        url: String,
    },
    Snapshot,
    Click {
        element_ref: String,
    },
    Type {
        element_ref: String,
        text: String,
    },
    Select {
        element_ref: String,
        value: String,
    },
    Back,
    /// Fill the unlocked traveler's fields on this page without returning them.
    FillTraveler {
        /// Required when more than one saved person is unlocked for this journey.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        traveler_id: Option<String>,
    },
    /// Type one unlocked traveler value into an element the agent chose.
    /// `field` is a saved field, or `phone_national` (no country code),
    /// `phone_area`, `phone_local`,
    /// `born_on_day`, `born_on_month`, `born_on_year`, `born_on_dmy` (DD/MM/YYYY).
    TypeTraveler {
        element_ref: String,
        field: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        traveler_id: Option<String>,
    },
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
    /// browser to the human (a login, a code) and buys nothing.
    Checkout {
        operation_id: String,
        #[serde(default)]
        card_id: Option<String>,
        agent_description: String,
        #[serde(default)]
        take_over: bool,
    },
    /// Unlock a saved traveler for the current website with one approval.
    /// Values stay in checkout; `FillTraveler` puts them on each page.
    Traveler {
        operation_id: String,
        traveler_id: String,
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
    /// The total the human approved, when Bloom read one.
    pub total_minor: Option<u64>,
    pub currency: Option<String>,
    pub status: Option<Status>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub operation_id: String,
    pub state: String,
    pub ceremony_url: Option<String>,
    pub filled_fields: Vec<String>,
    pub outcome: Option<Outcome>,
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
    /// Field names `FillTraveler` filled; never their values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filled_fields: Option<Vec<String>>,
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
    /// Field contents, except card and password fields. Unlocked traveler
    /// values appear as `[saved <field>]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
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
    fn traveler_selection_keeps_single_person_json_compatible() {
        for value in [
            json!({"action":"fill_traveler"}),
            json!({"action":"type_traveler","element_ref":"1:0","field":"given_name"}),
        ] {
            let request: BrowseRequest = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(request).unwrap(), value);
        }
        let value = json!({"action":"type_traveler","element_ref":"1:0","field":"given_name","traveler_id":"saved-person-one"});
        let request: BrowseRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), value);
        assert!(serde_json::from_value::<BrowseRequest>(json!({"action":"fill_traveler","traveler_id":"one","values":{"given_name":"not allowed"}})).is_err());
    }
}
