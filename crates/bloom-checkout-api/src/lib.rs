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
    Checkout {
        operation_id: String,
        card_id: String,
        agent_description: String,
    },
    Status {
        operation_id: String,
    },
    Cancel {
        operation_id: String,
    },
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
    #[serde(rename = "type")]
    pub input_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SelectOption>>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
}
