use super::*;
use crate::travelers::TravelerDiscovery;
use zeroize::Zeroize;
#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedAction {
    Traveler {
        traveler_id: String,
    },
    Pay {
        card_id: String,
        unpaid_checked: bool,
    },
}

pub(super) struct SavedState {
    parent: String,
    pub(super) operation: String,
    busy: bool,
    payment: bool,
    ceremony_url: String,
}
impl Drop for SavedState {
    fn drop(&mut self) {
        self.ceremony_url.zeroize();
    }
}

enum Release {
    Traveler(TravelerDiscovery, Recipient),
    Card(Discovery, Recipient),
}

impl CheckoutService {
    pub(super) fn require_saved_idle(&self) -> Result<()> {
        if self.saved.lock().as_ref().is_some_and(|s| s.busy) {
            bail!("Finish or cancel the saved-details approval before changing this page");
        }
        Ok(())
    }

    pub(super) fn saved_status(&self, parent: &str) -> Option<Value> {
        self.saved
            .lock()
            .as_ref()
            .filter(|s| s.parent == parent)
            .map(|s| {
                let mut status = self.store.get(&s.operation).ok();
                if s.busy
                    && let Some(status) = &mut status
                {
                    status.ceremony_url = Some(s.ceremony_url.clone());
                }
                json!({"busy":s.busy,"payment":s.payment,"status":status})
            })
    }
    fn saved_done(&self) {
        if let Some(saved) = self.saved.lock().as_mut() {
            saved.busy = false;
            saved.ceremony_url.zeroize();
        }
    }

    pub async fn private_saved_options(&self, token: &str) -> Result<Value> {
        {
            let private = self.private.lock().await;
            authorize_view(private.as_ref().context("Private view unavailable")?, token)?;
        }
        match self.intake(json!({"method":"saved"})).await? {
            IntakeResponse::Saved { cards, travelers } => {
                Ok(json!({"cards":cards,"travelers":travelers}))
            }
            _ => bail!("Saved details unavailable"),
        }
    }

    /// Only the authenticated private view can start these operations. The
    /// public browser remains revoked throughout, including cancelled approval.
    pub async fn private_saved(
        self: &Arc<Self>,
        token: &str,
        action: SavedAction,
    ) -> Result<Value> {
        let _gate = self.action_gate.lock().await;
        self.require_saved_idle()?;
        let private = self.private.lock().await;
        let checkout = private.as_ref().context("Private view unavailable")?;
        authorize_view(checkout, token)?;
        if checkout.mode != Mode::TakeOver {
            bail!("A payment is already in progress; check its outcome");
        }
        if let Some(previous) = self
            .saved
            .lock()
            .as_ref()
            .filter(|s| s.parent == checkout.operation_id && s.payment)
        {
            if self.store.get(&previous.operation)?.state != "failed_before_release" {
                bail!("An earlier payment may have started; do not pay again");
            }
        }
        let parent = checkout.operation_id.clone();
        let mut tab = checkout.tab.clone();
        tab.target = checkout.view_target.clone();
        tab.session = checkout.view_session.clone();
        let operation = hex_token(&rand::random::<[u8; 32]>());
        let recipient = Recipient::generate();
        let challenge = format!("http://127.0.0.1:{}/view", self.view_port);
        let (release, request, origin, payment) = match action {
            SavedAction::Traveler { traveler_id } => {
                Token::new(&traveler_id)?;
                let metadata = match self
                    .intake(json!({"method":"traveler_info","traveler_id":traveler_id}))
                    .await?
                {
                    IntakeResponse::Traveler { traveler }
                        if traveler.traveler_id.as_str() == traveler_id =>
                    {
                        traveler
                    }
                    _ => bail!("Traveler unavailable"),
                };
                let discovery = TravelerDiscovery::read(&tab, &metadata.fields).await?;
                let origin = discovery.scope.origin.clone();
                let request = json!({"method":"traveler","operation_id":operation,"traveler_id":traveler_id,
                    "scope":discovery.scope,"recipient_key":recipient.public,"challenge_url":challenge});
                (
                    Release::Traveler(discovery, recipient),
                    request,
                    origin,
                    false,
                )
            }
            SavedAction::Pay {
                card_id,
                unpaid_checked,
            } => {
                Token::new(&card_id)?;
                if !unpaid_checked {
                    bail!("Check the merchant order or your bank before requesting payment");
                }
                let discovery = Discovery::read(&tab).await?;
                let origin = discovery.facts.origin.clone();
                if let Some(unresolved) = self.store.unresolved_except(&origin, &parent)? {
                    return Err(Refusal::Blocked(unresolved).into());
                }
                // This acknowledgment concerns only this live navigation
                // session. It cannot clear an older uncertain payment.
                let request = json!({"method":"prepare","operation_id":operation,"card_id":card_id,
                    "facts":discovery.facts,"recipient_key":recipient.public,
                    "agent_description":"Requested in your private browser. You checked the merchant order or your bank and confirmed this order has not been paid.",
                    "challenge_url":challenge,"order_preview":crate::discovery::order_preview(&tab).await,
                    "order_fields":crate::discovery::order_fields(&tab).await});
                (Release::Card(discovery, recipient), request, origin, true)
            }
        };
        let mut status = Status {
            operation_id: operation.clone(),
            state: "requested".into(),
            ceremony_url: None,
            filled_fields: vec![],
            outcome: None,
            paused: false,
            reason: None,
            view_url: None,
        };
        self.store.insert(
            &status,
            if payment { "card" } else { "traveler" },
            "Requested in private browser",
        )?;
        let facts = match &release {
            Release::Card(d, _) => Some(&d.facts),
            _ => None,
        };
        self.store.record_order(
            &operation,
            Some(&origin),
            facts.map(|f| (f.total_minor, f.currency.as_str())),
            facts.and_then(renewal_terms),
        )?;
        let response = self.intake(request).await;
        let Ok(IntakeResponse::Prepared { ceremony_url }) = response else {
            self.set_state(&operation, "failed_before_release");
            bail!("Approval unavailable; the seller session is still open");
        };
        status.state = "awaiting_approval".into();
        // The review includes private page values. Never persist its bearer
        // URL in status/history, which Machine and the agent can read.
        if let Err(error) = self.store.update(&status) {
            let _ = self
                .intake(json!({"method":"cancel","operation_id":operation}))
                .await;
            return Err(error);
        }
        *self.saved.lock() = Some(SavedState {
            parent: parent.clone(),
            operation: operation.clone(),
            busy: true,
            payment,
            ceremony_url: ceremony_url.clone(),
        });
        let service = self.clone();
        tokio::spawn(async move {
            service.finish_saved(parent, operation, tab, release).await;
        });
        status.ceremony_url = Some(ceremony_url);
        Ok(serde_json::to_value(status)?)
    }

    async fn finish_saved(
        self: Arc<Self>,
        parent: String,
        operation: String,
        tab: PrivateTab,
        release: Release,
    ) {
        let deadline = tokio::time::Instant::now() + APPROVAL_RESULT_WAIT;
        let result = loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if let Ok(IntakeResponse::Result {
                status,
                receipt,
                output_aad,
            }) = self
                .intake(json!({"method":"result","operation_id":operation}))
                .await
            {
                match status.state {
                    CardOperationState::Succeeded => break Some((receipt, output_aad)),
                    CardOperationState::Cancelled
                    | CardOperationState::Expired
                    | CardOperationState::Failed
                    | CardOperationState::Missing => break None,
                    _ => {}
                }
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = self
                    .intake(json!({"method":"cancel","operation_id":operation}))
                    .await;
                let _gate = self.action_gate.lock().await;
                self.set_state(&operation, "disclosure_unknown");
                self.saved_done();
                return;
            }
        };
        let gate = self.action_gate.lock().await;
        let mut private = self.private.lock().await;
        let Some(checkout) = private.as_mut().filter(|c| c.operation_id == parent) else {
            self.set_state(&operation, "disclosure_unknown");
            self.saved_done();
            return;
        };
        let Some((receipt, aad)) = result else {
            self.set_state(&operation, "failed_before_release");
            self.saved_done();
            return;
        };
        let payment = matches!(release, Release::Card(..));
        let filled = match release {
            Release::Traveler(discovery, recipient) => {
                self.fill_saved_traveler(&operation, &tab, discovery, recipient, receipt, aad)
                    .await
            }
            Release::Card(discovery, recipient) => {
                // The fresh passkey approval follows the person's explicit
                // unpaid-order check, not a generic Done action.
                self.set_state(&parent, "resolved");
                checkout.operation_id = operation.clone();
                checkout.mode = Mode::Card;
                checkout.tab = tab;
                checkout.discovery = Some(discovery);
                checkout.recipient = Some(recipient);
                checkout.manual_submission = false;
                checkout.submitted = false;
                self.consume_and_fill(checkout, receipt, aad.map(|v| *v))
                    .await
            }
        };
        if filled.is_err() {
            self.set_state(&operation, "disclosure_unknown");
        }
        self.saved_done();
        // Failed preparation releases nothing and keeps the same browser
        // available for correction and a fresh approval.
        if payment
            && self
                .store
                .get(&operation)
                .is_ok_and(|s| s.state == "failed_before_release")
        {
            checkout.operation_id = parent.clone();
            checkout.mode = Mode::TakeOver;
            checkout.discovery = None;
            checkout.recipient = None;
            self.set_state(&parent, "human_control");
            return;
        }
        drop(private);
        drop(gate);
        if payment {
            self.watch_outcome(operation).await;
        }
    }

    async fn fill_saved_traveler(
        &self,
        operation: &str,
        tab: &PrivateTab,
        discovery: TravelerDiscovery,
        recipient: Recipient,
        receipt: Option<Box<CustodyResult>>,
        aad: Option<Box<CustodyOutputHpkeAad>>,
    ) -> Result<()> {
        let mut status = self.store.consume(operation)?;
        let receipt = receipt.context("Traveler receipt unavailable")?;
        let aad = aad.context("Traveler binding unavailable")?;
        if receipt.custody_operation_id.as_str() != operation
            || aad.custody_operation_id.as_str() != operation
            || receipt.surface.as_ref() != Some(&aad.surface)
        {
            bail!("Traveler binding changed");
        }
        let plaintext = recipient.open(
            receipt
                .encrypted_browser_result
                .as_ref()
                .context("Traveler release unavailable")?,
            &aad.canonical_bytes()?,
        )?;
        let values: BTreeMap<String, zeroize::Zeroizing<String>> =
            serde_json::from_slice(&plaintext)?;
        // The discovery's nonce, document and field mapping are rechecked by
        // the fill script. A navigation during approval cannot retarget it.
        status.filled_fields = discovery.fill(tab, &values).await?;
        self.browser.remember_private_traveler_use();
        status.state = "traveler_filled".into();
        status.ceremony_url = None;
        self.store.update(&status)
    }
}
