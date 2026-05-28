use bloom_chain_types::{
    tx::{Tx, TxKind},
    types::Address,
};
use bloom_script::{PtbTx, decode_ptb};

pub trait BalanceView {
    fn nonce(&self, addr: &Address) -> u64;
    fn loom_balance(&self, addr: &Address) -> u128;
    fn ptb_gas_payer_balance(&self, ptb: &PtbTx) -> Result<u128, AdmitReject>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    Ok,
    Reject(AdmitReject),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitReject {
    SenderMismatch,
    Nonce { expected: u64, got: u64 },
    InsufficientBalance { need: u128, have: u128 },
    EnvelopeInvalid(String),
    IntrinsicFuel { required: u64, got: u64 },
    Overflow(String),
}

pub fn check_admissible(tx: &Tx, view: &dyn BalanceView, strict_nonce: bool) -> AdmitOutcome {
    let derived = Address::from_pubkey_bytes(&tx.pubkey.0);
    if derived != tx.sender {
        return AdmitOutcome::Reject(AdmitReject::SenderMismatch);
    }

    let current_nonce = view.nonce(&tx.sender);
    let Some(expected_nonce) = current_nonce.checked_add(1) else {
        return AdmitOutcome::Reject(AdmitReject::Overflow(
            "sender nonce cannot advance".to_string(),
        ));
    };
    let nonce_ok = if strict_nonce {
        tx.nonce == expected_nonce
    } else {
        tx.nonce >= expected_nonce
    };
    if !nonce_ok {
        return AdmitOutcome::Reject(AdmitReject::Nonce {
            expected: expected_nonce,
            got: tx.nonce,
        });
    }

    match &tx.kind {
        TxKind::SubmitPtb { ptb_bytes } => check_submit_ptb(tx, ptb_bytes, view),
        TxKind::DeployPetal { .. } => check_sender_funded(tx, 0, view),
    }
}

fn check_sender_funded(tx: &Tx, value: u128, view: &dyn BalanceView) -> AdmitOutcome {
    if tx.max_fuel == 0 || tx.fee_per_unit == 0 {
        return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(
            "max_fuel and fee_per_unit must be non-zero".to_string(),
        ));
    }
    let Some(fee_reservation) = (tx.max_fuel as u128).checked_mul(tx.fee_per_unit as u128) else {
        return AdmitOutcome::Reject(AdmitReject::InsufficientBalance {
            need: u128::MAX,
            have: view.loom_balance(&tx.sender),
        });
    };
    let Some(need) = fee_reservation.checked_add(value) else {
        return AdmitOutcome::Reject(AdmitReject::InsufficientBalance {
            need: u128::MAX,
            have: view.loom_balance(&tx.sender),
        });
    };
    let have = view.loom_balance(&tx.sender);
    if have < need {
        return AdmitOutcome::Reject(AdmitReject::InsufficientBalance { need, have });
    }
    AdmitOutcome::Ok
}

fn check_submit_ptb(tx: &Tx, ptb_bytes: &[u8], view: &dyn BalanceView) -> AdmitOutcome {
    let ptb = match decode_ptb(ptb_bytes) {
        Ok(ptb) => ptb,
        Err(e) => {
            return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(format!(
                "decode failed: {e}"
            )));
        }
    };
    if tx.max_fuel == 0 {
        return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(
            "outer max_fuel must be non-zero".to_string(),
        ));
    }
    if ptb.gas_budget == 0 {
        return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(
            "inner gas_budget must be non-zero".to_string(),
        ));
    }
    if ptb.gas_price == 0 {
        return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(
            "inner gas_price must be non-zero".to_string(),
        ));
    }
    if tx.max_fuel < ptb.gas_budget {
        return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(format!(
            "outer max_fuel {} below inner gas_budget {}",
            tx.max_fuel, ptb.gas_budget
        )));
    }
    let Some(reservation) = ptb.checked_gas_reservation() else {
        return AdmitOutcome::Reject(AdmitReject::Overflow(
            "gas reservation overflow".to_string(),
        ));
    };
    if (tx.fee_per_unit as u128) < ptb.gas_price {
        return AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(format!(
            "outer fee_per_unit {} below inner gas_price {}",
            tx.fee_per_unit, ptb.gas_price
        )));
    }
    let have = match view.ptb_gas_payer_balance(&ptb) {
        Ok(have) => have,
        Err(reject) => return AdmitOutcome::Reject(reject),
    };
    if have < reservation {
        return AdmitOutcome::Reject(AdmitReject::InsufficientBalance {
            need: reservation,
            have,
        });
    }
    AdmitOutcome::Ok
}

#[derive(Debug, Clone, Copy)]
pub struct SimpleBalanceView {
    pub sender: Address,
    pub nonce: u64,
    pub balance: u128,
    pub ptb_gas_payer_balance: u128,
}

impl BalanceView for SimpleBalanceView {
    fn nonce(&self, addr: &Address) -> u64 {
        if *addr == self.sender { self.nonce } else { 0 }
    }

    fn loom_balance(&self, addr: &Address) -> u128 {
        if *addr == self.sender {
            self.balance
        } else {
            0
        }
    }

    fn ptb_gas_payer_balance(&self, _ptb: &PtbTx) -> Result<u128, AdmitReject> {
        Ok(self.ptb_gas_payer_balance)
    }
}
