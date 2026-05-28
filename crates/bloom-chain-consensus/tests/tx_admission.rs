use bloom_chain_consensus::tx_admission::{
    AdmitOutcome, AdmitReject, MAX_CHAIN_WASM_BYTES, SimpleBalanceView, check_admissible,
    deploy_petal_fuel_for_bytes,
};
use bloom_chain_types::tx::TxKind;
use bloom_script::{PtbTx, encode_ptb};
use bloom_test_util::make_mempool_tx;

fn view_for(tx: &bloom_chain_types::tx::Tx, nonce: u64, balance: u128) -> SimpleBalanceView {
    SimpleBalanceView {
        sender: tx.sender,
        nonce,
        balance,
        ptb_gas_payer_balance: u128::MAX,
    }
}

#[test]
fn future_nonce_is_allowed_only_when_not_strict() {
    let tx = make_mempool_tx(1, 3, 10, 1000, 0);
    let view = view_for(&tx, 0, 1_000_000);

    assert_eq!(check_admissible(&tx, &view, false), AdmitOutcome::Ok);
    assert!(matches!(
        check_admissible(&tx, &view, true),
        AdmitOutcome::Reject(AdmitReject::Nonce {
            expected: 1,
            got: 3
        })
    ));
}

#[test]
fn submit_ptb_reservation_overflow_is_rejected() {
    let ptb_bytes = encode_ptb(&PtbTx {
        gas_budget: u64::MAX,
        gas_price: u128::MAX,
        expiry_block: 100,
        ..PtbTx::default()
    })
    .unwrap();
    let mut tx = make_mempool_tx(1, 1, u64::MAX, u64::MAX, 0);
    tx.kind = TxKind::SubmitPtb { ptb_bytes };
    let view = view_for(&tx, 0, u128::MAX);

    assert!(matches!(
        check_admissible(&tx, &view, true),
        AdmitOutcome::Reject(AdmitReject::Overflow(reason))
            if reason.contains("gas reservation overflow")
    ));
}

#[test]
fn submit_ptb_checks_gas_payer_balance_not_outer_sender() {
    let ptb_bytes = encode_ptb(&PtbTx {
        gas_budget: 100,
        gas_price: 10,
        expiry_block: 100,
        ..PtbTx::default()
    })
    .unwrap();
    let mut tx = make_mempool_tx(1, 1, 10, 100, 0);
    tx.kind = TxKind::SubmitPtb { ptb_bytes };
    let mut view = view_for(&tx, 0, 0);
    view.ptb_gas_payer_balance = 999;

    assert_eq!(
        check_admissible(&tx, &view, true),
        AdmitOutcome::Reject(AdmitReject::InsufficientBalance {
            need: 1000,
            have: 999
        })
    );

    view.ptb_gas_payer_balance = 1000;
    assert_eq!(check_admissible(&tx, &view, true), AdmitOutcome::Ok);
}

#[test]
fn deploy_petal_requires_intrinsic_fuel_at_admission() {
    let mut tx = make_mempool_tx(1, 1, 10, 1, 0);
    tx.kind = TxKind::DeployPetal {
        wasm_bytes: b"module".to_vec(),
    };
    let view = view_for(&tx, 0, 1_000_000);
    let required = deploy_petal_fuel_for_bytes(6);

    assert_eq!(
        check_admissible(&tx, &view, true),
        AdmitOutcome::Reject(AdmitReject::IntrinsicFuel { required, got: 1 })
    );
}

#[test]
fn deploy_petal_rejects_oversized_wasm_at_admission() {
    let mut tx = make_mempool_tx(1, 1, 10, u64::MAX, 0);
    tx.kind = TxKind::DeployPetal {
        wasm_bytes: vec![0u8; MAX_CHAIN_WASM_BYTES + 1],
    };
    let view = view_for(&tx, 0, u128::MAX);

    assert!(matches!(
        check_admissible(&tx, &view, true),
        AdmitOutcome::Reject(AdmitReject::EnvelopeInvalid(reason))
            if reason.contains("wasm size")
    ));
}
