use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use embednfs_proto::{
    ChannelAttrs4, ClientOwner4, Clientid4, CreateSessionArgs4, EXCHGID4_FLAG_CONFIRMED_R,
    EXCHGID4_FLAG_USE_NON_PNFS, ExchangeIdArgs4, NfsLockType4, NfsStat4, OPEN4_SHARE_ACCESS_BOTH,
    OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE,
    OPEN4_SHARE_DENY_WRITE, SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED, SequenceArgs4, Sequenceid4,
    StateOwner4, StateProtect4A, Stateid4, Verifier4,
};

use crate::internal::ServerObject;

use super::{StateConfig, StateManager};

#[derive(Clone)]
struct ManualClock {
    now: Arc<Mutex<Instant>>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
        }
    }

    fn config(&self, lease_duration: Duration) -> StateConfig {
        let now = self.now.clone();
        StateConfig {
            lease_duration,
            revoked_retention: lease_duration,
            now: Arc::new(move || *now.lock().unwrap()),
        }
    }

    fn advance(&self, delta: Duration) {
        let mut now = self.now.lock().unwrap();
        *now += delta;
    }
}

fn exchange_id_args(ownerid: &[u8], verifier: Verifier4) -> ExchangeIdArgs4 {
    ExchangeIdArgs4 {
        clientowner: ClientOwner4 {
            verifier,
            ownerid: ownerid.to_vec().into(),
        },
        flags: EXCHGID4_FLAG_USE_NON_PNFS,
        state_protect: StateProtect4A::None,
        client_impl_id: vec![],
    }
}

fn create_session_args(clientid: Clientid4, sequence: Sequenceid4) -> CreateSessionArgs4 {
    CreateSessionArgs4 {
        clientid,
        sequence,
        flags: 0,
        fore_chan_attrs: ChannelAttrs4::default(),
        back_chan_attrs: ChannelAttrs4::default(),
        cb_program: 0,
        sec_parms: vec![],
    }
}

async fn setup_open_state(
    state: &StateManager,
    object: ServerObject,
    clientid: Clientid4,
) -> Stateid4 {
    state
        .create_open_state(
            object,
            clientid,
            OPEN4_SHARE_ACCESS_BOTH,
            OPEN4_SHARE_DENY_NONE,
        )
        .await
        .unwrap()
}

fn sequence_args(sessionid: [u8; 16], sequenceid: u32) -> SequenceArgs4 {
    SequenceArgs4 {
        sessionid,
        sequenceid,
        slotid: 0,
        highest_slotid: 0,
        cachethis: false,
    }
}

fn state_with_lease(lease_duration: Duration) -> (StateManager, ManualClock) {
    let clock = ManualClock::new();
    let state = StateManager::with_config(clock.config(lease_duration));
    (state, clock)
}

#[tokio::test]
async fn test_test_stateids_recognizes_open_and_lock_stateids() {
    let state = StateManager::new();
    let object = ServerObject::Fs(1);
    let open_stateid = setup_open_state(&state, object.clone(), 11).await;
    let owner = StateOwner4 {
        clientid: 11,
        owner: b"lock-owner".to_vec().into(),
    };
    let lock_stateid = state
        .create_lock_state(&open_stateid, &owner, object, NfsLockType4::WriteLt, 0, 10)
        .await
        .unwrap();

    let unknown = Stateid4 {
        seqid: 1,
        other: [0x55; 12],
    };
    let results = state
        .test_stateids(&[open_stateid, lock_stateid, unknown], None)
        .await;
    assert_eq!(
        results,
        vec![NfsStat4::Ok, NfsStat4::Ok, NfsStat4::BadStateid]
    );
}

#[tokio::test]
async fn test_test_stateids_checks_nonzero_seqids() {
    let state = StateManager::new();
    let object = ServerObject::Fs(1);
    let open_stateid = setup_open_state(&state, object.clone(), 17).await;
    let downgraded = state
        .open_downgrade(
            &open_stateid,
            OPEN4_SHARE_ACCESS_READ,
            OPEN4_SHARE_DENY_NONE,
        )
        .await
        .unwrap();
    let owner = StateOwner4 {
        clientid: 17,
        owner: b"lock-owner".to_vec().into(),
    };
    let lock_stateid = state
        .create_lock_state(&downgraded, &owner, object, NfsLockType4::WriteLt, 0, 10)
        .await
        .unwrap();
    let updated_lock = state
        .update_lock_state(&lock_stateid, NfsLockType4::WriteLt, 20, 10)
        .await
        .unwrap();

    let results = state
        .test_stateids(
            &[
                Stateid4 {
                    seqid: 0,
                    other: downgraded.other,
                },
                open_stateid,
                downgraded,
                lock_stateid,
                updated_lock,
                Stateid4 {
                    seqid: updated_lock.seqid.wrapping_add(1),
                    other: updated_lock.other,
                },
            ],
            None,
        )
        .await;

    assert_eq!(
        results,
        vec![
            NfsStat4::Ok,
            NfsStat4::OldStateid,
            NfsStat4::Ok,
            NfsStat4::OldStateid,
            NfsStat4::Ok,
            NfsStat4::BadStateid,
        ]
    );
}

#[tokio::test]
async fn test_exchange_id_reuses_existing_client_when_verifier_matches() {
    let state = StateManager::new();
    let args = exchange_id_args(b"owner", [0x11; 8]);

    let first = state.exchange_id(&args).await.unwrap();
    let _ = state
        .create_session(&create_session_args(first.clientid, first.sequenceid), 1)
        .await
        .unwrap();

    let second = state.exchange_id(&args).await.unwrap();

    assert_eq!(second.clientid, first.clientid);
    assert_eq!(
        second.flags & EXCHGID4_FLAG_CONFIRMED_R,
        EXCHGID4_FLAG_CONFIRMED_R
    );
}

#[tokio::test]
async fn test_exchange_id_reboot_drops_old_state_after_new_create_session() {
    let state = StateManager::new();
    let original = state
        .exchange_id(&exchange_id_args(b"owner", [0x11; 8]))
        .await
        .unwrap();
    let original_session = state
        .create_session(
            &create_session_args(original.clientid, original.sequenceid),
            1,
        )
        .await
        .unwrap();

    let object = ServerObject::Fs(1);
    let open_stateid = setup_open_state(&state, object.clone(), original.clientid).await;
    let owner = StateOwner4 {
        clientid: original.clientid,
        owner: b"lock-owner".to_vec().into(),
    };
    let lock_stateid = state
        .create_lock_state(&open_stateid, &owner, object, NfsLockType4::WriteLt, 0, 10)
        .await
        .unwrap();

    let rebooted = state
        .exchange_id(&exchange_id_args(b"owner", [0x22; 8]))
        .await
        .unwrap();
    assert_ne!(rebooted.clientid, original.clientid);
    assert_eq!(
        state.session_clientid(&original_session.sessionid).await,
        Some(original.clientid)
    );
    assert_eq!(
        state
            .test_stateids(&[open_stateid, lock_stateid], None)
            .await,
        vec![NfsStat4::Ok, NfsStat4::Ok]
    );

    let _ = state
        .create_session(
            &create_session_args(rebooted.clientid, rebooted.sequenceid),
            2,
        )
        .await
        .unwrap();

    assert_eq!(
        state.session_clientid(&original_session.sessionid).await,
        None
    );
    assert_eq!(
        state
            .test_stateids(&[open_stateid, lock_stateid], None)
            .await,
        vec![NfsStat4::BadStateid, NfsStat4::BadStateid]
    );
}

#[tokio::test]
async fn test_create_session_returns_stale_clientid_after_lease_expiry() {
    let (state, clock) = state_with_lease(Duration::from_secs(1));
    let client = state
        .exchange_id(&exchange_id_args(b"owner", [0x11; 8]))
        .await
        .unwrap();

    clock.advance(Duration::from_secs(2));

    assert_eq!(
        state
            .create_session(&create_session_args(client.clientid, client.sequenceid), 1)
            .await
            .unwrap_err(),
        NfsStat4::StaleClientid
    );
}

#[tokio::test]
async fn test_exchange_id_same_verifier_after_expiry_creates_fresh_client() {
    let (state, clock) = state_with_lease(Duration::from_secs(1));
    let args = exchange_id_args(b"owner", [0x11; 8]);
    let first = state.exchange_id(&args).await.unwrap();
    let session = state
        .create_session(&create_session_args(first.clientid, first.sequenceid), 1)
        .await
        .unwrap();

    clock.advance(Duration::from_secs(2));

    let second = state.exchange_id(&args).await.unwrap();
    assert_ne!(second.clientid, first.clientid);
    let _ = state
        .create_session(&create_session_args(second.clientid, second.sequenceid), 2)
        .await
        .unwrap();
    assert_eq!(state.session_clientid(&session.sessionid).await, None);
}

#[tokio::test]
async fn test_expired_client_conflicts_are_reaped_for_other_clients() {
    let (state, clock) = state_with_lease(Duration::from_secs(1));
    let client = state
        .exchange_id(&exchange_id_args(b"owner", [0x11; 8]))
        .await
        .unwrap();
    let _ = state
        .create_session(&create_session_args(client.clientid, client.sequenceid), 1)
        .await
        .unwrap();
    let object = ServerObject::Fs(1);
    let _open_stateid = state
        .create_open_state(
            object.clone(),
            client.clientid,
            OPEN4_SHARE_ACCESS_READ,
            OPEN4_SHARE_DENY_WRITE,
        )
        .await
        .unwrap();

    assert!(
        state
            .has_conflicting_share_deny(&object, OPEN4_SHARE_ACCESS_WRITE, None)
            .await
    );

    clock.advance(Duration::from_secs(2));

    assert!(
        !state
            .has_conflicting_share_deny(&object, OPEN4_SHARE_ACCESS_WRITE, None)
            .await
    );
}

#[tokio::test]
async fn test_prepare_sequence_returns_expired_all_state_revoked_for_revoked_session() {
    let (state, clock) = state_with_lease(Duration::from_secs(1));
    let client = state
        .exchange_id(&exchange_id_args(b"owner", [0x11; 8]))
        .await
        .unwrap();
    let session = state
        .create_session(&create_session_args(client.clientid, client.sequenceid), 1)
        .await
        .unwrap();
    let open_stateid = setup_open_state(&state, ServerObject::Fs(1), client.clientid).await;

    clock.advance(Duration::from_secs(2));

    let replay = state
        .prepare_sequence(&sequence_args(session.sessionid, 1), b"expired", 1)
        .await;
    match replay {
        super::model::SequenceReplay::StatusOnly(res) => {
            assert_eq!(res.status_flags, SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED);
        }
        _ => panic!("expected revoked session status reply"),
    }
    assert_eq!(
        state.test_stateids(&[open_stateid], None).await,
        vec![NfsStat4::BadStateid]
    );
}

#[tokio::test]
async fn test_revoked_clients_are_dropped_after_retention() {
    let (state, clock) = state_with_lease(Duration::from_secs(1));
    let client = state
        .exchange_id(&exchange_id_args(b"owner", [0x11; 8]))
        .await
        .unwrap();
    let session = state
        .create_session(&create_session_args(client.clientid, client.sequenceid), 1)
        .await
        .unwrap();

    clock.advance(Duration::from_secs(2));
    let _ = state
        .prepare_sequence(&sequence_args(session.sessionid, 1), b"expired", 1)
        .await;

    clock.advance(Duration::from_secs(2));
    state.reap_expired_clients().await;

    assert_eq!(state.session_clientid(&session.sessionid).await, None);
    assert_eq!(
        state
            .create_session(&create_session_args(client.clientid, client.sequenceid), 1)
            .await
            .unwrap_err(),
        NfsStat4::StaleClientid
    );
}

#[tokio::test]
async fn test_existing_lock_owner_tracks_multiple_ranges() {
    let state = StateManager::new();
    let object = ServerObject::Fs(7);
    let open_stateid = setup_open_state(&state, object.clone(), 22).await;
    let owner = StateOwner4 {
        clientid: 22,
        owner: b"owner".to_vec().into(),
    };

    let lock_stateid = state
        .create_lock_state(
            &open_stateid,
            &owner,
            object.clone(),
            NfsLockType4::WriteLt,
            0,
            10,
        )
        .await
        .unwrap();
    let _ = state
        .update_lock_state(&lock_stateid, NfsLockType4::WriteLt, 20, 10)
        .await
        .unwrap();

    let inner = state.inner.read().await;
    let lock = inner.lock_files.get(&lock_stateid.other).unwrap();
    assert!(lock.active);
    assert_eq!(lock.ranges.len(), 2);
    assert_eq!(lock.ranges[0].offset, 0);
    assert_eq!(lock.ranges[1].offset, 20);
}

#[tokio::test]
async fn test_open_downgrade_validates_subset_and_bumps_seqid() {
    let state = StateManager::new();
    let open_stateid = setup_open_state(&state, ServerObject::Fs(7), 22).await;

    let downgraded = state
        .open_downgrade(
            &open_stateid,
            OPEN4_SHARE_ACCESS_READ,
            OPEN4_SHARE_DENY_NONE,
        )
        .await
        .unwrap();
    assert_eq!(downgraded.other, open_stateid.other);
    assert_eq!(downgraded.seqid, 2);

    let inner = state.inner.read().await;
    let open = inner.open_files.get(&open_stateid.other).unwrap();
    assert_eq!(open.share_access, OPEN4_SHARE_ACCESS_READ);
    assert_eq!(open.share_deny, OPEN4_SHARE_DENY_NONE);
    drop(inner);

    assert_eq!(
        state
            .open_downgrade(&downgraded, 0, OPEN4_SHARE_DENY_NONE)
            .await
            .unwrap_err(),
        NfsStat4::Inval
    );
    assert_eq!(
        state
            .open_downgrade(&downgraded, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,)
            .await
            .unwrap_err(),
        NfsStat4::Inval
    );
    assert_eq!(
        state
            .open_downgrade(&downgraded, OPEN4_SHARE_ACCESS_READ, 4)
            .await
            .unwrap_err(),
        NfsStat4::Inval
    );
}

#[tokio::test]
async fn test_unlock_splits_range_and_conflict_checks_all_ranges() {
    let state = StateManager::new();
    let object = ServerObject::Fs(9);
    let open1 = setup_open_state(&state, object.clone(), 31).await;
    let owner1 = StateOwner4 {
        clientid: 31,
        owner: b"owner1".to_vec().into(),
    };
    let lock_stateid = state
        .create_lock_state(
            &open1,
            &owner1,
            object.clone(),
            NfsLockType4::WriteLt,
            0,
            100,
        )
        .await
        .unwrap();

    let _ = state.unlock_state(&lock_stateid, 40, 20).await.unwrap();

    let inner = state.inner.read().await;
    let lock = inner.lock_files.get(&lock_stateid.other).unwrap();
    assert!(lock.active);
    assert_eq!(lock.ranges.len(), 2);
    assert_eq!(lock.ranges[0].offset, 0);
    assert_eq!(lock.ranges[0].length, 40);
    assert_eq!(lock.ranges[1].offset, 60);
    assert_eq!(lock.ranges[1].length, 40);
    drop(inner);

    let owner2 = StateOwner4 {
        clientid: 32,
        owner: b"owner2".to_vec().into(),
    };
    let denied_left = state
        .find_lock_conflict(&object, &owner2, NfsLockType4::WriteLt, 10, 5, None)
        .await;
    assert!(denied_left.is_some());
    let denied_middle = state
        .find_lock_conflict(&object, &owner2, NfsLockType4::WriteLt, 45, 5, None)
        .await;
    assert!(denied_middle.is_none());
    let denied_right = state
        .find_lock_conflict(&object, &owner2, NfsLockType4::WriteLt, 70, 5, None)
        .await;
    assert!(denied_right.is_some());
}

#[tokio::test]
async fn test_close_and_unlock_validate_stateid_seqids() {
    let state = StateManager::new();
    let object = ServerObject::Fs(9);
    let open_stateid = setup_open_state(&state, object.clone(), 31).await;
    let downgraded = state
        .open_downgrade(
            &open_stateid,
            OPEN4_SHARE_ACCESS_READ,
            OPEN4_SHARE_DENY_NONE,
        )
        .await
        .unwrap();

    assert_eq!(
        state.close_state(&open_stateid).await.unwrap_err(),
        NfsStat4::OldStateid
    );
    assert_eq!(
        state
            .close_state(&Stateid4 {
                seqid: downgraded.seqid.wrapping_add(1),
                other: downgraded.other,
            })
            .await
            .unwrap_err(),
        NfsStat4::BadStateid
    );
    let closed = state
        .close_state(&Stateid4 {
            seqid: 0,
            other: downgraded.other,
        })
        .await
        .unwrap();
    assert_eq!(closed.seqid, downgraded.seqid.wrapping_add(1));

    let open_stateid = setup_open_state(&state, object.clone(), 31).await;
    let owner = StateOwner4 {
        clientid: 31,
        owner: b"owner1".to_vec().into(),
    };
    let lock_stateid = state
        .create_lock_state(&open_stateid, &owner, object, NfsLockType4::WriteLt, 0, 100)
        .await
        .unwrap();
    let updated_lock = state
        .update_lock_state(&lock_stateid, NfsLockType4::WriteLt, 120, 20)
        .await
        .unwrap();

    assert_eq!(
        state.unlock_state(&lock_stateid, 0, 5).await.unwrap_err(),
        NfsStat4::OldStateid
    );
    assert_eq!(
        state
            .unlock_state(
                &Stateid4 {
                    seqid: updated_lock.seqid.wrapping_add(1),
                    other: updated_lock.other,
                },
                0,
                5,
            )
            .await
            .unwrap_err(),
        NfsStat4::BadStateid
    );
    let unlocked = state
        .unlock_state(
            &Stateid4 {
                seqid: 0,
                other: updated_lock.other,
            },
            0,
            5,
        )
        .await
        .unwrap();
    assert_eq!(unlocked.seqid, updated_lock.seqid.wrapping_add(1));
}
