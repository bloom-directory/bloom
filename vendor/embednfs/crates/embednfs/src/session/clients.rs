use std::collections::HashSet;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use embednfs_proto::{
    BindConnToSessionArgs4, BindConnToSessionRes4, ChannelAttrs4, Clientid4, CreateSessionArgs4,
    CreateSessionRes4, EXCHGID4_FLAG_CONFIRMED_R, EXCHGID4_FLAG_USE_NON_PNFS, ExchangeIdArgs4,
    ExchangeIdRes4, NfsImplId4, NfsStat4, NfsTime4, OpenClaim4,
    SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED, Sessionid4, StateProtect4R,
};

use super::model::{ClientLeaseState, ClientState, SessionState, SlotState, StateInner};
use super::{MAX_CACHED_RESPONSE, MAX_FORE_CHAN_SLOTS, MAX_REQUEST_SIZE, StateManager};

impl StateManager {
    /// Handle EXCHANGE_ID.
    pub(crate) async fn exchange_id(
        &self,
        args: &ExchangeIdArgs4,
    ) -> Result<ExchangeIdRes4, NfsStat4> {
        if !matches!(args.state_protect, embednfs_proto::StateProtect4A::None) {
            return Err(NfsStat4::Inval);
        }

        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);

        let (clientid, seq, confirmed) = if let Some(existing) =
            inner.clients.values().find(|client| {
                client.owner.ownerid == args.clientowner.ownerid
                    && client.owner.verifier == args.clientowner.verifier
                    && matches!(client.lease_state, ClientLeaseState::Active { .. })
            }) {
            (existing.clientid, existing.sequence_id, existing.confirmed)
        } else {
            let old_clientid = inner
                .clients
                .values()
                .find(|client| {
                    client.owner.ownerid == args.clientowner.ownerid
                        && client.owner.verifier != args.clientowner.verifier
                        && (client.confirmed
                            || matches!(client.lease_state, ClientLeaseState::Revoked { .. }))
                })
                .map(|client| client.clientid)
                .or_else(|| {
                    inner
                        .clients
                        .values()
                        .find(|client| {
                            client.owner.ownerid == args.clientowner.ownerid
                                && client.owner.verifier == args.clientowner.verifier
                                && matches!(client.lease_state, ClientLeaseState::Revoked { .. })
                        })
                        .map(|client| client.clientid)
                });

            let stale_unconfirmed: Vec<_> = inner
                .clients
                .values()
                .filter(|client| {
                    client.owner.ownerid == args.clientowner.ownerid
                        && client.owner.verifier != args.clientowner.verifier
                        && !client.confirmed
                        && matches!(client.lease_state, ClientLeaseState::Active { .. })
                })
                .map(|client| client.clientid)
                .collect();
            for stale_clientid in stale_unconfirmed {
                let _ = Self::drop_client_state(&mut inner, stale_clientid);
            }

            let id = self.next_clientid.fetch_add(1, Ordering::Relaxed);
            let _ = inner.clients.insert(
                id,
                ClientState {
                    clientid: id,
                    owner: args.clientowner.clone(),
                    confirmed: false,
                    reclaim_complete_global: false,
                    sequence_id: 1,
                    replaced_clientid: old_clientid,
                    lease_state: ClientLeaseState::Active {
                        deadline: self.lease_deadline(now),
                    },
                },
            );
            (id, 1, false)
        };
        let confirmed_flag = if confirmed {
            EXCHGID4_FLAG_CONFIRMED_R
        } else {
            0
        };

        Ok(ExchangeIdRes4 {
            clientid,
            sequenceid: seq,
            flags: EXCHGID4_FLAG_USE_NON_PNFS | confirmed_flag,
            state_protect: StateProtect4R::None,
            server_owner: self.server_owner.clone(),
            server_scope: Bytes::from_static(b"embednfs"),
            server_impl_id: vec![NfsImplId4 {
                domain: "embednfs.local".into(),
                name: "embednfs".into(),
                date: NfsTime4 {
                    seconds: 0,
                    nseconds: 0,
                },
            }],
        })
    }

    /// Handle CREATE_SESSION.
    pub(crate) async fn create_session(
        &self,
        args: &CreateSessionArgs4,
        connection_id: u64,
    ) -> Result<CreateSessionRes4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);

        let (replaced_clientid, client_sequence_id) = {
            let client = inner
                .clients
                .get_mut(&args.clientid)
                .ok_or(NfsStat4::StaleClientid)?;
            if matches!(client.lease_state, ClientLeaseState::Revoked { .. }) {
                return Err(NfsStat4::StaleClientid);
            }

            if args.sequence != client.sequence_id {
                return Err(NfsStat4::SeqMisordered);
            }
            client.sequence_id += 1;
            client.confirmed = true;
            client.lease_state = ClientLeaseState::Active {
                deadline: self.lease_deadline(now),
            };
            (client.replaced_clientid.take(), client.sequence_id)
        };

        if let Some(old_clientid) = replaced_clientid {
            let _ = Self::drop_client_state(&mut inner, old_clientid);
        }

        let mut sessionid = [0u8; 16];
        sessionid[..8].copy_from_slice(&args.clientid.to_be_bytes());
        sessionid[8..16].copy_from_slice(&(client_sequence_id as u64).to_be_bytes());

        let max_slots = args.fore_chan_attrs.maxrequests.min(MAX_FORE_CHAN_SLOTS) as usize;
        let slots = vec![
            SlotState {
                sequence_id: 1,
                in_progress: None,
                cached_reply: None,
            };
            max_slots.max(1)
        ];

        let fore_chan = ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: args.fore_chan_attrs.maxrequestsize.min(MAX_REQUEST_SIZE),
            maxresponsesize: args.fore_chan_attrs.maxresponsesize.min(MAX_REQUEST_SIZE),
            maxresponsesize_cached: args
                .fore_chan_attrs
                .maxresponsesize_cached
                .min(MAX_CACHED_RESPONSE),
            maxoperations: args.fore_chan_attrs.maxoperations.min(MAX_FORE_CHAN_SLOTS),
            maxrequests: max_slots as u32,
            rdma_ird: vec![],
        };

        let back_chan = ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: 4096,
            maxresponsesize: 4096,
            maxresponsesize_cached: 0,
            maxoperations: 2,
            maxrequests: 1,
            rdma_ird: vec![],
        };

        let _ = inner.sessions.insert(
            sessionid,
            SessionState {
                clientid: args.clientid,
                slots,
                connections: HashSet::from([connection_id]),
            },
        );

        Ok(CreateSessionRes4 {
            sessionid,
            sequenceid: args.sequence,
            flags: 0,
            fore_chan_attrs: fore_chan,
            back_chan_attrs: back_chan,
        })
    }

    /// Handle DESTROY_SESSION.
    pub(crate) async fn destroy_session(
        &self,
        sessionid: &Sessionid4,
        connection_id: u64,
    ) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);
        let Some(session) = inner.sessions.get(sessionid) else {
            return Err(NfsStat4::BadSession);
        };
        if !session.connections.contains(&connection_id) {
            return Err(NfsStat4::ConnNotBoundToSession);
        }
        let _ = inner.sessions.remove(sessionid);
        Ok(())
    }

    /// Handle DESTROY_CLIENTID.
    pub(crate) async fn destroy_clientid(&self, clientid: Clientid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);
        if Self::client_has_active_state(&inner, clientid) {
            return Err(NfsStat4::ClientidBusy);
        }
        if Self::drop_client_state(&mut inner, clientid) {
            Ok(())
        } else {
            Err(NfsStat4::StaleClientid)
        }
    }

    /// Handle BIND_CONN_TO_SESSION.
    pub(crate) async fn bind_conn_to_session(
        &self,
        args: &BindConnToSessionArgs4,
        connection_id: u64,
    ) -> Result<BindConnToSessionRes4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);
        let Some(session) = inner.sessions.get_mut(&args.sessionid) else {
            return Err(NfsStat4::BadSession);
        };
        let _ = session.connections.insert(connection_id);
        Ok(BindConnToSessionRes4 {
            sessionid: args.sessionid,
            dir: args.dir,
            use_conn_in_rdma_mode: false,
        })
    }

    /// Look up the client ID associated with a session.
    pub(crate) async fn session_clientid(&self, sessionid: &Sessionid4) -> Option<Clientid4> {
        let inner = self.inner.read().await;
        inner
            .sessions
            .get(sessionid)
            .map(|session| session.clientid)
    }

    pub(crate) async fn reclaim_complete(
        &self,
        clientid: Clientid4,
        one_fs: bool,
    ) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);
        let client = inner
            .clients
            .get_mut(&clientid)
            .ok_or(NfsStat4::StaleClientid)?;
        if one_fs {
            return Ok(());
        }
        if client.reclaim_complete_global {
            return Err(NfsStat4::CompleteAlready);
        }
        client.reclaim_complete_global = true;
        Ok(())
    }

    pub(crate) async fn validate_open_reclaim(
        &self,
        clientid: Clientid4,
        claim: &OpenClaim4,
    ) -> Result<(), NfsStat4> {
        self.reap_expired_clients().await;
        let inner = self.inner.read().await;
        let client = inner
            .clients
            .get(&clientid)
            .ok_or(NfsStat4::StaleClientid)?;
        if matches!(client.lease_state, ClientLeaseState::Revoked { .. }) {
            return Err(NfsStat4::StaleClientid);
        }
        match claim {
            OpenClaim4::Previous(_) if client.reclaim_complete_global => Err(NfsStat4::NoGrace),
            _ => Ok(()),
        }
    }

    pub(super) async fn reap_expired_clients(&self) {
        let mut inner = self.inner.write().await;
        let now = self.config.now();
        self.reap_expired_clients_locked(&mut inner, now);
    }

    pub(super) fn lease_deadline(&self, now: std::time::Instant) -> std::time::Instant {
        now + self.config.lease_duration
    }

    pub(super) fn reap_expired_clients_locked(
        &self,
        inner: &mut StateInner,
        now: std::time::Instant,
    ) {
        let expired_active: Vec<_> = inner
            .clients
            .iter()
            .filter_map(|(clientid, client)| match client.lease_state {
                ClientLeaseState::Active { deadline } if now >= deadline => Some(*clientid),
                _ => None,
            })
            .collect();

        for clientid in expired_active {
            Self::revoke_client_state(inner, clientid);
            if let Some(client) = inner.clients.get_mut(&clientid) {
                client.lease_state = ClientLeaseState::Revoked {
                    since: now,
                    status_flags: SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED,
                };
            }
        }

        let drop_revoked: Vec<_> = inner
            .clients
            .iter()
            .filter_map(|(clientid, client)| match client.lease_state {
                ClientLeaseState::Revoked { since, .. }
                    if now.duration_since(since) >= self.config.revoked_retention
                        || !inner
                            .sessions
                            .values()
                            .any(|session| session.clientid == *clientid) =>
                {
                    Some(*clientid)
                }
                _ => None,
            })
            .collect();
        for clientid in drop_revoked {
            let _ = Self::drop_client_state(inner, clientid);
        }
    }

    fn revoke_client_state(inner: &mut StateInner, clientid: Clientid4) {
        inner
            .open_files
            .retain(|_, state| state.clientid != clientid);
        inner
            .lock_files
            .retain(|_, state| state.owner.clientid != clientid);
    }

    pub(super) fn drop_client_state(inner: &mut StateInner, clientid: Clientid4) -> bool {
        inner
            .sessions
            .retain(|_, session| session.clientid != clientid);
        Self::revoke_client_state(inner, clientid);
        inner.clients.remove(&clientid).is_some()
    }

    pub(super) fn client_has_active_state(inner: &StateInner, clientid: Clientid4) -> bool {
        inner
            .sessions
            .values()
            .any(|session| session.clientid == clientid)
            || inner
                .open_files
                .values()
                .any(|state| state.clientid == clientid)
            || inner
                .lock_files
                .values()
                .any(|state| state.owner.clientid == clientid)
    }
}
