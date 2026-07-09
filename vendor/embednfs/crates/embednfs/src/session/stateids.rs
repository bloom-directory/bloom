use embednfs_proto::{Clientid4, NfsStat4, Stateid4};

use super::StateManager;
use super::model::{ResolvedLockState, ResolvedOpenState, ResolvedStateid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CurrentStateidMode {
    ZeroSeqid,
    PreserveSeqid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NormalizedStateid {
    Anonymous,
    Bypass,
    Concrete(Stateid4),
}

impl StateManager {
    pub(crate) fn share_access_mode(&self, share_access: u32) -> u32 {
        share_access & !embednfs_proto::OPEN4_SHARE_ACCESS_WANT_DELEG_MASK
    }

    pub(crate) fn normalize_stateid(
        &self,
        requested: &Stateid4,
        current_stateid: Option<Stateid4>,
        current_mode: CurrentStateidMode,
    ) -> Result<NormalizedStateid, NfsStat4> {
        if *requested == Stateid4::ANONYMOUS {
            return Ok(NormalizedStateid::Anonymous);
        }
        if *requested == Stateid4::BYPASS {
            return Ok(NormalizedStateid::Bypass);
        }
        if *requested == Stateid4::CURRENT {
            let current = current_stateid.ok_or(NfsStat4::BadStateid)?;
            if Self::is_special_stateid(&current) {
                return Err(NfsStat4::BadStateid);
            }
            return Ok(NormalizedStateid::Concrete(match current_mode {
                CurrentStateidMode::ZeroSeqid => Stateid4 {
                    seqid: 0,
                    other: current.other,
                },
                CurrentStateidMode::PreserveSeqid => current,
            }));
        }
        if Self::is_invalid_special_stateid(requested) {
            return Err(NfsStat4::BadStateid);
        }
        Ok(NormalizedStateid::Concrete(*requested))
    }

    pub(crate) async fn resolve_stateid(
        &self,
        clientid: Clientid4,
        requested: &Stateid4,
        current_stateid: Option<Stateid4>,
        current_mode: CurrentStateidMode,
    ) -> Result<ResolvedStateid, NfsStat4> {
        self.reap_expired_clients().await;
        match self.normalize_stateid(requested, current_stateid, current_mode)? {
            NormalizedStateid::Anonymous => Ok(ResolvedStateid::Anonymous),
            NormalizedStateid::Bypass => Ok(ResolvedStateid::Bypass),
            NormalizedStateid::Concrete(stateid) => {
                let inner = self.inner.read().await;

                if let Some(open) = inner.open_files.get(&stateid.other) {
                    Self::validate_stateid_seq(open.stateid_seq, stateid.seqid)?;
                    if !open.active || open.clientid != clientid {
                        return Err(NfsStat4::BadStateid);
                    }
                    return Ok(ResolvedStateid::Open(ResolvedOpenState {
                        other: stateid.other,
                        object: open.object.clone(),
                        share_access: open.share_access,
                    }));
                }

                if let Some(lock) = inner.lock_files.get(&stateid.other) {
                    Self::validate_stateid_seq(lock.stateid_seq, stateid.seqid)?;
                    if lock.owner.clientid != clientid {
                        return Err(NfsStat4::BadStateid);
                    }
                    let open = inner
                        .open_files
                        .get(&lock.open_state_other)
                        .ok_or(NfsStat4::BadStateid)?;
                    if !open.active || open.clientid != clientid {
                        return Err(NfsStat4::BadStateid);
                    }
                    return Ok(ResolvedStateid::Lock(ResolvedLockState {
                        other: stateid.other,
                        object: lock.object.clone(),
                        owner: lock.owner.clone(),
                        open_state: ResolvedOpenState {
                            other: lock.open_state_other,
                            object: open.object.clone(),
                            share_access: open.share_access,
                        },
                    }));
                }

                Err(NfsStat4::BadStateid)
            }
        }
    }

    pub(crate) fn is_special_stateid(stateid: &Stateid4) -> bool {
        *stateid == Stateid4::ANONYMOUS
            || *stateid == Stateid4::BYPASS
            || *stateid == Stateid4::CURRENT
    }

    fn is_invalid_special_stateid(stateid: &Stateid4) -> bool {
        let all_zero_other = stateid.other == [0u8; 12];
        let all_one_other = stateid.other == [0xFFu8; 12];
        (all_zero_other || all_one_other) && !Self::is_special_stateid(stateid)
    }
}
