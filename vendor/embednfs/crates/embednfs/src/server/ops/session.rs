use embednfs_proto::*;

use crate::fs::FileSystem;

use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_reclaim_complete(
        &self,
        args: &ReclaimCompleteArgs4,
        current_fh: &Option<NfsFh4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let Some(clientid) = sequence_clientid else {
            return NfsResop4::ReclaimComplete(NfsStat4::OpNotInSession);
        };

        if args.one_fs {
            if current_fh.is_none() {
                return NfsResop4::ReclaimComplete(NfsStat4::Nofilehandle);
            }
            if let Err(status) = self.resolve_object(current_fh).await {
                return NfsResop4::ReclaimComplete(status);
            }
        }

        match self.state.reclaim_complete(clientid, args.one_fs).await {
            Ok(()) => NfsResop4::ReclaimComplete(NfsStat4::Ok),
            Err(status) => NfsResop4::ReclaimComplete(status),
        }
    }
}
