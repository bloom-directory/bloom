use crate::internal::ServerObject;

use super::StateManager;

impl StateManager {
    pub(crate) fn alloc_connection_id(&self) -> u64 {
        self.next_connectionid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn object_to_fh(&self, object: &ServerObject) -> embednfs_proto::NfsFh4 {
        if let Some(fh) = self.object_to_fh.get(object) {
            return embednfs_proto::NfsFh4(fh.value().clone().into());
        }
        let fh_num = self
            .next_fh
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let fh = fh_num.to_be_bytes().to_vec();
        let _ = self.fh_to_object.insert(fh.clone(), object.clone());
        let _ = self.object_to_fh.insert(object.clone(), fh.clone());
        embednfs_proto::NfsFh4(fh.into())
    }

    pub(crate) fn fh_to_object(&self, fh: &embednfs_proto::NfsFh4) -> Option<ServerObject> {
        self.fh_to_object
            .get(fh.0.as_ref())
            .map(|r| r.value().clone())
    }
}
