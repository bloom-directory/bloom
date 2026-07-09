use crate::fs::{SetAttrs, SetTime};
use crate::internal::{ServerFileType, ServerObject};

use super::{StateInner, StateManager, SynthMeta};

impl StateManager {
    fn now() -> (i64, u32) {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (dur.as_secs() as i64, dur.subsec_nanos())
    }

    fn default_mode(file_type: ServerFileType) -> u32 {
        match file_type {
            ServerFileType::Regular | ServerFileType::NamedAttr => 0o644,
            ServerFileType::Directory | ServerFileType::NamedAttrDir => 0o755,
            ServerFileType::Symlink => 0o777,
        }
    }

    fn default_nlink(file_type: ServerFileType) -> u32 {
        match file_type {
            ServerFileType::Directory | ServerFileType::NamedAttrDir => 2,
            _ => 1,
        }
    }

    fn ensure_meta_locked(
        &self,
        inner: &mut StateInner,
        object: &ServerObject,
        file_type: ServerFileType,
    ) -> SynthMeta {
        if let Some(meta) = inner.metadata.get(object) {
            return meta.clone();
        }

        let (now_s, now_ns) = Self::now();
        let fileid = match object {
            ServerObject::Fs(id) => *id,
            ServerObject::NamedAttrDir(_) | ServerObject::NamedAttrFile { .. } => self
                .next_synth_fileid
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
        let meta = SynthMeta {
            fileid,
            mode: Self::default_mode(file_type),
            nlink: Self::default_nlink(file_type),
            uid: 0,
            gid: 0,
            owner: "root".into(),
            owner_group: "root".into(),
            atime_sec: now_s,
            atime_nsec: now_ns,
            mtime_sec: now_s,
            mtime_nsec: now_ns,
            ctime_sec: now_s,
            ctime_nsec: now_ns,
            crtime_sec: now_s,
            crtime_nsec: now_ns,
            change_id: self
                .next_changeid
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            archive: false,
            hidden: false,
            system: false,
            named_attr_count: None,
        };
        let _ = inner.metadata.insert(object.clone(), meta.clone());
        meta
    }

    pub(crate) async fn ensure_meta(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
    ) -> SynthMeta {
        let mut inner = self.inner.write().await;
        self.ensure_meta_locked(&mut inner, object, file_type)
    }

    pub(crate) async fn touch_data(&self, object: &ServerObject, file_type: ServerFileType) {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        let (now_s, now_ns) = Self::now();
        meta.mtime_sec = now_s;
        meta.mtime_nsec = now_ns;
        meta.ctime_sec = now_s;
        meta.ctime_nsec = now_ns;
        meta.change_id = self
            .next_changeid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = inner.metadata.insert(object.clone(), meta);
    }

    pub(crate) async fn named_attr_count(&self, object: &ServerObject) -> Option<u64> {
        let inner = self.inner.read().await;
        inner
            .metadata
            .get(object)
            .and_then(|meta| meta.named_attr_count)
    }

    pub(crate) async fn set_named_attr_count(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
        count: u64,
    ) {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        meta.named_attr_count = Some(count);
        let _ = inner.metadata.insert(object.clone(), meta);
    }

    pub(crate) async fn touch_metadata(&self, object: &ServerObject, file_type: ServerFileType) {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        let (now_s, now_ns) = Self::now();
        meta.ctime_sec = now_s;
        meta.ctime_nsec = now_ns;
        meta.mtime_sec = now_s;
        meta.mtime_nsec = now_ns;
        meta.change_id = self
            .next_changeid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = inner.metadata.insert(object.clone(), meta);
    }

    pub(crate) async fn apply_setattr(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
        attrs: &SetAttrs,
    ) {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        let (now_s, now_ns) = Self::now();

        if let Some(mode) = attrs.mode {
            meta.mode = mode;
        }
        if let Some(archive) = attrs.archive {
            meta.archive = archive;
        }
        if let Some(hidden) = attrs.hidden {
            meta.hidden = hidden;
        }
        if let Some(uid) = attrs.uid {
            meta.uid = uid;
        }
        if let Some(gid) = attrs.gid {
            meta.gid = gid;
        }
        if let Some(system) = attrs.system {
            meta.system = system;
        }
        if let Some(atime) = attrs.atime {
            match atime {
                SetTime::ServerNow => {
                    meta.atime_sec = now_s;
                    meta.atime_nsec = now_ns;
                }
                SetTime::Client(ts) => {
                    meta.atime_sec = ts.seconds;
                    meta.atime_nsec = ts.nanos;
                }
            }
        }
        if let Some(mtime) = attrs.mtime {
            match mtime {
                SetTime::ServerNow => {
                    meta.mtime_sec = now_s;
                    meta.mtime_nsec = now_ns;
                }
                SetTime::Client(ts) => {
                    meta.mtime_sec = ts.seconds;
                    meta.mtime_nsec = ts.nanos;
                }
            }
        }
        if let Some(birthtime) = attrs.birthtime {
            match birthtime {
                SetTime::ServerNow => {
                    meta.crtime_sec = now_s;
                    meta.crtime_nsec = now_ns;
                }
                SetTime::Client(ts) => {
                    meta.crtime_sec = ts.seconds;
                    meta.crtime_nsec = ts.nanos;
                }
            }
        }

        if !attrs.is_empty() {
            meta.ctime_sec = now_s;
            meta.ctime_nsec = now_ns;
            meta.change_id = self
                .next_changeid
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let _ = inner.metadata.insert(object.clone(), meta);
    }
}
