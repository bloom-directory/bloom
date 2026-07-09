use crate::fs::{FsCapabilities, FsLimits, FsStats, SetAttrs, SetTime, Timestamp};
use crate::internal::{ServerFileAttr, ServerFileType};
use crate::session::DEFAULT_LEASE_TIME_SECS;
/// NFSv4.1 file attribute encoding and decoding.
///
/// Handles the bitmap-driven attribute encoding used by GETATTR/SETATTR.
use bytes::BytesMut;
use embednfs_proto::xdr::*;
use embednfs_proto::*;
const MODE_PERM_MASK: u32 = 0o7777;

/// Snapshot of filesystem-wide values needed for attribute encoding.
pub(crate) struct AttrEncodingContext<'a> {
    pub limits: &'a FsLimits,
    pub stats: &'a FsStats,
    pub capabilities: &'a FsCapabilities,
}

pub(crate) fn supported_attrs_bitmap(capabilities: &FsCapabilities) -> Bitmap4 {
    let mut supported = Bitmap4::new();
    for bit in &[
        FATTR4_SUPPORTED_ATTRS,
        FATTR4_TYPE,
        FATTR4_FH_EXPIRE_TYPE,
        FATTR4_CHANGE,
        FATTR4_SIZE,
        FATTR4_LINK_SUPPORT,
        FATTR4_SYMLINK_SUPPORT,
        FATTR4_FSID,
        FATTR4_UNIQUE_HANDLES,
        FATTR4_LEASE_TIME,
        FATTR4_RDATTR_ERROR,
        FATTR4_FILEHANDLE,
        FATTR4_ACLSUPPORT,
        FATTR4_ARCHIVE,
        FATTR4_CANSETTIME,
        FATTR4_CASE_INSENSITIVE,
        FATTR4_CASE_PRESERVING,
        FATTR4_CHOWN_RESTRICTED,
        FATTR4_FILEID,
        FATTR4_FILES_AVAIL,
        FATTR4_FILES_FREE,
        FATTR4_FILES_TOTAL,
        FATTR4_HIDDEN,
        FATTR4_HOMOGENEOUS,
        FATTR4_MAXFILESIZE,
        FATTR4_MAXLINK,
        FATTR4_MAXNAME,
        FATTR4_MAXREAD,
        FATTR4_MAXWRITE,
        FATTR4_MODE,
        FATTR4_NO_TRUNC,
        FATTR4_NUMLINKS,
        FATTR4_OWNER,
        FATTR4_OWNER_GROUP,
        FATTR4_RAWDEV,
        FATTR4_SPACE_AVAIL,
        FATTR4_SPACE_FREE,
        FATTR4_SPACE_TOTAL,
        FATTR4_SPACE_USED,
        FATTR4_SYSTEM,
        FATTR4_TIME_ACCESS,
        FATTR4_TIME_ACCESS_SET,
        FATTR4_TIME_BACKUP,
        FATTR4_TIME_CREATE,
        FATTR4_TIME_DELTA,
        FATTR4_TIME_METADATA,
        FATTR4_TIME_MODIFY,
        FATTR4_TIME_MODIFY_SET,
        FATTR4_MOUNTED_ON_FILEID,
        FATTR4_SUPPATTR_EXCLCREAT,
    ] {
        supported.set(*bit);
    }
    if capabilities.xattrs {
        supported.set(FATTR4_NAMED_ATTR);
    }
    supported
}

/// Encode file attributes according to the requested bitmap.
pub(crate) fn encode_fattr4(
    attr: &ServerFileAttr,
    request: &Bitmap4,
    fh: &NfsFh4,
    ctx: &AttrEncodingContext<'_>,
) -> Fattr4 {
    let mut result_bitmap = Bitmap4::new();
    let mut vals = BytesMut::with_capacity(256);

    // Word 0 attributes (bits 0-31)

    // FATTR4_SUPPORTED_ATTRS (0) - mandatory
    if request.is_set(FATTR4_SUPPORTED_ATTRS) {
        result_bitmap.set(FATTR4_SUPPORTED_ATTRS);
        let supported = supported_attrs_bitmap(ctx.capabilities);
        supported.encode(&mut vals);
    }

    // FATTR4_TYPE (1) - mandatory
    if request.is_set(FATTR4_TYPE) {
        result_bitmap.set(FATTR4_TYPE);
        let nfs_type = match attr.file_type {
            ServerFileType::Regular => NfsFtype4::Reg,
            ServerFileType::Directory => NfsFtype4::Dir,
            ServerFileType::Symlink => NfsFtype4::Lnk,
            ServerFileType::NamedAttrDir => NfsFtype4::AttrDir,
            ServerFileType::NamedAttr => NfsFtype4::NamedAttr,
        };
        nfs_type.encode(&mut vals);
    }

    // FATTR4_FH_EXPIRE_TYPE (2) - mandatory
    if request.is_set(FATTR4_FH_EXPIRE_TYPE) {
        result_bitmap.set(FATTR4_FH_EXPIRE_TYPE);
        // FH4_PERSISTENT = 0x00
        0u32.encode(&mut vals);
    }

    // FATTR4_CHANGE (3) - mandatory
    if request.is_set(FATTR4_CHANGE) {
        result_bitmap.set(FATTR4_CHANGE);
        attr.change_id.encode(&mut vals);
    }

    // FATTR4_SIZE (4) - mandatory
    if request.is_set(FATTR4_SIZE) {
        result_bitmap.set(FATTR4_SIZE);
        attr.size.encode(&mut vals);
    }

    // FATTR4_LINK_SUPPORT (5)
    if request.is_set(FATTR4_LINK_SUPPORT) {
        result_bitmap.set(FATTR4_LINK_SUPPORT);
        ctx.capabilities.hard_links.encode(&mut vals);
    }

    // FATTR4_SYMLINK_SUPPORT (6)
    if request.is_set(FATTR4_SYMLINK_SUPPORT) {
        result_bitmap.set(FATTR4_SYMLINK_SUPPORT);
        ctx.capabilities.symlinks.encode(&mut vals);
    }

    // FATTR4_NAMED_ATTR (7)
    if request.is_set(FATTR4_NAMED_ATTR) {
        result_bitmap.set(FATTR4_NAMED_ATTR);
        attr.has_named_attrs.encode(&mut vals);
    }

    // FATTR4_FSID (8) - mandatory
    if request.is_set(FATTR4_FSID) {
        result_bitmap.set(FATTR4_FSID);
        // Use a non-zero fsid; macOS uses this to identify the filesystem
        let fsid = Fsid4 { major: 1, minor: 1 };
        fsid.encode(&mut vals);
    }

    // FATTR4_UNIQUE_HANDLES (9)
    if request.is_set(FATTR4_UNIQUE_HANDLES) {
        result_bitmap.set(FATTR4_UNIQUE_HANDLES);
        true.encode(&mut vals);
    }

    // FATTR4_LEASE_TIME (10) - mandatory
    if request.is_set(FATTR4_LEASE_TIME) {
        result_bitmap.set(FATTR4_LEASE_TIME);
        DEFAULT_LEASE_TIME_SECS.encode(&mut vals);
    }

    // FATTR4_RDATTR_ERROR (11) - mandatory
    if request.is_set(FATTR4_RDATTR_ERROR) {
        result_bitmap.set(FATTR4_RDATTR_ERROR);
        (NfsStat4::Ok as u32).encode(&mut vals);
    }

    // FATTR4_ACL (12) - skip
    // FATTR4_ACLSUPPORT (13)
    if request.is_set(FATTR4_ACLSUPPORT) {
        result_bitmap.set(FATTR4_ACLSUPPORT);
        0u32.encode(&mut vals); // no ACL support
    }

    // FATTR4_ARCHIVE (14) - macOS SF_ARCHIVED flag
    if request.is_set(FATTR4_ARCHIVE) {
        result_bitmap.set(FATTR4_ARCHIVE);
        attr.archive.encode(&mut vals);
    }

    // FATTR4_CANSETTIME (15)
    if request.is_set(FATTR4_CANSETTIME) {
        result_bitmap.set(FATTR4_CANSETTIME);
        true.encode(&mut vals);
    }

    // FATTR4_CASE_INSENSITIVE (16)
    if request.is_set(FATTR4_CASE_INSENSITIVE) {
        result_bitmap.set(FATTR4_CASE_INSENSITIVE);
        (!ctx.capabilities.case_sensitive).encode(&mut vals);
    }

    // FATTR4_CASE_PRESERVING (17)
    if request.is_set(FATTR4_CASE_PRESERVING) {
        result_bitmap.set(FATTR4_CASE_PRESERVING);
        ctx.capabilities.case_preserving.encode(&mut vals);
    }

    // FATTR4_CHOWN_RESTRICTED (18)
    if request.is_set(FATTR4_CHOWN_RESTRICTED) {
        result_bitmap.set(FATTR4_CHOWN_RESTRICTED);
        true.encode(&mut vals);
    }

    // FATTR4_FILEHANDLE (19)
    if request.is_set(FATTR4_FILEHANDLE) {
        result_bitmap.set(FATTR4_FILEHANDLE);
        fh.encode(&mut vals);
    }

    // FATTR4_FILEID (20)
    if request.is_set(FATTR4_FILEID) {
        result_bitmap.set(FATTR4_FILEID);
        attr.fileid.encode(&mut vals);
    }

    // FATTR4_FILES_AVAIL (21)
    if request.is_set(FATTR4_FILES_AVAIL) {
        result_bitmap.set(FATTR4_FILES_AVAIL);
        ctx.stats.avail_files.encode(&mut vals);
    }

    // FATTR4_FILES_FREE (22)
    if request.is_set(FATTR4_FILES_FREE) {
        result_bitmap.set(FATTR4_FILES_FREE);
        ctx.stats.free_files.encode(&mut vals);
    }

    // FATTR4_FILES_TOTAL (23)
    if request.is_set(FATTR4_FILES_TOTAL) {
        result_bitmap.set(FATTR4_FILES_TOTAL);
        ctx.stats.total_files.encode(&mut vals);
    }

    // FATTR4_HIDDEN (25) - macOS UF_HIDDEN flag
    if request.is_set(FATTR4_HIDDEN) {
        result_bitmap.set(FATTR4_HIDDEN);
        attr.hidden.encode(&mut vals);
    }

    // FATTR4_HOMOGENEOUS (26)
    if request.is_set(FATTR4_HOMOGENEOUS) {
        result_bitmap.set(FATTR4_HOMOGENEOUS);
        true.encode(&mut vals);
    }

    // FATTR4_MAXFILESIZE (27)
    if request.is_set(FATTR4_MAXFILESIZE) {
        result_bitmap.set(FATTR4_MAXFILESIZE);
        ctx.limits.max_file_size.encode(&mut vals);
    }

    // FATTR4_MAXLINK (28)
    if request.is_set(FATTR4_MAXLINK) {
        result_bitmap.set(FATTR4_MAXLINK);
        255u32.encode(&mut vals);
    }

    // FATTR4_MAXNAME (29)
    if request.is_set(FATTR4_MAXNAME) {
        result_bitmap.set(FATTR4_MAXNAME);
        ctx.limits.max_name_bytes.encode(&mut vals);
    }

    // FATTR4_MAXREAD (30)
    if request.is_set(FATTR4_MAXREAD) {
        result_bitmap.set(FATTR4_MAXREAD);
        (ctx.limits.max_read as u64).encode(&mut vals);
    }

    // FATTR4_MAXWRITE (31)
    if request.is_set(FATTR4_MAXWRITE) {
        result_bitmap.set(FATTR4_MAXWRITE);
        (ctx.limits.max_write as u64).encode(&mut vals);
    }

    // Word 1 attributes (bits 32-63)

    // FATTR4_MODE (33)
    if request.is_set(FATTR4_MODE) {
        result_bitmap.set(FATTR4_MODE);
        (attr.mode & MODE_PERM_MASK).encode(&mut vals);
    }

    // FATTR4_NO_TRUNC (34)
    if request.is_set(FATTR4_NO_TRUNC) {
        result_bitmap.set(FATTR4_NO_TRUNC);
        true.encode(&mut vals);
    }

    // FATTR4_NUMLINKS (35)
    if request.is_set(FATTR4_NUMLINKS) {
        result_bitmap.set(FATTR4_NUMLINKS);
        attr.nlink.encode(&mut vals);
    }

    // FATTR4_OWNER (36)
    if request.is_set(FATTR4_OWNER) {
        result_bitmap.set(FATTR4_OWNER);
        attr.owner.encode(&mut vals);
    }

    // FATTR4_OWNER_GROUP (37)
    if request.is_set(FATTR4_OWNER_GROUP) {
        result_bitmap.set(FATTR4_OWNER_GROUP);
        attr.owner_group.encode(&mut vals);
    }

    // FATTR4_RAWDEV (41)
    if request.is_set(FATTR4_RAWDEV) {
        result_bitmap.set(FATTR4_RAWDEV);
        let spec = Specdata4 {
            specdata1: attr.rdev_major,
            specdata2: attr.rdev_minor,
        };
        spec.encode(&mut vals);
    }

    // FATTR4_SPACE_AVAIL (42)
    if request.is_set(FATTR4_SPACE_AVAIL) {
        result_bitmap.set(FATTR4_SPACE_AVAIL);
        ctx.stats.avail_bytes.encode(&mut vals);
    }

    // FATTR4_SPACE_FREE (43)
    if request.is_set(FATTR4_SPACE_FREE) {
        result_bitmap.set(FATTR4_SPACE_FREE);
        ctx.stats.free_bytes.encode(&mut vals);
    }

    // FATTR4_SPACE_TOTAL (44)
    if request.is_set(FATTR4_SPACE_TOTAL) {
        result_bitmap.set(FATTR4_SPACE_TOTAL);
        ctx.stats.total_bytes.encode(&mut vals);
    }

    // FATTR4_SPACE_USED (45)
    if request.is_set(FATTR4_SPACE_USED) {
        result_bitmap.set(FATTR4_SPACE_USED);
        attr.used.encode(&mut vals);
    }

    // FATTR4_SYSTEM (46) - macOS system flag
    if request.is_set(FATTR4_SYSTEM) {
        result_bitmap.set(FATTR4_SYSTEM);
        attr.system.encode(&mut vals);
    }

    // FATTR4_TIME_ACCESS (47)
    if request.is_set(FATTR4_TIME_ACCESS) {
        result_bitmap.set(FATTR4_TIME_ACCESS);
        let t = NfsTime4 {
            seconds: attr.atime_sec,
            nseconds: attr.atime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_BACKUP (49) - same as creation time
    if request.is_set(FATTR4_TIME_BACKUP) {
        result_bitmap.set(FATTR4_TIME_BACKUP);
        let t = NfsTime4 {
            seconds: attr.crtime_sec,
            nseconds: attr.crtime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_CREATE (50) - birth/creation time (macOS uses this)
    if request.is_set(FATTR4_TIME_CREATE) {
        result_bitmap.set(FATTR4_TIME_CREATE);
        let t = NfsTime4 {
            seconds: attr.crtime_sec,
            nseconds: attr.crtime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_DELTA (51)
    if request.is_set(FATTR4_TIME_DELTA) {
        result_bitmap.set(FATTR4_TIME_DELTA);
        let t = NfsTime4 {
            seconds: 0,
            nseconds: 1000000,
        }; // 1ms
        t.encode(&mut vals);
    }

    // FATTR4_TIME_METADATA (52)
    if request.is_set(FATTR4_TIME_METADATA) {
        result_bitmap.set(FATTR4_TIME_METADATA);
        let t = NfsTime4 {
            seconds: attr.ctime_sec,
            nseconds: attr.ctime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_MODIFY (53)
    if request.is_set(FATTR4_TIME_MODIFY) {
        result_bitmap.set(FATTR4_TIME_MODIFY);
        let t = NfsTime4 {
            seconds: attr.mtime_sec,
            nseconds: attr.mtime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_MOUNTED_ON_FILEID (55)
    if request.is_set(FATTR4_MOUNTED_ON_FILEID) {
        result_bitmap.set(FATTR4_MOUNTED_ON_FILEID);
        attr.fileid.encode(&mut vals);
    }

    // Word 2 attributes (bits 64-95)

    // FATTR4_SUPPATTR_EXCLCREAT (75)
    if request.is_set(FATTR4_SUPPATTR_EXCLCREAT) {
        result_bitmap.set(FATTR4_SUPPATTR_EXCLCREAT);
        // We support setting mode, size, etc. on exclusive create
        let mut excl = Bitmap4::new();
        excl.set(FATTR4_SIZE);
        excl.set(FATTR4_MODE);
        excl.encode(&mut vals);
    }

    Fattr4 {
        attrmask: result_bitmap,
        attr_vals: vals.freeze(),
    }
}

/// Decode setattr attributes from an Fattr4.
pub(crate) fn decode_setattr(fattr: &Fattr4) -> Result<SetAttrs, NfsStat4> {
    let mut result = SetAttrs::default();
    let mut src = fattr.attr_vals.clone();

    // Attributes must be decoded in bitmap order
    if fattr.attrmask.is_set(FATTR4_SIZE) {
        let size = u64::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.size = Some(size);
    }

    // ARCHIVE (14) - macOS sends this; consume but store as flag
    if fattr.attrmask.is_set(FATTR4_ARCHIVE) {
        let archive = bool::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.archive = Some(archive);
    }

    // HIDDEN (25) - macOS sends this
    if fattr.attrmask.is_set(FATTR4_HIDDEN) {
        let hidden = bool::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.hidden = Some(hidden);
    }

    if fattr.attrmask.is_set(FATTR4_MODE) {
        let mode = u32::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.mode = Some(mode & MODE_PERM_MASK);
    }

    if fattr.attrmask.is_set(FATTR4_OWNER) {
        let owner_str = String::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        // Parse numeric uid or "uid@domain" format
        let uid_str = owner_str.split('@').next().unwrap_or(&owner_str);
        if let Ok(uid) = uid_str.parse::<u32>() {
            result.uid = Some(uid);
        }
    }

    if fattr.attrmask.is_set(FATTR4_OWNER_GROUP) {
        let group_str = String::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        let gid_str = group_str.split('@').next().unwrap_or(&group_str);
        if let Ok(gid) = gid_str.parse::<u32>() {
            result.gid = Some(gid);
        }
    }

    // SYSTEM (46) - macOS sends this
    if fattr.attrmask.is_set(FATTR4_SYSTEM) {
        let system = bool::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.system = Some(system);
    }

    if fattr.attrmask.is_set(FATTR4_TIME_ACCESS_SET) {
        let how = u32::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        match how {
            0 => result.atime = Some(SetTime::ServerNow),
            1 => {
                let t = NfsTime4::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
                result.atime = Some(SetTime::Client(Timestamp {
                    seconds: t.seconds,
                    nanos: t.nseconds,
                }));
            }
            _ => {}
        }
    }

    // TIME_BACKUP (49) - macOS sends this (same format as time_create)
    if fattr.attrmask.is_set(FATTR4_TIME_BACKUP) {
        let t = NfsTime4::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.birthtime = Some(SetTime::Client(Timestamp {
            seconds: t.seconds,
            nanos: t.nseconds,
        }));
    }

    // TIME_CREATE (50) - macOS sends this as birth/creation time
    if fattr.attrmask.is_set(FATTR4_TIME_CREATE) {
        let t = NfsTime4::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        result.birthtime = Some(SetTime::Client(Timestamp {
            seconds: t.seconds,
            nanos: t.nseconds,
        }));
    }

    if fattr.attrmask.is_set(FATTR4_TIME_MODIFY_SET) {
        let how = u32::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
        match how {
            0 => result.mtime = Some(SetTime::ServerNow),
            1 => {
                let t = NfsTime4::decode(&mut src).map_err(|_| NfsStat4::BadXdr)?;
                result.mtime = Some(SetTime::Client(Timestamp {
                    seconds: t.seconds,
                    nanos: t.nseconds,
                }));
            }
            _ => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_setattr_masks_file_type_bits_from_mode() {
        let mut bitmap = Bitmap4::new();
        bitmap.set(FATTR4_MODE);

        let mut vals = BytesMut::new();
        0o100644u32.encode(&mut vals);

        let attrs = decode_setattr(&Fattr4 {
            attrmask: bitmap,
            attr_vals: vals.freeze(),
        })
        .unwrap();

        assert_eq!(attrs.mode, Some(0o644));
    }

    #[test]
    fn test_decode_setattr_rejects_truncated_client_time() {
        let mut bitmap = Bitmap4::new();
        bitmap.set(FATTR4_TIME_MODIFY_SET);

        let mut vals = BytesMut::new();
        1u32.encode(&mut vals);
        123i64.encode(&mut vals);

        let err = decode_setattr(&Fattr4 {
            attrmask: bitmap,
            attr_vals: vals.freeze(),
        })
        .unwrap_err();

        assert_eq!(err, NfsStat4::BadXdr);
    }

    #[test]
    fn test_encode_fattr4_masks_mode_to_permission_bits() {
        let mut request = Bitmap4::new();
        request.set(FATTR4_MODE);

        let attr = ServerFileAttr {
            fileid: 1,
            file_type: ServerFileType::Regular,
            size: 0,
            used: 0,
            mode: 0o100644,
            nlink: 1,
            owner: "root".into(),
            owner_group: "root".into(),
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            crtime_sec: 0,
            crtime_nsec: 0,
            change_id: 0,
            rdev_major: 0,
            rdev_minor: 0,
            archive: false,
            hidden: false,
            system: false,
            has_named_attrs: false,
        };
        let fh = NfsFh4(vec![1, 2, 3, 4].into());
        let limits = FsLimits::default();
        let stats = FsStats::default();
        let caps = FsCapabilities::default();
        let ctx = AttrEncodingContext {
            limits: &limits,
            stats: &stats,
            capabilities: &caps,
        };
        let fattr = encode_fattr4(&attr, &request, &fh, &ctx);
        let mut src = bytes::Bytes::from(fattr.attr_vals);

        assert_eq!(u32::decode(&mut src).unwrap(), 0o644);
    }
}
