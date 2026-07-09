use bytes::Bytes;

use crate::fs::{
    AccessMask, AuthContext, CreateKind, CreateRequest, FileSystem, FsError, HardLinks, ObjectType,
    RequestContext, SetAttrs, SetTime, Timestamp, WriteStability, XattrSetMode, Xattrs,
};

use super::MemFs;

#[tokio::test]
async fn create_write_read_round_trip() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "hello.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    let written = fs
        .write(
            &ctx,
            &created.handle,
            0,
            Bytes::from_static(b"hello world"),
            WriteStability::FileSync,
        )
        .await
        .unwrap();
    assert_eq!(written.written, 11);

    let read = fs.read(&ctx, &created.handle, 0, 1024).await.unwrap();
    assert_eq!(read.data, Bytes::from_static(b"hello world"));
    assert!(read.eof);
}

#[tokio::test]
async fn readdir_returns_inline_attrs_when_requested() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let _ = fs
        .create(
            &ctx,
            &1,
            "a.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    let page = fs.readdir(&ctx, &1, 0, 16, true).await.unwrap();
    assert_eq!(page.entries.len(), 1);
    let entry = &page.entries[0];
    assert_eq!(entry.name, "a.txt");
    assert_eq!(entry.attrs.as_ref().unwrap().object_type, ObjectType::File);
}

#[tokio::test]
async fn xattrs_update_exported_attrs() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "notes.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    fs.set_xattr(
        &ctx,
        &created.handle,
        "com.apple.test",
        Bytes::from_static(b"value"),
        XattrSetMode::CreateOrReplace,
    )
    .await
    .unwrap();

    assert!(
        fs.getattr(&ctx, &created.handle)
            .await
            .unwrap()
            .has_named_attrs
    );

    fs.remove_xattr(&ctx, &created.handle, "com.apple.test")
        .await
        .unwrap();

    assert!(
        !fs.getattr(&ctx, &created.handle)
            .await
            .unwrap()
            .has_named_attrs
    );
}

#[tokio::test]
async fn root_is_writable_for_non_owner_auth_sys_callers() {
    let fs = MemFs::new();
    let ctx = RequestContext {
        auth: AuthContext::Sys {
            uid: 1000,
            gid: 1000,
            supplemental_gids: vec![],
        },
    };

    let access = fs
        .access(
            &ctx,
            &1,
            AccessMask::READ | AccessMask::LOOKUP | AccessMask::MODIFY | AccessMask::EXTEND,
        )
        .await
        .unwrap();

    assert!(access.intersects(AccessMask::READ));
    assert!(access.intersects(AccessMask::LOOKUP));
    assert!(access.intersects(AccessMask::MODIFY));
    assert!(access.intersects(AccessMask::EXTEND));
}

#[tokio::test]
async fn create_stamps_auth_sys_owner_by_default() {
    let fs = MemFs::new();
    let ctx = RequestContext {
        auth: AuthContext::Sys {
            uid: 501,
            gid: 20,
            supplemental_gids: vec![12],
        },
    };

    let created = fs
        .create(
            &ctx,
            &1,
            "owned.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    assert_eq!(created.attrs.uid, 501);
    assert_eq!(created.attrs.gid, 20);
}

#[tokio::test]
async fn rename_over_nonempty_directory_is_atomic_on_error() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let source = fs
        .create(
            &ctx,
            &1,
            "source.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let target_dir = fs
        .create(
            &ctx,
            &1,
            "target",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let nested = fs
        .create(
            &ctx,
            &target_dir.handle,
            "nested.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    let err = fs
        .rename(&ctx, &1, "source.txt", &1, "target")
        .await
        .unwrap_err();
    assert_eq!(err, FsError::IsDirectory);
    assert_eq!(
        fs.lookup(&ctx, &1, "source.txt").await.unwrap(),
        source.handle
    );
    assert_eq!(
        fs.lookup(&ctx, &1, "target").await.unwrap(),
        target_dir.handle
    );
    assert_eq!(
        fs.lookup(&ctx, &target_dir.handle, "nested.txt")
            .await
            .unwrap(),
        nested.handle
    );
}

#[tokio::test]
async fn rename_same_name_is_a_noop() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "same.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let root_before = fs.getattr(&ctx, &1).await.unwrap();

    fs.rename(&ctx, &1, "same.txt", &1, "same.txt")
        .await
        .unwrap();

    let root_after = fs.getattr(&ctx, &1).await.unwrap();
    assert_eq!(
        fs.lookup(&ctx, &1, "same.txt").await.unwrap(),
        created.handle
    );
    assert_eq!(root_after.change, root_before.change);
}

#[tokio::test]
async fn rename_over_existing_hard_link_to_same_inode_is_a_noop() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "source.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    fs.link(&ctx, &created.handle, &1, "alias.txt")
        .await
        .unwrap();
    let root_before = fs.getattr(&ctx, &1).await.unwrap();

    fs.rename(&ctx, &1, "source.txt", &1, "alias.txt")
        .await
        .unwrap();

    let root_after = fs.getattr(&ctx, &1).await.unwrap();
    assert_eq!(
        fs.lookup(&ctx, &1, "source.txt").await.unwrap(),
        created.handle
    );
    assert_eq!(
        fs.lookup(&ctx, &1, "alias.txt").await.unwrap(),
        created.handle
    );
    assert_eq!(root_after.change, root_before.change);
}

#[tokio::test]
async fn rename_rejects_moving_directory_into_its_descendant() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let src = fs
        .create(
            &ctx,
            &1,
            "src",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let subdir = fs
        .create(
            &ctx,
            &src.handle,
            "child",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    let err = fs
        .rename(&ctx, &1, "src", &subdir.handle, "moved")
        .await
        .unwrap_err();
    assert_eq!(err, FsError::InvalidInput);
    assert_eq!(fs.lookup(&ctx, &1, "src").await.unwrap(), src.handle);
    assert_eq!(
        fs.lookup(&ctx, &src.handle, "child").await.unwrap(),
        subdir.handle
    );
}

#[tokio::test]
async fn rename_rejects_directory_file_type_mismatches() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let dir = fs
        .create(
            &ctx,
            &1,
            "dir",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let file = fs
        .create(
            &ctx,
            &1,
            "file.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    let err = fs
        .rename(&ctx, &1, "file.txt", &1, "dir")
        .await
        .unwrap_err();
    assert_eq!(err, FsError::IsDirectory);

    let err = fs
        .rename(&ctx, &1, "dir", &1, "file.txt")
        .await
        .unwrap_err();
    assert_eq!(err, FsError::NotDirectory);
    assert_eq!(fs.lookup(&ctx, &1, "dir").await.unwrap(), dir.handle);
    assert_eq!(fs.lookup(&ctx, &1, "file.txt").await.unwrap(), file.handle);
}

#[tokio::test]
async fn oversized_mutations_return_file_too_large() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "huge.bin",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let over_limit = fs.limits().max_file_size + 1;

    let err = fs
        .setattr(
            &ctx,
            &created.handle,
            &SetAttrs {
                size: Some(over_limit),
                ..SetAttrs::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err, FsError::FileTooLarge);

    let err = fs
        .write(
            &ctx,
            &created.handle,
            fs.limits().max_file_size,
            Bytes::from_static(b"x"),
            WriteStability::FileSync,
        )
        .await
        .unwrap_err();
    assert_eq!(err, FsError::FileTooLarge);
    assert_eq!(fs.getattr(&ctx, &created.handle).await.unwrap().size, 0);
}

#[tokio::test]
async fn setattr_size_updates_mtime_when_client_did_not_supply_one() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "mtime.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let fixed_mtime = Timestamp {
        seconds: 123,
        nanos: 456,
    };

    let _ = fs
        .setattr(
            &ctx,
            &created.handle,
            &SetAttrs {
                mtime: Some(SetTime::Client(fixed_mtime)),
                ..SetAttrs::default()
            },
        )
        .await
        .unwrap();

    let attrs = fs
        .setattr(
            &ctx,
            &created.handle,
            &SetAttrs {
                size: Some(1),
                ..SetAttrs::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(attrs.size, 1);
    assert_ne!(attrs.mtime, fixed_mtime);
}

#[tokio::test]
async fn access_is_permissionless_to_match_memfs_operations() {
    let fs = MemFs::new();
    let ctx = RequestContext {
        auth: AuthContext::Sys {
            uid: 1000,
            gid: 1000,
            supplemental_gids: vec![],
        },
    };
    let created = fs
        .create(
            &ctx,
            &1,
            "mode.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs {
                    mode: Some(0),
                    ..SetAttrs::default()
                },
            },
        )
        .await
        .unwrap();
    let requested = AccessMask::READ | AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE;

    let granted = fs.access(&ctx, &created.handle, requested).await.unwrap();
    assert_eq!(granted, requested);
}

#[tokio::test]
async fn statfs_saturates_when_usage_exceeds_advertised_capacity() {
    let fs = MemFs::new();
    {
        let mut inner = fs.inner.write().await;
        let root = inner.inodes.get_mut(&1).unwrap();
        root.attrs.space_used = (1_u64 << 30) + 1;
    }

    let stats = fs.statfs(&RequestContext::anonymous()).await.unwrap();
    assert_eq!(stats.free_bytes, 0);
    assert_eq!(stats.avail_bytes, 0);
}
