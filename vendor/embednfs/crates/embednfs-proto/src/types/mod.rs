//! NFSv4.1 protocol types per RFC 8881.

mod basic;
mod constants;
mod operations;
mod session;

pub use basic::*;
pub use constants::*;
pub use operations::*;
pub use session::*;

mod codec;

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};

    use super::*;
    use crate::xdr::{XdrDecode, XdrEncode};

    #[test]
    fn test_nfsstat4_v41_status_codes_match_rfc8881() {
        assert_eq!(NfsStat4::SequencePos as u32, 10064);
        assert_eq!(NfsStat4::ReqTooBig as u32, 10065);
        assert_eq!(NfsStat4::RepTooBig as u32, 10066);
        assert_eq!(NfsStat4::RepTooBigToCache as u32, 10067);
        assert_eq!(NfsStat4::RetryUncachedRep as u32, 10068);
        assert_eq!(NfsStat4::UnsafeCompound as u32, 10069);
        assert_eq!(NfsStat4::TooManyOps as u32, 10070);
        assert_eq!(NfsStat4::OpNotInSession as u32, 10071);
        assert_eq!(NfsStat4::ClientidBusy as u32, 10074);
        assert_eq!(NfsStat4::SeqFalseRetry as u32, 10076);
        assert_eq!(NfsStat4::BadHighSlot as u32, 10077);
        assert_eq!(NfsStat4::NotOnlyOp as u32, 10081);
        assert_eq!(NfsStat4::WrongCred as u32, 10082);
        assert_eq!(NfsStat4::WrongType as u32, 10083);
        assert_eq!(NfsStat4::DelegRevoked as u32, 10087);
    }

    #[test]
    fn test_nfsstat4_from_u32_decodes_newer_v41_errors() {
        assert_eq!(NfsStat4::from_u32(10064), Some(NfsStat4::SequencePos));
        assert_eq!(NfsStat4::from_u32(10068), Some(NfsStat4::RetryUncachedRep));
        assert_eq!(NfsStat4::from_u32(10071), Some(NfsStat4::OpNotInSession));
        assert_eq!(NfsStat4::from_u32(10074), Some(NfsStat4::ClientidBusy));
        assert_eq!(NfsStat4::from_u32(10081), Some(NfsStat4::NotOnlyOp));
        assert_eq!(NfsStat4::from_u32(10082), Some(NfsStat4::WrongCred));
        assert_eq!(NfsStat4::from_u32(10083), Some(NfsStat4::WrongType));
    }

    #[test]
    fn test_nfsstat4_decode_rejects_unknown_status_codes() {
        let mut buf = BytesMut::new();
        123_456u32.encode(&mut buf);
        let mut bytes = buf.freeze();
        let err = NfsStat4::decode(&mut bytes).unwrap_err();
        assert!(matches!(err, crate::xdr::XdrError::InvalidEnum(123_456)));
    }

    #[test]
    fn test_stateid4_current_matches_rfc_special_value() {
        assert_eq!(Stateid4::CURRENT.seqid, 1);
        assert_eq!(Stateid4::CURRENT.other, [0u8; 12]);
    }

    #[test]
    fn test_bitmap4_decode_accepts_more_than_eight_words() {
        let mut buf = BytesMut::new();
        9u32.encode(&mut buf);
        for word in 0..9u32 {
            word.encode(&mut buf);
        }

        let mut bytes = buf.freeze();
        let decoded = Bitmap4::decode(&mut bytes).unwrap();
        assert_eq!(decoded.0.len(), 9);
        assert_eq!(decoded.0[8], 8);
    }

    #[test]
    fn test_create_decodes_default_arm_as_unsupported_type() {
        let mut buf = BytesMut::new();
        "create".to_string().encode(&mut buf);
        1u32.encode(&mut buf);
        1u32.encode(&mut buf);
        OP_CREATE.encode(&mut buf);
        (NfsFtype4::AttrDir as u32).encode(&mut buf);
        "named-attr-dir".to_string().encode(&mut buf);
        Bitmap4::new().encode(&mut buf);
        Vec::<u8>::new().encode(&mut buf);

        let mut bytes = buf.freeze();
        let args = Compound4Args::decode(&mut bytes).unwrap();
        match &args.argarray[0] {
            NfsArgop4::Create(create) => {
                assert!(matches!(create.objtype, Createtype4::Unsupported(8)));
            }
            other => panic!("expected CREATE arg, got {other:?}"),
        }
    }

    #[test]
    fn test_exchange_id_decode_accepts_sp4_ssv() {
        let mut buf = BytesMut::new();
        "exid".to_string().encode(&mut buf);
        1u32.encode(&mut buf);
        1u32.encode(&mut buf);
        OP_EXCHANGE_ID.encode(&mut buf);
        buf.extend_from_slice(&[0u8; 8]);
        b"client".to_vec().encode(&mut buf);
        EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
        2u32.encode(&mut buf);
        Bitmap4::new().encode(&mut buf);
        Bitmap4::new().encode(&mut buf);
        1u32.encode(&mut buf);
        b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
            .to_vec()
            .encode(&mut buf);
        1u32.encode(&mut buf);
        b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2a"
            .to_vec()
            .encode(&mut buf);
        4u32.encode(&mut buf);
        1u32.encode(&mut buf);
        0u32.encode(&mut buf);

        let mut bytes = buf.freeze();
        let args = Compound4Args::decode(&mut bytes).unwrap();
        match &args.argarray[0] {
            NfsArgop4::ExchangeId(exchange) => {
                assert!(matches!(exchange.state_protect, StateProtect4A::Ssv { .. }));
            }
            other => panic!("expected EXCHANGE_ID arg, got {other:?}"),
        }
    }

    #[test]
    fn test_backchannel_ctl_decode_accepts_rpcsec_gss_callback_parms() {
        let mut buf = BytesMut::new();
        "bctl".to_string().encode(&mut buf);
        1u32.encode(&mut buf);
        1u32.encode(&mut buf);
        OP_BACKCHANNEL_CTL.encode(&mut buf);
        99u32.encode(&mut buf);
        1u32.encode(&mut buf);
        6u32.encode(&mut buf);
        1u32.encode(&mut buf);
        b"fore-handle".to_vec().encode(&mut buf);
        b"back-handle".to_vec().encode(&mut buf);

        let mut bytes = buf.freeze();
        let args = Compound4Args::decode(&mut bytes).unwrap();
        assert!(matches!(args.argarray[0], NfsArgop4::BackchannelCtl));
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_open_encode_emits_delegation_payloads() {
        let open_none_ext = NfsResop4::Open(
            NfsStat4::Ok,
            Some(OpenRes4 {
                stateid: Stateid4::ANONYMOUS,
                cinfo: ChangeInfo4 {
                    atomic: true,
                    before: 1,
                    after: 2,
                },
                rflags: 0,
                attrset: Bitmap4::new(),
                delegation: OpenDelegation4::NoneExt(OpenNoneDelegation4::Contention {
                    server_will_push_deleg: true,
                }),
            }),
        );
        let encoded = open_none_ext.to_bytes();
        let mut bytes = Bytes::from(encoded);
        assert_eq!(u32::decode(&mut bytes).unwrap(), OP_OPEN);
        assert_eq!(u32::decode(&mut bytes).unwrap(), NfsStat4::Ok as u32);
        let _ = Stateid4::decode(&mut bytes).unwrap();
        let _ = bool::decode(&mut bytes).unwrap();
        let _ = u64::decode(&mut bytes).unwrap();
        let _ = u64::decode(&mut bytes).unwrap();
        let _ = u32::decode(&mut bytes).unwrap();
        let _ = Bitmap4::decode(&mut bytes).unwrap();
        assert_eq!(
            u32::decode(&mut bytes).unwrap(),
            OpenDelegationType4::NoneExt as u32
        );
        assert_eq!(
            u32::decode(&mut bytes).unwrap(),
            WhyNoDelegation4::Contention as u32
        );
        assert!(bool::decode(&mut bytes).unwrap());

        let open_read = NfsResop4::Open(
            NfsStat4::Ok,
            Some(OpenRes4 {
                stateid: Stateid4::ANONYMOUS,
                cinfo: ChangeInfo4 {
                    atomic: true,
                    before: 1,
                    after: 2,
                },
                rflags: 0,
                attrset: Bitmap4::new(),
                delegation: OpenDelegation4::Read(OpenReadDelegation4 {
                    stateid: Stateid4::BYPASS,
                    recall: false,
                    permissions: NfsAce4 {
                        ace_type: 0,
                        ace_flags: 0,
                        access_mask: 0,
                        who: "OWNER@".into(),
                    },
                }),
            }),
        );
        assert!(open_read.to_bytes().len() > 8);
    }

    #[test]
    fn test_optional_operation_result_payloads_are_encoded() {
        let payload_ops = [
            NfsResop4::LayoutGet(
                NfsStat4::Ok,
                Some(LayoutGetRes4::Ok(LayoutGetResOk4 {
                    return_on_close: true,
                    stateid: Stateid4::ANONYMOUS,
                    layout: vec![],
                })),
            ),
            NfsResop4::LayoutGet(
                NfsStat4::LayoutTrylater,
                Some(LayoutGetRes4::LayoutTryLater {
                    will_signal_layout_avail: true,
                }),
            ),
            NfsResop4::LayoutReturn(
                NfsStat4::Ok,
                Some(LayoutReturnStateid4::Some(Stateid4::ANONYMOUS)),
            ),
            NfsResop4::LayoutCommit(
                NfsStat4::Ok,
                Some(LayoutCommitResOk4 {
                    newsize: Newsize4::Size(42),
                }),
            ),
            NfsResop4::GetDirDelegation(
                NfsStat4::Ok,
                Some(GetDirDelegationRes4::Unavail {
                    will_signal_deleg_avail: false,
                }),
            ),
            NfsResop4::WantDelegation(
                NfsStat4::Ok,
                Some(OpenDelegation4::NoneExt(OpenNoneDelegation4::Other(
                    WhyNoDelegation4::NotWanted,
                ))),
            ),
            NfsResop4::GetDeviceInfo(
                NfsStat4::Toosmall,
                Some(GetDeviceInfoRes4::TooSmall { mincount: 512 }),
            ),
            NfsResop4::GetDeviceList(
                NfsStat4::Ok,
                Some(GetDeviceListResOk4 {
                    cookie: 7,
                    cookieverf: [0xAB; 8],
                    deviceid_list: vec![[0xCD; 16]],
                    eof: true,
                }),
            ),
            NfsResop4::SetSsv(
                NfsStat4::Ok,
                Some(SetSsvResOk4 {
                    digest: b"digest".to_vec().into(),
                }),
            ),
        ];

        for op in payload_ops {
            assert!(op.to_bytes().len() > 8, "missing payload for {op:?}");
        }
    }
}
