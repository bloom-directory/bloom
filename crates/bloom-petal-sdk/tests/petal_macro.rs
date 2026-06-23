use bloom_petal_sdk::{DispatchOp, DispatchRequest, DispatchResponse};

#[bloom_petal_sdk::petal]
fn handle(req: DispatchRequest) -> DispatchResponse {
    match req.op {
        DispatchOp::Read => DispatchResponse::Read(req.path.into_bytes()),
        _ => DispatchResponse::Error {
            code: -3,
            message: "read only".into(),
        },
    }
}

#[test]
fn petal_attribute_exports_dispatch_entrypoint() {
    let _dispatch: extern "C" fn(i32, i32) -> i64 = petal_dispatch;
    let req = DispatchRequest {
        op: DispatchOp::Read,
        path: "hello".into(),
        body: Vec::new(),
        ctx: Vec::new(),
    };
    assert_eq!(handle(req), DispatchResponse::Read(b"hello".to_vec()));
}

#[test]
fn petal_attribute_exports_allocator() {
    let ptr = petal_alloc(16);
    assert!(!ptr.is_null());
}
