//! Times one full verification pass over an audit journal, the work Machine
//! repeats when it opens its journal and when it reports audit status.
//!
//! `cargo run --release -p bloom-proto --example audit_verify_bench -- PATH`
//! Point it at a copy: the journal is only read.

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: audit_verify_bench PATH");
    let started = std::time::Instant::now();
    bloom_proto::AuditLog::verify(std::path::Path::new(&path)).expect("verify audit journal");
    println!("verified {path} in {:.2?}", started.elapsed());
}
