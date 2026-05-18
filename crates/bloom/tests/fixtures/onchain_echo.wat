(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $exit (param i32)))
  (memory (export "memory") 1)
  ;; Echo the first 16 bytes of stdin to stdout. Reads to address 32,
  ;; iovec at 0 (ptr=32, max=16), nread at 16. Then writes whatever
  ;; was actually read.
  (data (i32.const 0) "\20\00\00\00\10\00\00\00") ;; iovec: ptr=32, max=16
  (func (export "_start")
    (local $n i32)
    (call $fd_read
      (i32.const 0)  ;; stdin
      (i32.const 0)  ;; iovec ptr
      (i32.const 1)  ;; iovec count
      (i32.const 16)) ;; nread ptr
    drop
    (local.set $n (i32.load (i32.const 16)))
    ;; Stdout iovec at 64: ptr=32, len=$n.
    (i32.store (i32.const 64) (i32.const 32))
    (i32.store (i32.const 68) (local.get $n))
    (call $fd_write
      (i32.const 1)
      (i32.const 64)
      (i32.const 1)
      (i32.const 72))
    drop
    (call $exit (i32.const 0)))
)
