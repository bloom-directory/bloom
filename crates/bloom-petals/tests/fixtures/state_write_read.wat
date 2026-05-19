(module
  (import "chain" "state.write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "chain" "state.read"  (func $read  (param i32 i32 i32) (result i64)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; key:  32 bytes of 0x01 at offset 0
  ;; val:  32 bytes of 0xFF at offset 32
  ;; out:  32 bytes at offset 64 (for read result)
  (data (i32.const 0)  "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01")
  (data (i32.const 32) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (func (export "call") (param i32 i32) (result i32)
    ;; first write (new slot — 5000 fuel)
    (drop (call $write (i32.const 0) (i32.const 32) (i32.const 32) (i32.const 32)))
    ;; second write to same key (existing slot — 1500 fuel)
    (drop (call $write (i32.const 0) (i32.const 32) (i32.const 32) (i32.const 32)))
    ;; read back
    (drop (call $read (i32.const 0) (i32.const 32) (i32.const 64)))
    ;; return 32 bytes from offset 64
    (call $ret (i32.const 64) (i32.const 32))
    i32.const 0)
)
