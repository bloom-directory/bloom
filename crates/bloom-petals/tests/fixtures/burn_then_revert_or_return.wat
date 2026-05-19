(module
  (import "chain" "msg.calldata.read" (func $cdread (param i32 i32 i32) (result i32)))
  (import "chain" "petal.revert"      (func $revert (param i32 i32)))
  (import "chain" "petal.return"      (func $ret    (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0)   "\00")                              ;; calldata byte slot
  (data (i32.const 16)  "burned-and-reverted")              ;; 19 bytes, revert reason
  (data (i32.const 64)  "\aa")                              ;; success return byte
  (func (export "init") (param i32 i32) (result i32)
    i32.const 0)
  (func (export "call") (param i32 i32) (result i32)
    (local $i i32)
    ;; Read 1 byte of calldata into [0..1].
    (drop (call $cdread (i32.const 0) (i32.const 0) (i32.const 1)))
    ;; Counted loop: i = 0; while (i < 50000) { i += 1; }
    (local.set $i (i32.const 0))
    (block $done
      (loop $top
        (br_if $done (i32.ge_s (local.get $i) (i32.const 50000)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $top)))
    ;; Branch on calldata[0].
    (if (i32.eq (i32.load8_u (i32.const 0)) (i32.const 1))
      (then
        ;; Revert with 19-byte reason at offset 16.
        (call $revert (i32.const 16) (i32.const 19))
        (unreachable))
      (else
        ;; Return 1 byte at offset 64.
        (call $ret (i32.const 64) (i32.const 1))
        (unreachable)))
    i32.const 0)
)
