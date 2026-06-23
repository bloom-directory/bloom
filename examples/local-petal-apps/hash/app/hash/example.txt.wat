(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (data (i32.const 64) "\02\0a\00\00\00hash demo\0a")
  (func (export "petal_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $ptr))
  (func (export "petal_dispatch") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 64)) (i64.const 32))
      (i64.extend_i32_u (i32.const 15)))))
