(module
  (memory (export "memory") 1)
  (func (export "call") (param i32 i32) (result i32)
    ;; memory.grow returns the previous size, or -1 on failure.
    ;; We don't even need to check — if the limiter rejects, the next
    ;; load/store would still pass; we want a HARD trap. The simplest way
    ;; is to insist the grow succeeded by trapping if it returned -1.
    (if (i32.eq (memory.grow (i32.const 1024)) (i32.const -1))
      (then (unreachable)))
    i32.const 0)
)
