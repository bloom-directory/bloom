(component
  (type $ty-bloom:http/fetch@0.1.0 (;0;)
    (instance
      (type (;0;) (tuple string string))
      (type (;1;) (list 0))
      (type (;2;) (list u8))
      (type (;3;) (record (field "method" string) (field "url" string) (field "headers" 1) (field "body" 2)))
      (export (;4;) "request" (type (eq 3)))
      (type (;5;) (record (field "status" u16) (field "headers" 1) (field "body" 2)))
      (export (;6;) "response" (type (eq 5)))
      (type (;7;) (result 6 (error string)))
      (type (;8;) (func (param "req" 4) (result 7)))
      (export (;0;) "fetch" (func (type 8)))
    )
  )
  (import "bloom:http/fetch@0.1.0" (instance $bloom:http/fetch@0.1.0 (;0;) (type $ty-bloom:http/fetch@0.1.0)))
  (type $ty-bloom:route/types@0.1.0 (;1;)
    (instance
      (type (;0;) (tuple string string))
      (type (;1;) (list 0))
      (type (;2;) (option string))
      (type (;3;) (record (field "petal-root" string) (field "package-hash" string) (field "path" string) (field "params" 1) (field "actor" 2)))
      (export (;4;) "ctx" (type (eq 3)))
      (type (;5;) (enum "dir" "file" "symlink"))
      (export (;6;) "entry-kind" (type (eq 5)))
      (type (;7;) (option u64))
      (type (;8;) (record (field "name" string) (field "kind" 6) (field "mode" u32) (field "size" 7) (field "link-target" 2)))
      (export (;9;) "entry" (type (eq 8)))
      (type (;10;) (variant (case "not-found" string) (case "not-a-dir" string) (case "denied" string) (case "invalid" string) (case "backend" string) (case "unsupported" string)))
      (export (;11;) "route-error" (type (eq 10)))
      (type (;12;) (list string))
      (type (;13;) (record (field "kind" 6) (field "mode" u32) (field "cache-ttl-ms" 7) (field "side-effecting-read" bool) (field "write-async" bool) (field "description" 2) (field "consent-summary" 2) (field "required-caps" 12) (field "sign-intent" 2) (field "executable" bool)))
      (export (;14;) "route-meta" (type (eq 13)))
    )
  )
  (import "bloom:route/types@0.1.0" (instance $bloom:route/types@0.1.0 (;1;) (type $ty-bloom:route/types@0.1.0)))
  (alias export $bloom:route/types@0.1.0 "ctx" (type $ctx (;2;)))
  (import "ctx" (type $"#type3 ctx" (@name "ctx") (;3;) (eq $ctx)))
  (alias export $bloom:route/types@0.1.0 "entry" (type $entry (;4;)))
  (import "entry" (type $"#type5 entry" (@name "entry") (;5;) (eq $entry)))
  (alias export $bloom:route/types@0.1.0 "route-error" (type $route-error (;6;)))
  (import "route-error" (type $"#type7 route-error" (@name "route-error") (;7;) (eq $route-error)))
  (alias export $bloom:route/types@0.1.0 "route-meta" (type $route-meta (;8;)))
  (import "route-meta" (type $"#type9 route-meta" (@name "route-meta") (;9;) (eq $route-meta)))
  (core module $main (;0;)
    (type (;0;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (type (;1;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
    (type (;2;) (func (param i32)))
    (type (;3;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
    (type (;4;) (func (param i32 i32 i32 i32) (result i32)))
    (type (;5;) (func))
    (import "cm32p2|bloom:http/fetch@0.1" "fetch" (func (;0;) (type 0)))
    (memory (;0;) 1)
    (data (i32.const 0) "GET")
    (data (i32.const 16) "https://api.example.com/status")
    (global $heap (mut i32) (i32.const 2048))
    (export "cm32p2||metadata" (func 1))
    (export "cm32p2||metadata_post" (func 2))
    (export "cm32p2||lookup" (func 3))
    (export "cm32p2||lookup_post" (func 4))
    (export "cm32p2||list" (func 5))
    (export "cm32p2||list_post" (func 6))
    (export "cm32p2||read" (func 7))
    (export "cm32p2||read_post" (func 8))
    (export "cm32p2||write" (func 9))
    (export "cm32p2||write_post" (func 10))
    (export "cm32p2_memory" (memory 0))
    (export "cm32p2_realloc" (func 11))
    (export "cm32p2_initialize" (func 12))
    (func (;1;) (type 1) (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      unreachable
    )
    (func (;2;) (type 2) (param i32))
    (func (;3;) (type 1) (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      unreachable
    )
    (func (;4;) (type 2) (param i32))
    (func (;5;) (type 1) (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      unreachable
    )
    (func (;6;) (type 2) (param i32))
    (func (;7;) (type 1) (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const 0
      i32.const 3
      i32.const 16
      i32.const 30
      i32.const 0
      i32.const 0
      i32.const 0
      i32.const 0
      i32.const 128
      call 0
      unreachable
    )
    (func (;8;) (type 2) (param i32))
    (func (;9;) (type 3) (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      unreachable
    )
    (func (;10;) (type 2) (param i32))
    (func (;11;) (type 4) (param i32 i32 i32 i32) (result i32)
      (local $ptr i32)
      global.get $heap
      local.get 2
      i32.add
      i32.const 1
      i32.sub
      local.get 2
      i32.const 1
      i32.sub
      i32.const -1
      i32.xor
      i32.and
      local.tee $ptr
      local.get $ptr
      local.get 3
      i32.add
      global.set $heap
    )
    (func (;12;) (type 5))
    (@producers
      (processed-by "wit-component" "0.249.0")
    )
  )
  (core module $wit-component-shim-module (;1;)
    (type (;0;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (table (;0;) 1 1 funcref)
    (export "0" (func 0))
    (export "$imports" (table 0))
    (func (;0;) (type 0) (param i32 i32 i32 i32 i32 i32 i32 i32 i32)
      local.get 0
      local.get 1
      local.get 2
      local.get 3
      local.get 4
      local.get 5
      local.get 6
      local.get 7
      local.get 8
      i32.const 0
      call_indirect (type 0)
    )
    (@producers
      (processed-by "wit-component" "0.249.0")
    )
  )
  (core module $wit-component-fixup (;2;)
    (type (;0;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (import "" "0" (func (;0;) (type 0)))
    (import "" "$imports" (table (;0;) 1 1 funcref))
    (elem (;0;) (i32.const 0) func 0)
    (@producers
      (processed-by "wit-component" "0.249.0")
    )
  )
  (core instance $wit-component-shim-instance (;0;) (instantiate $wit-component-shim-module))
  (alias core export $wit-component-shim-instance "0" (core func $indirect-cm32p2|bloom:http/fetch@0.1-fetch (;0;)))
  (core instance $cm32p2|bloom:http/fetch@0.1 (;1;)
    (export "fetch" (func $indirect-cm32p2|bloom:http/fetch@0.1-fetch))
  )
  (core instance $main (;2;) (instantiate $main
      (with "cm32p2|bloom:http/fetch@0.1" (instance $cm32p2|bloom:http/fetch@0.1))
    )
  )
  (alias core export $main "cm32p2_memory" (core memory $memory (;0;)))
  (alias core export $wit-component-shim-instance "$imports" (core table $"shim table" (;0;)))
  (alias export $bloom:http/fetch@0.1.0 "fetch" (func $fetch (;0;)))
  (alias core export $main "cm32p2_realloc" (core func $realloc (;1;)))
  (core func $"#core-func2 indirect-cm32p2|bloom:http/fetch@0.1-fetch" (@name "indirect-cm32p2|bloom:http/fetch@0.1-fetch") (;2;) (canon lower (func $fetch) (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core instance $fixup-args (;3;)
    (export "$imports" (table $"shim table"))
    (export "0" (func $"#core-func2 indirect-cm32p2|bloom:http/fetch@0.1-fetch"))
  )
  (core instance $fixup (;4;) (instantiate $wit-component-fixup
      (with "" (instance $fixup-args))
    )
  )
  (alias core export $main "cm32p2_initialize" (core func $start (;3;)))
  (core module $start-shim-module (;3;)
    (type (;0;) (func))
    (import "" "" (func (;0;) (type 0)))
    (start 0)
  )
  (core instance $start-shim-args (;5;)
    (export "" (func $start))
  )
  (core instance $start-shim-instance (;6;) (instantiate $start-shim-module
      (with "" (instance $start-shim-args))
    )
  )
  (type (;10;) (result $"#type9 route-meta" (error $"#type7 route-error")))
  (type (;11;) (func (param "ctx" $"#type3 ctx") (result 10)))
  (alias core export $main "cm32p2||metadata" (core func $cm32p2||metadata (;4;)))
  (alias core export $main "cm32p2||metadata_post" (core func $cm32p2||metadata_post (;5;)))
  (func $metadata (;1;) (type 11) (canon lift (core func $cm32p2||metadata) (memory $memory) (realloc $realloc) string-encoding=utf8 (post-return $cm32p2||metadata_post)))
  (export $"#func2 metadata" (@name "metadata") (;2;) "metadata" (func $metadata))
  (type (;12;) (result $"#type5 entry" (error $"#type7 route-error")))
  (type (;13;) (func (param "ctx" $"#type3 ctx") (result 12)))
  (alias core export $main "cm32p2||lookup" (core func $cm32p2||lookup (;6;)))
  (alias core export $main "cm32p2||lookup_post" (core func $cm32p2||lookup_post (;7;)))
  (func $lookup (;3;) (type 13) (canon lift (core func $cm32p2||lookup) (memory $memory) (realloc $realloc) string-encoding=utf8 (post-return $cm32p2||lookup_post)))
  (export $"#func4 lookup" (@name "lookup") (;4;) "lookup" (func $lookup))
  (type (;14;) (list $"#type5 entry"))
  (type (;15;) (result 14 (error $"#type7 route-error")))
  (type (;16;) (func (param "ctx" $"#type3 ctx") (result 15)))
  (alias core export $main "cm32p2||list" (core func $cm32p2||list (;8;)))
  (alias core export $main "cm32p2||list_post" (core func $cm32p2||list_post (;9;)))
  (func $list (;5;) (type 16) (canon lift (core func $cm32p2||list) (memory $memory) (realloc $realloc) string-encoding=utf8 (post-return $cm32p2||list_post)))
  (export $"#func6 list" (@name "list") (;6;) "list" (func $list))
  (type (;17;) (list u8))
  (type (;18;) (result 17 (error $"#type7 route-error")))
  (type (;19;) (func (param "ctx" $"#type3 ctx") (result 18)))
  (alias core export $main "cm32p2||read" (core func $cm32p2||read (;10;)))
  (alias core export $main "cm32p2||read_post" (core func $cm32p2||read_post (;11;)))
  (func $read (;7;) (type 19) (canon lift (core func $cm32p2||read) (memory $memory) (realloc $realloc) string-encoding=utf8 (post-return $cm32p2||read_post)))
  (export $"#func8 read" (@name "read") (;8;) "read" (func $read))
  (type (;20;) (result (error $"#type7 route-error")))
  (type (;21;) (func (param "ctx" $"#type3 ctx") (param "body" 17) (result 20)))
  (alias core export $main "cm32p2||write" (core func $cm32p2||write (;12;)))
  (alias core export $main "cm32p2||write_post" (core func $cm32p2||write_post (;13;)))
  (func $write (;9;) (type 21) (canon lift (core func $cm32p2||write) (memory $memory) (realloc $realloc) string-encoding=utf8 (post-return $cm32p2||write_post)))
  (export $"#func10 write" (@name "write") (;10;) "write" (func $write))
  (@producers
    (processed-by "wit-component" "0.249.0")
  )
)
