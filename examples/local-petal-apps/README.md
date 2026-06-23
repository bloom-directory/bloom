# Local Petal App v2 demos

These are source-first demo packages for the v2 file-driven local app format.
Route sources are checked in as WAT to avoid opaque binary artifacts.

Build installable package directories:

```sh
./examples/local-petal-apps/build-demo-apps.sh
```

Build route artifacts and archive a package:

```sh
cargo run -p bloom -- petal app build examples/local-petal-apps/build/echo --out /tmp/echo.petal.tar
```

Install and read through `/apps`:

```sh
cargo run -p bloom -- petals install examples/local-petal-apps/build/echo
cargo run -p bloom -- vfs cat apps/echo/message.txt
```

Current bootstrap demos use the compatibility `petal_dispatch` ABI. Component
route demos should replace these once the `bloom:route@0.1.0` runner lands.
