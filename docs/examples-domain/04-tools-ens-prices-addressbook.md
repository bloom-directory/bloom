# Tools, ENS, Prices, Addressbook

VFS is mounted at `/bloom/`. All paths below are relative to that mount.

## Tools

`tools/` exposes pure helpers in two flavours: stateless one-shots where the
input fits in the path, and write-then-read sessions where the input is JSON
written to `in.json` and the result is read from `out.hex` / `out.json`.
Sessions auto-expire after 5 minutes of idle.

### keccak

```sh
cat /bloom/tools/keccak/hello%20world
# 0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
```

The path is URL-encoded if the input contains `/`; unencoded inputs are joined
back with `/` (so `keccak/a/b` hashes the literal string `a/b`).

### selector

4-byte function selector (the first 4 bytes of `keccak(sig)`).

```sh
cat /bloom/tools/selector/transfer(address,uint256)
# 0xa9059cbb

cat /bloom/tools/selector/approve(address,uint256)
# 0x095ea7b3
```

Note the full event-topic form is just `keccak`:

```sh
cat /bloom/tools/keccak/Transfer(address,address,uint256)
# 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
```

### address/checksum

EIP-55 checksum a lowercase or any-case address.

```sh
cat /bloom/tools/address/checksum/0xd8da6bf26964af9d7eed9e03e53415d37aa96045
# 0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045
```

### sha256, blake3

```sh
cat /bloom/tools/sha256/hello%20world
cat /bloom/tools/blake3/hello%20world
```

### hex / base64

```sh
cat /bloom/tools/hex/encode/hello
# 0x68656c6c6f
cat /bloom/tools/hex/decode/0x68656c6c6f
# hello

cat /bloom/tools/base64/encode/hello
# aGVsbG8=
cat /bloom/tools/base64/decode/aGVsbG8=
# hello
```

`hex/decode` and `base64/decode` return raw decoded bytes (no trailing newline).

### unit/parse, unit/format

`parse` takes a value plus a unit and produces base units (wei). `format`
takes a u256 and a decimals count and produces a human-readable scalar.

```sh
cat /bloom/tools/unit/parse/1.5/eth
# 1500000000000000000

cat /bloom/tools/unit/parse/25/gwei
# 25000000000

cat /bloom/tools/unit/format/1500000000000000000/18
# 1.5
```

### abi (encode / decode) — session

Write the input JSON to `in.json` under any session id, then read the result.

```sh
echo '{"sig":"transfer(address,uint256)","args":["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045","1000000"]}' \
  > /bloom/tools/abi/encode/s1/in.json
cat /bloom/tools/abi/encode/s1/out.hex
# 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000000000f4240
```

```sh
echo '{"types":["address","uint256"],"data":"0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000000000f4240"}' \
  > /bloom/tools/abi/decode/s1/in.json
cat /bloom/tools/abi/decode/s1/out.json
```

`ls /bloom/tools/abi/encode/` lists live session ids; `ls /bloom/tools/abi/encode/s1/`
shows `in.json` and `out.hex`.

### rlp (encode / decode) — session

```sh
echo '{"value":["0x83","0xff",["0x01"]]}' > /bloom/tools/rlp/encode/r1/in.json
cat /bloom/tools/rlp/encode/r1/out.hex
# 0xc6818381ffc101

echo '{"data":"0xc6818381ffc101"}' > /bloom/tools/rlp/decode/r1/in.json
cat /bloom/tools/rlp/decode/r1/out.json
```

### eip712/hash — session

Write the full EIP-712 typed-data document to `in.json`; the hash is read from
`out.hex`.

```sh
cat > /tmp/mail.json <<'JSON'
{
  "domain": {},
  "types": {
    "EIP712Domain": [],
    "Person": [{"name":"name","type":"string"},{"name":"wallet","type":"address"}],
    "Mail": [{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]
  },
  "primaryType": "Mail",
  "message": {
    "from": {"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":   {"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!"
  }
}
JSON
cp /tmp/mail.json /bloom/tools/eip712/hash/m1/in.json
cat /bloom/tools/eip712/hash/m1/out.hex
# 0x25c3d40a39e639a4d0b6e4d2ace5e1281e039c88494d97d8d08f99a6ea75d775
```

## ENS

The `ens/` surface is forward-only and read-only. Reverse resolution is not
mounted here — it lives at `chains/<chain>/addresses/<addr>/ens` (per spec
§3.2). Listing `/bloom/ens/` returns names looked up in this session only;
agents can `cat` any `*.eth` name without listing it first.

### Forward (resolve to address)

```sh
cat /bloom/ens/vitalik.eth/address
# 0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045
```

Unresolved names return the literal string `unresolved`.

### Reverse (address → name)

Routed through the chain handler:

```sh
cat /bloom/chains/mainnet/addresses/0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045/ens
```

### Text records

Any text key is accepted; unset keys return `not set`.

```sh
cat /bloom/ens/vitalik.eth/text/url
cat /bloom/ens/vitalik.eth/text/com.twitter
cat /bloom/ens/brantly.eth/text/email
```

`avatar` is exposed both as a top-level file (a shortcut for the `avatar` text
record) and via the `text/` directory:

```sh
cat /bloom/ens/vitalik.eth/avatar
# (same as) cat /bloom/ens/vitalik.eth/text/avatar
```

### Contenthash

EIP-1577 contenthash, returned as `0x`-prefixed hex (no codec decoding).

```sh
cat /bloom/ens/ens.eth/content_hash
```

### Listing a name's surface

```sh
ls /bloom/ens/vitalik.eth/
# address  avatar  content_hash  text
```

### Namehash

Not exposed through the VFS. The `namehash` implementation lives in
`bloom-ens` but is not currently wired into `tools/` — compute it offline if
you need the EIP-137 node value.

## Prices

Backed by DefiLlama (keyless, rate-limited; results cached for 30s).

Coin segment forms:

* bare symbol — `eth`, `usdc`, `btc`
* `<chain>:<address>` — `ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`
* `coingecko:<slug>` — `coingecko:lido`

### Spot price

`spot/<coin>` returns the full JSON quote; the `.usd` suffix returns the
scalar price as text.

```sh
cat /bloom/prices/spot/eth.usd
cat /bloom/prices/spot/btc.usd
cat /bloom/prices/spot/usdc.usd

cat /bloom/prices/spot/eth
# {"price": ..., "symbol": "ETH", "decimals": 18, "timestamp": ..., "confidence": ...}
```

### 24h change

`change_24h/<coin>` returns the percentage as text. There is no `.usd`
variant on this path.

```sh
cat /bloom/prices/change_24h/eth
cat /bloom/prices/change_24h/usdc
```

## Addressbook

A local petname directory persisted to `<home>/addressbook.toml`. Reads return
the EIP-55 checksum address with a trailing newline. Writes register or delete.

### List & read

```sh
ls /bloom/addressbook/
# new  vitalik  weth  usdc

cat /bloom/addressbook/vitalik
# 0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045
```

`new` is always present and acts as a write-only registration endpoint (see
below). Reading it returns a short usage hint.

### Set an alias

Either write the address directly to the alias file, or post `alias=0x…` to
`new`:

```sh
echo "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045" > /bloom/addressbook/vitalik
echo "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" > /bloom/addressbook/weth
echo "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" > /bloom/addressbook/usdc

# Alternative form via the `new` endpoint:
echo "vitalik=0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045" > /bloom/addressbook/new
```

The address is checksum-normalised on write.

### Remove an alias

Write `delete` (case-insensitive) or an empty body to the alias file:

```sh
echo "delete" > /bloom/addressbook/vitalik
# or
: > /bloom/addressbook/vitalik
```
