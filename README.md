# jcs-canonical-json

[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization Scheme for Rust.

I wrote this because I needed deterministic JSON serialization for receipt signing. I have a desktop app (Rust) that verifies cryptographic receipts from a cloud runtime (TypeScript). Both sides need to agree on the exact byte-for-byte representation of a JSON object before signing it — if one key gets reordered differently or a number serializes with a trailing zero, the Ed25519 signature breaks silently.

There are other JCS crates, but the ones I tried either:
- pulled in a surprising number of dependencies for what's essentially string formatting
- got the key sort order wrong for characters above U+FFFF (the spec says sort by UTF-16 code units, not UTF-8 bytes — the difference matters for emoji and musical symbols because they become surrogate pairs)

The second issue cost me a full afternoon of debugging before I realized my receipt verification was failing because `𝌆` (U+1D306) was sorting differently on each side. Fun times.

## Usage

```rust
use jcs_canonical_json::canonicalize;
use serde_json::json;

let value = json!({"z": 1, "a": 2});
let canonical = canonicalize(&value);
assert_eq!(canonical, r#"{"a":2,"z":1}"#);

// or if you're feeding it into a hasher:
let bytes = jcs_canonical_json::canonicalize_to_vec(&value);
```

## What it does

- Sorts object keys by UTF-16 code unit values (not UTF-8 byte order)
- Serializes numbers using ES2015 `Number.toString()` semantics
- Only applies mandatory string escapes (no optional `/` escaping)
- No whitespace
- Recursive — nested objects are sorted too

## What it doesn't do

- Validation. If you hand it a `serde_json::Value`, it trusts that it's valid JSON.
- Streaming. The whole thing is in-memory. For the payload sizes I deal with (legal documents, not gigabyte blobs) this is fine.

## Why not just `serde_json::to_string()`?

`serde_json` preserves insertion order via `IndexMap` when you enable the `preserve_order` feature, which is the opposite of what you want for canonical signing. Even without that feature, the default `BTreeMap` sorts by Rust's `Ord` for `String`, which is UTF-8 byte order — close to UTF-16 order for most text but wrong for supplementary-plane characters.

## License

MIT
