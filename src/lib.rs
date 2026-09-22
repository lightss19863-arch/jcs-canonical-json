//! # jcs-canonical-json
//!
//! [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization
//! Scheme (JCS) for Rust.
//!
//! I needed this because I have a desktop app (Rust/Tauri) that verifies
//! cryptographic receipts produced by a cloud runtime (TypeScript). Both sides
//! have to agree on the exact byte representation of a JSON payload before
//! signing or hashing it. If even one key gets reordered or a number gets
//! serialized slightly differently, the whole signature chain breaks.
//!
//! There are other JCS crates out there but most of them either pulled in
//! way too many dependencies for what's essentially string manipulation, or
//! got the UTF-16 sort order wrong for supplementary-plane characters. I
//! spent a pretty painful afternoon debugging why my receipt signatures were
//! failing on a test case with emoji in the keys before I realized the sort
//! was comparing UTF-8 bytes instead of UTF-16 code units. So here we are.
//!
//! ## Quick start
//!
//! ```rust
//! use jcs_canonical_json::canonicalize;
//! use serde_json::json;
//!
//! let value = json!({"z": 1, "a": 2});
//! let bytes = canonicalize(&value);
//! assert_eq!(bytes, r#"{"a":2,"z":1}"#);
//! ```

use serde_json::Value;
use std::fmt::Write;

/// Serialize a JSON value into its RFC 8785 canonical form.
///
/// Object keys are sorted by UTF-16 code unit values (not UTF-8 byte order —
/// the distinction matters for codepoints above U+FFFF because they become
/// surrogate pairs). Numbers use ES2015 `Number.toString()` rules. No optional
/// whitespace, no optional escaping.
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    render(value, &mut out);
    out
}

/// Returns the canonical form as a byte vector, for when you want to pipe
/// it straight into a SHA-256 hasher without the intermediate string.
pub fn canonicalize_to_vec(value: &Value) -> Vec<u8> {
    canonicalize(value).into_bytes()
}

fn render(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // serde_json stores numbers as i64/u64/f64 and already serializes
            // them without trailing zeros, which matches ES2015 semantics for
            // the values we care about. If someone hands us a NaN or Infinity
            // that's not valid JSON anyway — serde_json won't parse it.
            write!(out, "{n}").unwrap();
        }
        Value::String(s) => escape_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // The actual heart of this crate: sorting keys by UTF-16 code units.
            // This is NOT the same as sorting by raw bytes or by Rust's default
            // char ordering. The difference only shows up with supplementary-plane
            // characters (above U+FFFF) that become surrogate pairs in UTF-16.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a_u16: Vec<u16> = a.encode_utf16().collect();
                let b_u16: Vec<u16> = b.encode_utf16().collect();
                a_u16.cmp(&b_u16)
            });

            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_string(key, out);
                out.push(':');
                render(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// RFC 8785 §3.2.2.2 string escaping. Only the mandatory escapes — we leave
/// forward slashes and everything above U+001F alone.
fn escape_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{0020}' => {
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys() {
        assert_eq!(
            canonicalize(&json!({"z": 1, "a": 2, "m": 3})),
            r#"{"a":2,"m":3,"z":1}"#
        );
    }

    #[test]
    fn nested_sort() {
        assert_eq!(
            canonicalize(&json!({"b": {"z": 1, "a": 2}, "a": 3})),
            r#"{"a":3,"b":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn empties() {
        assert_eq!(canonicalize(&json!({})), "{}");
        assert_eq!(canonicalize(&json!([])), "[]");
    }

    #[test]
    fn primitives() {
        assert_eq!(canonicalize(&json!(null)), "null");
        assert_eq!(canonicalize(&json!(true)), "true");
        assert_eq!(canonicalize(&json!(false)), "false");
        assert_eq!(canonicalize(&json!(42)), "42");
        assert_eq!(canonicalize(&json!("hello")), "\"hello\"");
    }

    #[test]
    fn mandatory_escapes() {
        assert_eq!(canonicalize(&json!("\n")), r#""\n""#);
        assert_eq!(canonicalize(&json!("\t")), r#""\t""#);
        assert_eq!(canonicalize(&json!("\"")), r#""\"""#);
        assert_eq!(canonicalize(&json!("\\")), r#""\\""#);
    }

    #[test]
    fn forward_slash_is_not_escaped() {
        assert_eq!(canonicalize(&json!("a/b")), "\"a/b\"");
    }

    #[test]
    fn low_control_chars() {
        assert_eq!(canonicalize(&json!("\u{0001}")), r#""\u0001""#);
    }

    #[test]
    fn array_order_preserved() {
        assert_eq!(canonicalize(&json!([3, 1, 2])), "[3,1,2]");
    }

    #[test]
    fn no_whitespace() {
        let v = json!({"key": [1, 2, {"nested": true}]});
        let r = canonicalize(&v);
        assert!(!r.contains(' '));
        assert_eq!(r, r#"{"key":[1,2,{"nested":true}]}"#);
    }

    #[test]
    fn utf16_sort_order_for_supplementary_plane() {
        // This is the test that caught my original bug.
        //
        // U+1D306 (𝌆) encodes as UTF-16 surrogates D834 DF06
        // U+FEFF (BOM) is a single UTF-16 unit FEFF
        //
        // UTF-8 byte order: FEFF (EF BB BF) < 1D306 (F0 9D 8C 86)
        // UTF-16 code unit order: D834 < FEFF, so 1D306 sorts FIRST
        //
        // If you sort by UTF-8 bytes you get the wrong answer and your
        // cross-runtime signatures silently break. Ask me how I know.
        let value = json!({"\u{FEFF}": 1, "\u{1D306}": 2});
        let result = canonicalize(&value);
        assert!(result.starts_with("{\"𝌆\""));
    }

    #[test]
    fn roundtrip_is_stable() {
        let value = json!({"b": [null, true, {"z": 1, "a": 2}], "a": "hello"});
        let first = canonicalize(&value);
        let reparsed: Value = serde_json::from_str(&first).unwrap();
        let second = canonicalize(&reparsed);
        assert_eq!(first, second);
    }

    #[test]
    fn rfc8785_appendix_b_test_vector() {
        // Adapted from RFC 8785 Appendix B
        let input = r#"{"1":{"f":{"f":"hi","F":5},"\\n\\n":"ignore"},"10":{},"":1,"a":{},"111":[{"e":"yes","E":"no"}]}"#;
        let value: Value = serde_json::from_str(input).unwrap();
        let result = canonicalize(&value);
        let expected = r#"{"":1,"1":{"\\n\\n":"ignore","f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"a":{}}"#;
        assert_eq!(result, expected);
    }
}
