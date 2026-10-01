// The canonical JSON NEAR's compose-manager hashes its action log with:
// `serde_json::to_string` of the actions with every object's keys sorted
// (nearai/compose-manager src/main.rs `canonicalize_actions`, documented there
// as Python `json.dumps(actions, sort_keys=True, separators=(",", ":"),
// ensure_ascii=False)`). actions_hash = sha256 of this text, and the second TDX
// quote binds that hash, so re-deriving it exactly is what ties the log to the
// hardware. Mirrors `python_sorted_json` in native/hw-verifier/src/util.rs.
//
// Escaping is serde_json's (= Python with ensure_ascii=False): only `"`, `\`
// and control characters below U+0020 are escaped (\b \f \n \r \t, otherwise
// \u00xx lowercase); everything else, DEL and non-ASCII included, is written
// as is (UTF-8 when hashed). Floats are refused (languages print them
// differently and the log has none); so is nesting deeper than 64.

function escapeString(text: string): string {
  let out = "\"";
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    const ch = text[i];
    if (ch === "\"") out += "\\\"";
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (unit === 0x08) out += "\\b";
    else if (unit === 0x0c) out += "\\f";
    else if (unit < 0x20) out += "\\u" + unit.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + "\"";
}

export function pythonSortedJson(value: unknown, depth = 0): string | null {
  if (depth > 64) return null;
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return Number.isSafeInteger(value) ? String(value) : null;
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value) {
      const encoded = pythonSortedJson(item, depth + 1);
      if (encoded === null) return null;
      parts.push(encoded);
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    // Byte order of the UTF-8 keys, which is what Rust's String ordering and
    // Python's code-point ordering both give. For BMP keys (every key in the
    // log is ASCII) UTF-16 order is the same.
    const keys = Object.keys(value as Record<string, unknown>).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts: string[] = [];
    for (const key of keys) {
      const encoded = pythonSortedJson((value as Record<string, unknown>)[key], depth + 1);
      if (encoded === null) return null;
      parts.push(`${escapeString(key)}:${encoded}`);
    }
    return `{${parts.join(",")}}`;
  }
  return null;
}
