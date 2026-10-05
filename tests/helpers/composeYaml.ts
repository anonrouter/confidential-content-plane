// A reader for the Compose files deploy/phala generates.
//
// WHY THIS EXISTS. The topology suites have to ask structural questions of a
// rendered manifest: which networks is this service on, what is in its
// environment, which volumes does it mount. Asking them of a model inside the
// generator would test the generator's opinion of its output. Asking them of
// the rendered TEXT tests the artifact the hardware measures, and that needs a
// parser. This repository has no YAML dependency and a test cannot install one.
//
// IT IS NOT A YAML PARSER. It reads the subset those generators emit and
// REFUSES everything else by throwing, because a reader that guesses at
// syntax it does not understand would report a network or a variable as absent
// when it was merely unparsed, and "absent" is the answer most of these suites
// are looking for. The subset:
//
//   - block mappings and block sequences, indented with spaces, including a
//     sequence item that opens a mapping (`- subnet: 10.231.1.0/24`);
//   - plain, double-quoted and single-quoted scalars, kept as STRINGS (no
//     booleans, no numbers: `"3000"` and `3000` both read as "3000", which is
//     what a container's environment receives either way);
//   - literal block scalars (`key: |` and `- |`), whose lines are CONTENT even
//     when they begin with `#`;
//   - JSON-compatible flow sequences (`["CMD", "node"]`) and the empty flow
//     mapping `{}`;
//   - one anchor on a mapping (`x-hardened: &hardened`) and the merge key that
//     uses it (`<<: *hardened`);
//   - full-line comments and blank lines.
//
// A key with no value (`cert-data:`) reads as an empty mapping.

export type ComposeNode = string | ComposeNode[] | { [key: string]: ComposeNode };
export type ComposeMap = { [key: string]: ComposeNode };

interface Line {
  readonly indent: number;
  readonly text: string;
  readonly number: number;
}

function fail(line: Line | undefined, message: string): never {
  throw new Error(`compose line ${line ? line.number : "?"}: ${message}${line ? ` (${JSON.stringify(line.text)})` : ""}`);
}

function scalar(raw: string, line: Line): ComposeNode {
  const value = raw.trim();
  if (value === "{}") return {};
  if (value.startsWith("[")) {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) throw new Error("not a list of strings");
      return parsed as string[];
    } catch {
      fail(line, "a flow sequence must be a JSON list of strings");
    }
  }
  if (value.startsWith('"')) {
    try {
      return JSON.parse(value) as string;
    } catch {
      fail(line, "unparseable double-quoted scalar");
    }
  }
  if (value.startsWith("'")) {
    if (!value.endsWith("'") || value.length < 2) fail(line, "unterminated single-quoted scalar");
    return value.slice(1, -1).replaceAll("''", "'");
  }
  if (value.startsWith("{") || value.startsWith("&") || value.startsWith("*") || value.startsWith("!") || value.startsWith(">")) {
    fail(line, "unsupported YAML syntax");
  }
  // A plain scalar holding `: ` or ` #` would mean something else to a real
  // parser. The generators never emit one, so seeing one is a parse this
  // reader would get wrong.
  if (/: /.test(value) || / #/.test(value)) fail(line, "plain scalar containing ': ' or ' #'");
  return value;
}

export function parseCompose(text: string): ComposeMap {
  const raw = text.split("\n");
  const anchors = new Map<string, ComposeMap>();
  let cursor = 0;

  const lineAt = (index: number): Line => {
    const source = raw[index]!;
    if (source.includes("\t")) fail({ indent: 0, text: source, number: index + 1 }, "tab in a compose file");
    return { indent: source.length - source.trimStart().length, text: source, number: index + 1 };
  };
  const skippable = (index: number) => {
    const trimmed = raw[index]!.trim();
    return trimmed === "" || trimmed.startsWith("#");
  };
  /** The next line that is neither blank nor a comment, without consuming it. */
  const peek = (): Line | null => {
    while (cursor < raw.length && skippable(cursor)) cursor += 1;
    return cursor < raw.length ? lineAt(cursor) : null;
  };

  /** Lines of a literal block scalar whose owner sits at `ownerIndent`. Comments are content. */
  const blockScalar = (ownerIndent: number): string => {
    const lines: string[] = [];
    let blockIndent: number | null = null;
    while (cursor < raw.length) {
      const source = raw[cursor]!;
      if (source.trim() === "") { lines.push(""); cursor += 1; continue; }
      const indent = source.length - source.trimStart().length;
      if (indent <= ownerIndent) break;
      blockIndent ??= indent;
      if (indent < blockIndent) fail(lineAt(cursor), "block scalar line less indented than its first line");
      lines.push(source.slice(blockIndent));
      cursor += 1;
    }
    while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
  };

  const block = (indent: number): ComposeNode => {
    const first = peek();
    if (!first || first.indent < indent) return {};
    if (first.indent !== indent) fail(first, `expected indentation ${indent}`);
    return first.text.trimStart().startsWith("- ") || first.text.trim() === "-" ? sequence(indent) : mapping(indent);
  };

  const sequence = (indent: number): ComposeNode[] => {
    const items: ComposeNode[] = [];
    for (;;) {
      const line = peek();
      if (!line || line.indent < indent) return items;
      if (line.indent !== indent) fail(line, `expected indentation ${indent}`);
      const body = line.text.trimStart();
      if (!body.startsWith("- ")) fail(line, "expected a sequence item");
      const value = body.slice(2).trim();
      // A sequence item that OPENS A MAPPING (`- subnet: 10.231.1.0/24`), the
      // form an `ipam.config` entry takes. Its keys sit at the column after
      // "- ", so the item line is re-read as that mapping's first line. Only a
      // plain key followed by `:` and then a space or the end of the line
      // qualifies: `- /tmp:size=16m` and `- evidences:/evidences:ro` are
      // scalars, as they always were.
      if (/^[A-Za-z_][A-Za-z0-9_-]*:(?: .*)?$/.test(value)) {
        raw[cursor] = `${" ".repeat(indent + 2)}${value}`;
        items.push(mapping(indent + 2));
        continue;
      }
      cursor += 1;
      if (value === "|") { items.push(blockScalar(indent)); continue; }
      // Flow sequences and quoted scalars may contain `: `, so only plain ones are checked.
      items.push(scalar(value, line));
    }
  };

  const mapping = (indent: number): ComposeMap => {
    const result: ComposeMap = {};
    // Keys written in this mapping, as opposed to merged into it.
    const written = new Set<string>();
    for (;;) {
      const line = peek();
      if (!line || line.indent < indent) return result;
      if (line.indent !== indent) fail(line, `expected indentation ${indent}`);
      const body = line.text.trimStart();
      const match = /^([^\s:#"'][^:]*?):(?: (.*))?$/.exec(body);
      if (!match) fail(line, "expected `key: value` or `key:`");
      const key = match[1]!;
      let rest = (match[2] ?? "").trim();
      cursor += 1;

      if (key === "<<") {
        const name = /^\*([A-Za-z0-9_-]+)$/.exec(rest)?.[1];
        const anchored = name ? anchors.get(name) : undefined;
        if (!anchored) fail(line, "merge key that does not name a known anchor");
        // Explicit keys win over merged ones whatever their order, as in YAML.
        for (const [mergedKey, mergedValue] of Object.entries(anchored)) {
          if (!Object.hasOwn(result, mergedKey)) result[mergedKey] = structuredClone(mergedValue);
        }
        continue;
      }
      // A duplicate key is last-one-wins to Compose and a silent override to a
      // reader, so it is refused. Overriding a MERGED key is ordinary YAML.
      if (written.has(key)) fail(line, `duplicate key ${JSON.stringify(key)}`);
      written.add(key);

      let anchor: string | null = null;
      const anchorMatch = /^&([A-Za-z0-9_-]+)$/.exec(rest);
      if (anchorMatch) { anchor = anchorMatch[1]!; rest = ""; }

      let value: ComposeNode;
      if (rest === "|") {
        value = blockScalar(indent);
      } else if (rest !== "") {
        value = scalar(rest, line);
      } else {
        const next = peek();
        value = next && next.indent > indent ? block(next.indent) : {};
      }
      if (anchor) {
        if (typeof value !== "object" || Array.isArray(value)) fail(line, "only a mapping may carry an anchor");
        anchors.set(anchor, value);
      }
      result[key] = value;
    }
  };

  const document = mapping(0);
  const trailing = peek();
  if (trailing) fail(trailing, "content after the end of the document");
  return document;
}

function asMap(node: ComposeNode | undefined, what: string): ComposeMap {
  if (node === undefined) return {};
  if (typeof node !== "object" || Array.isArray(node)) throw new Error(`${what} is not a mapping`);
  return node;
}

function asStrings(node: ComposeNode | undefined, what: string): string[] {
  if (node === undefined) return [];
  if (!Array.isArray(node) || node.some((item) => typeof item !== "string")) throw new Error(`${what} is not a list of strings`);
  return node as string[];
}

/** One service of a parsed compose file, with the questions the suites ask of it. */
export interface ComposeService {
  readonly name: string;
  /** Every key of the service, merge keys already applied. */
  readonly raw: ComposeMap;
  readonly image: string;
  /** The environment as the container receives it, `${...}` references unsubstituted. */
  readonly environment: Readonly<Record<string, string>>;
  /** Every network the service joins, whichever form (`- name` or `name:`) declares it. */
  readonly networks: readonly string[];
  /** Network name to the DNS aliases the service answers to on it. */
  readonly aliases: Readonly<Record<string, readonly string[]>>;
  readonly volumes: readonly string[];
  /** The entrypoint script when the command is a single literal block, else null. */
  readonly script: string | null;
}

export interface ComposeFile {
  readonly document: ComposeMap;
  readonly services: Readonly<Record<string, ComposeService>>;
  /** Top-level network name to its options (`{ internal: "true" }`, or `{}`). */
  readonly networks: Readonly<Record<string, ComposeMap>>;
  /** Top-level volume name to its options. */
  readonly volumes: Readonly<Record<string, ComposeMap>>;
}

export function readCompose(text: string): ComposeFile {
  const document = parseCompose(text);
  const services: Record<string, ComposeService> = {};
  for (const [name, node] of Object.entries(asMap(document.services, "services"))) {
    const raw = asMap(node, `service ${name}`);
    const environment: Record<string, string> = {};
    for (const [key, value] of Object.entries(asMap(raw.environment, `${name}.environment`))) {
      if (typeof value !== "string") throw new Error(`${name}.environment.${key} is not a scalar`);
      environment[key] = value;
    }
    const aliases: Record<string, readonly string[]> = {};
    let networks: string[];
    if (Array.isArray(raw.networks)) {
      networks = asStrings(raw.networks, `${name}.networks`);
    } else {
      const map = asMap(raw.networks, `${name}.networks`);
      networks = Object.keys(map);
      for (const [network, options] of Object.entries(map)) {
        aliases[network] = asStrings(asMap(options, `${name}.networks.${network}`).aliases, `${name}.networks.${network}.aliases`);
      }
    }
    const command = raw.command;
    services[name] = {
      name,
      raw,
      image: typeof raw.image === "string" ? raw.image : "",
      environment,
      networks,
      aliases,
      volumes: asStrings(raw.volumes, `${name}.volumes`),
      script: Array.isArray(command) && command.length === 1 && typeof command[0] === "string" && command[0].includes("\n")
        ? command[0]
        : null
    };
  }
  const options = (node: ComposeNode | undefined, what: string) => {
    const result: Record<string, ComposeMap> = {};
    for (const [name, value] of Object.entries(asMap(node, what))) result[name] = asMap(value, `${what}.${name}`);
    return result;
  };
  return {
    document,
    services,
    networks: options(document.networks, "networks"),
    volumes: options(document.volumes, "volumes")
  };
}

/** `"a|b"` for an unordered pair of service names, the smaller first. */
export const pairKey = (a: string, b: string): string => (a < b ? `${a}|${b}` : `${b}|${a}`);

/**
 * Every pair of services that shares at least one network, with the networks.
 *
 * The whole matrix, not a sample of it: a property "these two share nothing"
 * is only as strong as the enumeration, and an unintended bridge is by
 * definition between two services nobody thought to check.
 */
export function sharedNetworks(compose: ComposeFile): Record<string, string[]> {
  const names = Object.keys(compose.services).sort();
  const shared: Record<string, string[]> = {};
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      const other = new Set(compose.services[names[j]!]!.networks);
      const common = compose.services[names[i]!]!.networks.filter((network) => other.has(network)).sort();
      if (common.length > 0) shared[pairKey(names[i]!, names[j]!)] = common;
    }
  }
  return shared;
}
