// Shared runtime for the escrow mirroring tools: paths, hashing, process
// execution and the observed-state file.
//
// FAIL-CLOSED IS THE WHOLE DESIGN. Every function here either returns a value
// that has been checked or throws. Nothing returns "probably fine". A mirroring
// tool that records success on an unverified copy is worse than no mirror,
// because the failure surfaces during a restore, which is the one moment when
// there is no time to discover it.
//
// The state file is written ONLY by these tools and is never hand-edited. It is
// measurement; the ledger is intent. Keeping them in separate files is what
// stops a mirroring run from marking its own homework.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

export const STATE_SCHEMA = "anonrouter-dstack-escrow-state-v1";

export interface MirrorObservation {
  status: "PRESENT" | "FAILED";
  /** Manifest digest, file sha256 or bundle sha256, whichever identifies it. */
  observedDigest: string | null;
  bytes: number | null;
  /** Human-readable record of every check that actually ran and passed. */
  checks: string[];
  verifiedAt: string;
}

export interface EscrowState {
  schema: typeof STATE_SCHEMA;
  /** entryId -> "kind:location" -> observation */
  mirrors: Record<string, Record<string, MirrorObservation>>;
}

/**
 * Resolve the escrow archive root.
 *
 * Deliberately OUTSIDE the repository. A 170 MB guest image inside the worktree
 * would be one `git add -A` away from a commit that cannot be pushed, and the
 * escrow must survive `git clean` rather than be deleted by it.
 */
export function archiveRoot(declared: string): string {
  const fromEnv = process.env.ANONROUTER_ESCROW_ROOT;
  const raw = fromEnv && fromEnv.length > 0 ? fromEnv : declared;
  return raw.startsWith("~/") ? join(homedir(), raw.slice(2)) : resolve(raw);
}

export function ensureDir(path: string): string {
  mkdirSync(path, { recursive: true });
  return path;
}

export function sha256File(path: string): { digest: string; bytes: number } {
  const buf = readFileSync(path);
  return { digest: createHash("sha256").update(buf).digest("hex"), bytes: buf.length };
}

export function sha256Buffer(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** npm-style subresource integrity, which is what package-lock.json records. */
export function sha512Integrity(buf: Buffer): string {
  return `sha512-${createHash("sha512").update(buf).digest("base64")}`;
}

export class EscrowError extends Error {}

export function fail(message: string): never {
  throw new EscrowError(message);
}

export interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

/**
 * Run a command with arguments passed as an array, never a shell string.
 *
 * Array form is not a style preference here. It is what keeps a registry
 * reference or a filename from being reinterpreted by a shell, and it is the
 * same rule that keeps credentials out of argv: nothing in this file ever
 * interpolates a value into a command line.
 */
export function run(command: string, args: string[], options: { allowFailure?: boolean; maxBuffer?: number } = {}): RunResult {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 256 * 1024 * 1024
  });
  if (result.error) fail(`${command} could not be executed: ${result.error.message}`);
  const out: RunResult = {
    status: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? ""
  };
  if (out.status !== 0 && !options.allowFailure) {
    fail(`${command} ${args.join(" ")} exited ${out.status}\n${out.stderr.trim()}`);
  }
  return out;
}

/**
 * Same as `run`, but returns stdout as a Buffer.
 *
 * Needed because blobs are binary. Decoding a layer as UTF-8 and hashing the
 * result would produce a digest that never matches and, worse, could be made to
 * match by an attacker choosing bytes that survive the round trip.
 */
export function runBuffer(command: string, args: string[], maxBuffer = 1024 * 1024 * 1024): Buffer {
  const result = spawnSync(command, args, { maxBuffer });
  if (result.error) fail(`${command} could not be executed: ${result.error.message}`);
  if ((result.status ?? -1) !== 0) {
    fail(`${command} ${args.join(" ")} exited ${result.status}\n${(result.stderr ?? Buffer.alloc(0)).toString()}`);
  }
  return result.stdout ?? Buffer.alloc(0);
}

export function requireTool(command: string, versionArgs: string[] = ["--version"]): string {
  const result = spawnSync(command, versionArgs, { encoding: "utf8" });
  if (result.error || (result.status ?? 1) !== 0) {
    fail(
      `required tool '${command}' is not available.\n` +
        `Install it and re-run. This tool refuses to continue with a partial mirror,\n` +
        `because a partial mirror that reports success is the failure mode it exists to prevent.`
    );
  }
  return `${result.stdout}${result.stderr}`.trim().split("\n")[0] ?? command;
}

// ---------------------------------------------------------------------------
// Observed state
// ---------------------------------------------------------------------------

export function loadState(path: string): EscrowState {
  if (!existsSync(path)) return { schema: STATE_SCHEMA, mirrors: {} };
  const parsed = JSON.parse(readFileSync(path, "utf8")) as EscrowState;
  if (parsed.schema !== STATE_SCHEMA) fail(`${path}: unexpected state schema ${parsed.schema}`);
  return parsed;
}

export function saveState(path: string, state: EscrowState): void {
  ensureDir(dirname(path));
  const ordered: EscrowState = { schema: STATE_SCHEMA, mirrors: {} };
  for (const entryId of Object.keys(state.mirrors).sort()) {
    ordered.mirrors[entryId] = {};
    for (const key of Object.keys(state.mirrors[entryId]).sort()) {
      ordered.mirrors[entryId][key] = state.mirrors[entryId][key];
    }
  }
  writeFileSync(path, `${JSON.stringify(ordered, null, 2)}\n`, { mode: 0o644 });
}

export function recordMirror(
  state: EscrowState,
  entryId: string,
  mirrorKey: string,
  observation: MirrorObservation
): void {
  state.mirrors[entryId] ??= {};
  state.mirrors[entryId][mirrorKey] = observation;
}

export function mirrorKey(kind: string, location: string): string {
  return `${kind}:${location}`;
}

// ---------------------------------------------------------------------------
// Checksum manifests for on-disk archives
// ---------------------------------------------------------------------------

function walk(dir: string, base: string, out: string[]): string[] {
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, base, out);
    else out.push(relative(base, full));
  }
  return out;
}

/**
 * Write a SHA256SUMS file over every file in a directory and return a single
 * digest committing to the whole tree.
 *
 * The tree digest is sha256 over sorted "<sha256>  <path>" lines, which is the
 * same construction the export manifest and the ingress source pin use. Reusing
 * it means a reviewer who has checked one has checked all three.
 *
 * `SHA256SUMS` itself is excluded from its own contents, for the obvious reason.
 */
export function writeChecksumManifest(dir: string): { treeDigest: string; fileCount: number; totalBytes: number } {
  const files = walk(dir, dir, []).filter((f) => f !== "SHA256SUMS");
  const lines: string[] = [];
  let totalBytes = 0;
  for (const file of files) {
    const { digest, bytes } = sha256File(join(dir, file));
    totalBytes += bytes;
    lines.push(`${digest}  ${file}`);
  }
  writeFileSync(join(dir, "SHA256SUMS"), `${lines.join("\n")}\n`, { mode: 0o644 });
  return { treeDigest: sha256Buffer(lines.join("\n")), fileCount: files.length, totalBytes };
}

/**
 * Recheck a directory against its own SHA256SUMS.
 *
 * Detects three different things and reports them separately, because they mean
 * different things: a corrupted file, a missing file, and a file nobody
 * expected. The last is the one a naive verifier misses, and it is how a
 * substituted archive passes a check that only iterates the manifest.
 */
export function verifyChecksumManifest(dir: string): { treeDigest: string; fileCount: number } {
  const manifestPath = join(dir, "SHA256SUMS");
  if (!existsSync(manifestPath)) fail(`${dir}: no SHA256SUMS, so the archive cannot be verified`);
  const lines = readFileSync(manifestPath, "utf8").trimEnd().split("\n").filter(Boolean);
  const expected = new Map<string, string>();
  for (const line of lines) {
    const match = /^([0-9a-f]{64})\s\s(.+)$/.exec(line);
    if (!match) fail(`${manifestPath}: malformed line: ${line}`);
    expected.set(match[2], match[1]);
  }
  const present = new Set(walk(dir, dir, []).filter((f) => f !== "SHA256SUMS"));

  for (const [file, digest] of expected) {
    if (!present.has(file)) fail(`${dir}: ${file} is listed in SHA256SUMS and MISSING from the archive`);
    const actual = sha256File(join(dir, file)).digest;
    if (actual !== digest) fail(`${dir}: ${file} hashes to ${actual}, SHA256SUMS says ${digest}`);
  }
  for (const file of present) {
    if (!expected.has(file)) {
      fail(`${dir}: ${file} is present in the archive and ABSENT from SHA256SUMS; an unlisted file is an unverified file`);
    }
  }
  return { treeDigest: sha256Buffer(lines.join("\n")), fileCount: expected.size };
}

/**
 * Replace a file only after the replacement has been written and checked.
 *
 * Writing straight to the destination means a failure mid-write destroys the
 * copy being replaced, which for an escrow archive turns a bad update into a
 * total loss.
 */
export function atomicReplace(tempPath: string, finalPath: string): void {
  ensureDir(dirname(finalPath));
  renameSync(tempPath, finalPath);
}

export function nowIso(): string {
  return new Date().toISOString();
}
