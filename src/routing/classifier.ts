import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { env, pipeline } from "@huggingface/transformers";
import type { ChatMessage } from "../providers/types.js";
import { messageText } from "../metering/tokens.js";

export const routingTasks = [
  "general",
  "coding",
  "math",
  "research",
  "writing",
  "translation",
  "summarization",
  "analysis"
] as const;

export type RoutingTask = (typeof routingTasks)[number];
export type RoutingComplexity = "low" | "high";

export interface RoutingClassification {
  task: RoutingTask;
  effectiveTask: RoutingTask;
  complexity: RoutingComplexity;
  needsWeb: boolean;
  /** Content a moderated model is likely to refuse; steers selection toward uncensored routes. */
  maybeSensitive: boolean;
  taskConfidence: number;
  taskMargin: number;
  complexityConfidence: number;
  nearestSimilarity: number;
  abstained: boolean;
  classifierVersion: number;
  latencyMs: number;
}

interface ArtifactItem {
  index: number;
  task: RoutingTask;
  complexity: RoutingComplexity;
}

interface ArtifactMetadata {
  version: number;
  model_id: string;
  model_revision: string;
  dtype: "q4";
  input_prefix: string;
  dimensions: number;
  k_task: number;
  k_complexity: number;
  vote_temperature: number;
  confidence_threshold: number;
  vector_file: string;
  vector_sha256: string;
  items: ArtifactItem[];
}

interface Neighbor extends ArtifactItem {
  similarity: number;
}

interface Vote<T extends string> {
  label: T;
  confidence: number;
  margin: number;
}

type FeatureExtractor = (
  inputs: string[],
  options: { pooling: "mean"; normalize: true }
) => Promise<{ tolist(): number[][] }>;

export interface RequestClassifierConfig {
  cacheDir: string;
  artifactMetadataPath: string;
  allowRemoteModels: boolean;
  maxInputChars: number;
  confidenceThreshold?: number;
  queueTimeoutMs?: number;
  maxQueue?: number;
}

interface QueuedClassification {
  messages: ChatMessage[];
  resolve: (result: RoutingClassification) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
  settled: boolean;
}

function isRoutingTask(value: unknown): value is RoutingTask {
  return typeof value === "string" && routingTasks.includes(value as RoutingTask);
}

function validateMetadata(value: unknown): ArtifactMetadata {
  if (!value || typeof value !== "object") throw new Error("Router classifier metadata is invalid");
  const metadata = value as Partial<ArtifactMetadata>;
  if (
    metadata.version !== 1 ||
    typeof metadata.model_id !== "string" ||
    typeof metadata.model_revision !== "string" ||
    metadata.dtype !== "q4" ||
    typeof metadata.input_prefix !== "string" ||
    !Number.isInteger(metadata.dimensions) ||
    !Number.isInteger(metadata.k_task) ||
    !Number.isInteger(metadata.k_complexity) ||
    typeof metadata.vote_temperature !== "number" ||
    typeof metadata.confidence_threshold !== "number" ||
    typeof metadata.vector_file !== "string" ||
    typeof metadata.vector_sha256 !== "string" ||
    !Array.isArray(metadata.items) ||
    metadata.items.some((item) => !isRoutingTask(item.task) || !["low", "high"].includes(item.complexity))
  ) {
    throw new Error("Router classifier metadata is invalid");
  }
  return metadata as ArtifactMetadata;
}

function cosine(vector: number[], training: Float32Array, offset: number, dimensions: number) {
  let dot = 0;
  let vectorNorm = 0;
  let trainingNorm = 0;
  for (let index = 0; index < dimensions; index += 1) {
    const a = vector[index] ?? 0;
    const b = training[offset + index] ?? 0;
    dot += a * b;
    vectorNorm += a * a;
    trainingNorm += b * b;
  }
  return dot / Math.max(Number.EPSILON, Math.sqrt(vectorNorm) * Math.sqrt(trainingNorm));
}

function weightedVote<T extends string>(neighbors: Neighbor[], field: "task" | "complexity", k: number, temperature: number): Vote<T> {
  const votes = new Map<T, number>();
  for (const neighbor of neighbors.slice(0, k)) {
    const label = neighbor[field] as T;
    const weight = Math.exp(neighbor.similarity * temperature);
    votes.set(label, (votes.get(label) ?? 0) + weight);
  }
  const ordered = [...votes.entries()].sort((a, b) => b[1] - a[1]);
  const total = ordered.reduce((sum, entry) => sum + entry[1], 0);
  return {
    label: ordered[0]?.[0] as T,
    confidence: (ordered[0]?.[1] ?? 0) / Math.max(Number.EPSILON, total),
    margin: ((ordered[0]?.[1] ?? 0) - (ordered[1]?.[1] ?? 0)) / Math.max(Number.EPSILON, total)
  };
}

function needsWeb(text: string, task: RoutingTask) {
  if (task === "research") return true;
  return /\b(latest|current|today|recent|citations?|sources?|verify|published|live|availability|exchange rate)\b/i.test(text);
}

/**
 * Lexical signal that a moderated provider model would likely refuse the
 * request, so selection should steer toward an uncensored route instead. This
 * is a routing preference, not a policy judgment: it only decides WHICH model
 * answers. Kept high-precision (explicit adult/unfiltered intent, graphic
 * fiction cues) so ordinary prompts never lose the frontier default pool.
 */
export function maybeSensitiveContent(text: string): boolean {
  const adult = /\b(?:nsfw|explicit|erotic|erotica|smut|lewd|porn\w*|hentai|kink\w*|fetish\w*|bdsm|nudity|sexual(?:ly)?|seductive|adult (?:story|stories|content|fiction|roleplay|chat))\b/i;
  const unfiltered = /\b(?:uncensored|unfiltered|no (?:content )?filter|without (?:any )?(?:censorship|restrictions|filters)|no restrictions)\b/i;
  const graphic = /\b(?:gore|gory|graphic violence|extremely violent|slasher|torture scene|dark romance|taboo)\b/i;
  return adult.test(text) || unfiltered.test(text) || graphic.test(text);
}

/**
 * High-precision lexical guardrails for requests whose intent should not be
 * lost when an otherwise useful embedding classifier has a low margin.
 */
export function explicitRoutingTask(text: string): RoutingTask | null {
  const language = /\b(?:python|typescript|javascript|java|rust|golang|c\+\+|c#|swift|kotlin|ruby|php|sql|bash|shell|react|next\.?js|node\.?js)\b/i;
  const artifact = /\b(?:code|program|script|function|class|api|cli|application|app|website|component|library|package|module|query|endpoint|server)\b/i;
  const implementationAction = /\b(?:debug|refactor|implement|compile|fix|build|create|optimi[sz]e)\b/i;
  const writtenArtifact = /\b(?:code|program|script|function|class|api|cli|library|package|module|query|endpoint)\b/i;
  if ((language.test(text) && artifact.test(text)) || (implementationAction.test(text) && artifact.test(text))) return "coding";
  if (/\b(?:write|generate)\b/i.test(text) && writtenArtifact.test(text)) return "coding";
  if (/\breview\b/i.test(text) && /\b(?:code|function|class|module|pull request|diff)\b/i.test(text)) return "coding";
  if (/\b(?:stack trace|traceback|syntax error|type error|runtime error|compiler error)\b/i.test(text)) return "coding";
  return null;
}

export function explicitHighComplexity(text: string, task: RoutingTask) {
  if (text.length >= 700 && ["coding", "math", "research", "analysis"].includes(task)) return true;
  if (task !== "coding") return false;
  return /\b(?:advanced|production[- ]ready|full[- ]stack|distributed|concurrent|architecture|authentication|authorization|database migration|test suite|multiple files|entire codebase|complete (?:application|system|service)|security review|performance profiling)\b/i.test(text);
}

function latestUserText(messages: ChatMessage[], maxInputChars: number) {
  const text = messageText([...messages].reverse().find((message) => message.role === "user")?.content);
  return text.length <= maxInputChars ? text : `${text.slice(0, Math.floor(maxInputChars / 2))}\n${text.slice(-Math.ceil(maxInputChars / 2))}`;
}

export class LocalRequestClassifier {
  private readonly metadata: ArtifactMetadata;
  private readonly vectors: Float32Array;
  private readonly config: RequestClassifierConfig;
  private extractor: FeatureExtractor | null = null;
  private inferenceActive = false;
  private readonly queue: QueuedClassification[] = [];

  constructor(config: RequestClassifierConfig) {
    this.config = config;
    const metadataPath = resolve(config.artifactMetadataPath);
    this.metadata = validateMetadata(JSON.parse(readFileSync(metadataPath, "utf8")));
    const vectorBuffer = readFileSync(resolve(dirname(metadataPath), this.metadata.vector_file));
    const hash = createHash("sha256").update(vectorBuffer).digest("hex");
    if (hash !== this.metadata.vector_sha256) throw new Error("Router classifier vector checksum mismatch");
    const expectedBytes = this.metadata.items.length * this.metadata.dimensions * Float32Array.BYTES_PER_ELEMENT;
    if (vectorBuffer.byteLength !== expectedBytes) throw new Error("Router classifier vector size mismatch");
    this.vectors = new Float32Array(
      vectorBuffer.buffer.slice(vectorBuffer.byteOffset, vectorBuffer.byteOffset + vectorBuffer.byteLength)
    );
  }

  async initialize() {
    if (this.extractor) return;
    env.cacheDir = resolve(this.config.cacheDir);
    env.allowRemoteModels = this.config.allowRemoteModels;
    this.extractor = (await pipeline("feature-extraction", this.metadata.model_id, {
      dtype: this.metadata.dtype,
      revision: this.metadata.model_revision
    })) as unknown as FeatureExtractor;
    await this.extractor([`${this.metadata.input_prefix}warm up`], { pooling: "mean", normalize: true });
  }

  classify(messages: ChatMessage[]): Promise<RoutingClassification> {
    const maxQueue = this.config.maxQueue ?? 8;
    if (this.queue.length >= maxQueue) {
      return Promise.reject(new Error("Router classifier queue is full"));
    }
    const timeoutMs = this.config.queueTimeoutMs ?? 100;
    return new Promise<RoutingClassification>((resolve, reject) => {
      const queued: QueuedClassification = {
        messages,
        resolve,
        reject,
        settled: false,
        timer: setTimeout(() => {
          queued.settled = true;
          reject(new Error("Router classifier queue timed out"));
        }, timeoutMs)
      };
      this.queue.push(queued);
      this.drainQueue();
    });
  }

  private drainQueue() {
    if (this.inferenceActive) return;
    const queued = this.queue.shift();
    if (!queued) return;
    if (queued.settled) {
      clearTimeout(queued.timer);
      this.drainQueue();
      return;
    }
    this.inferenceActive = true;
    this.classifyNow(queued.messages)
      .then((result) => {
        if (!queued.settled) queued.resolve(result);
      })
      .catch((error: unknown) => {
        if (!queued.settled) queued.reject(error instanceof Error ? error : new Error("Router classifier failed"));
      })
      .finally(() => {
        queued.settled = true;
        clearTimeout(queued.timer);
        this.inferenceActive = false;
        this.drainQueue();
      });
  }

  private async classifyNow(messages: ChatMessage[]): Promise<RoutingClassification> {
    if (!this.extractor) throw new Error("Router classifier is not initialized");
    const startedAt = performance.now();
    const text = latestUserText(messages, this.config.maxInputChars);
    const output = await this.extractor([`${this.metadata.input_prefix}${text}`], { pooling: "mean", normalize: true });
    const vector = output.tolist()[0];
    if (!vector || vector.length !== this.metadata.dimensions) throw new Error("Router classifier returned an invalid embedding");

    const neighbors = this.metadata.items
      .map((item) => ({
        ...item,
        similarity: cosine(vector, this.vectors, item.index * this.metadata.dimensions, this.metadata.dimensions)
      }))
      .sort((a, b) => b.similarity - a.similarity);
    const taskVote = weightedVote<RoutingTask>(neighbors, "task", this.metadata.k_task, this.metadata.vote_temperature);
    const explicitTask = explicitRoutingTask(text);
    const task = explicitTask ?? taskVote.label;
    const sameTask = neighbors.filter((neighbor) => neighbor.task === task);
    const complexityVote = weightedVote<RoutingComplexity>(
      sameTask.length >= this.metadata.k_complexity ? sameTask : neighbors,
      "complexity",
      this.metadata.k_complexity,
      this.metadata.vote_temperature
    );
    const confidenceThreshold = this.config.confidenceThreshold ?? this.metadata.confidence_threshold;
    const hasExplicitTask = explicitTask !== null;
    const abstained = !hasExplicitTask && taskVote.confidence < confidenceThreshold;
    const complexity = explicitHighComplexity(text, task) ? "high" : complexityVote.label;

    return {
      task,
      effectiveTask: abstained ? "general" : task,
      complexity,
      needsWeb: needsWeb(text, task),
      maybeSensitive: maybeSensitiveContent(text),
      taskConfidence: hasExplicitTask ? 1 : taskVote.confidence,
      taskMargin: hasExplicitTask ? 1 : taskVote.margin,
      complexityConfidence: complexityVote.confidence,
      nearestSimilarity: neighbors[0]?.similarity ?? 0,
      abstained,
      classifierVersion: this.metadata.version,
      latencyMs: performance.now() - startedAt
    };
  }
}
