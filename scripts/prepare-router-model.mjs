import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { env, pipeline } from "@huggingface/transformers";

const modelId = "onnx-community/embeddinggemma-300m-ONNX";
const revision = "5090578d9565bb06545b4552f76e6bc2c93e4a66";
const inputPrefix = "task: classification | query: ";
const cacheDir = resolve(
  process.argv.find((value) => value.startsWith("--cache-dir="))?.split("=")[1] ?? ".cache/router-models"
);
const artifactDir = resolve(
  process.argv.find((value) => value.startsWith("--artifact-dir="))?.split("=")[1] ?? "src/routing/artifacts"
);
const offline = process.argv.includes("--offline");
const downloadOnly = process.argv.includes("--download-only");

env.cacheDir = cacheDir;
env.allowRemoteModels = !offline;

const extractor = await pipeline("feature-extraction", modelId, {
  dtype: "q4",
  revision
});
await extractor([`${inputPrefix}warm up`], { pooling: "mean", normalize: true });

if (downloadOnly) {
  process.stdout.write(`Prepared ${modelId}@${revision} in ${cacheDir}\n`);
} else {
  // The public content-plane image needs only the pinned model cache. Keep the
  // private evaluation corpus out of that build input: it is required only when
  // regenerating the checked-in classifier vectors, not when warming an image.
  const { trainingCases } = await import("../experiments/router-eval/cases.mjs");
  const output = await extractor(trainingCases.map((item) => `${inputPrefix}${item.text}`), {
    pooling: "mean",
    normalize: true
  });
  const vectors = output.tolist();
  const dimensions = vectors[0]?.length ?? 0;
  if (dimensions <= 0 || vectors.length !== trainingCases.length) {
    throw new Error("Classifier artifact generation returned an unexpected embedding shape");
  }

  mkdirSync(artifactDir, { recursive: true });
  const binary = Buffer.alloc(vectors.length * dimensions * Float32Array.BYTES_PER_ELEMENT);
  let offset = 0;
  for (const vector of vectors) {
    if (vector.length !== dimensions) throw new Error("Classifier embeddings have inconsistent dimensions");
    for (const value of vector) {
      binary.writeFloatLE(value, offset);
      offset += Float32Array.BYTES_PER_ELEMENT;
    }
  }

  const binaryName = "embeddinggemma-q4-v1.f32";
  const metadataName = "embeddinggemma-q4-v1.json";
  writeFileSync(resolve(artifactDir, binaryName), binary);
  writeFileSync(
    resolve(artifactDir, metadataName),
    `${JSON.stringify({
      version: 1,
      model_id: modelId,
      model_revision: revision,
      dtype: "q4",
      input_prefix: inputPrefix,
      dimensions,
      k_task: 5,
      k_complexity: 3,
      vote_temperature: 20,
      confidence_threshold: 0.55,
      vector_file: binaryName,
      vector_sha256: createHash("sha256").update(binary).digest("hex"),
      items: trainingCases.map((item, index) => ({
        index,
        task: item.task,
        complexity: item.complexity
      }))
    }, null, 2)}\n`
  );

  process.stdout.write(`Wrote ${vectors.length}x${dimensions} classifier vectors to ${artifactDir}\n`);
}
