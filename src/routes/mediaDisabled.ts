import type { FastifyInstance } from "fastify";
import { AppError } from "../security/errors.js";

/**
 * Explicit-disable stubs for the media endpoints. When a surface is not enabled
 * for this role/deployment (e.g. the control plane, which holds no Venice key,
 * or a deployment with the image flag off) these return a clear 503
 * `media_disabled` instead of a silent, confusing 404. Image and speech are
 * governed by independent flags, so each has its own stub — exactly one handler
 * is ever registered per path per server.
 */
async function disabled() {
  throw new AppError(503, "media_disabled", "Media generation is not enabled on this deployment");
}

/**
 * Reject in `onRequest`, BEFORE Fastify parses the body.
 *
 * A handler-level rejection still lets the JSON parser materialize the request
 * in this process's memory first, and for speech that request is the user's
 * text arriving on the accounts host alongside their session cookie. The same
 * reasoning already governs /v1/routing/preview; this is the other half of it.
 * See docs/PHALA_CONFIDENTIAL_DATA_PLANE.md section 5.1.
 */
async function refuseBeforeBodyParse() {
  throw new AppError(503, "media_disabled", "Media generation is not enabled on this deployment");
}

export async function registerDisabledImageRoute(server: FastifyInstance) {
  server.post("/v1/images/generations", { onRequest: refuseBeforeBodyParse }, disabled);
}

export async function registerDisabledSpeechRoute(server: FastifyInstance) {
  server.post("/v1/audio/speech", { onRequest: refuseBeforeBodyParse }, disabled);
}

/** Both media stubs (used by the control role, which serves neither). */
export async function registerDisabledMediaRoutes(server: FastifyInstance) {
  await registerDisabledImageRoute(server);
  await registerDisabledSpeechRoute(server);
}
