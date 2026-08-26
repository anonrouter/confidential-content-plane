import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
// Each function asks for exactly the secret it uses, as a structural type,
// rather than for the whole application config. Both AppConfig and
// ContentPlaneConfig satisfy these, so every existing call site is unchanged,
// and the content plane no longer needs a config type carrying the cookie
// secret, the admin access token, or the email keys just to hash a network
// fingerprint.
type WithAppSecret = { readonly secrets: { readonly appSecret: string } };
type WithEmailHashSecret = { readonly secrets: { readonly emailHashSecret: string } };
type WithEmailEncryptionKey = { readonly secrets: { readonly emailEncryptionKey: string } };

function keyBytes(input: string) {
  return createHash("sha256").update(input).digest();
}

export function base64url(bytes: Buffer) {
  return bytes.toString("base64url");
}

export function randomToken(bytes = 32) {
  return base64url(randomBytes(bytes));
}

export function hmacSha256(value: string, secret: string) {
  return createHmac("sha256", secret).update(value, "utf8").digest("hex");
}

export function hashToken(value: string, config: WithAppSecret) {
  return hmacSha256(value, config.secrets.appSecret);
}

export function hashEmail(normalizedEmail: string, config: WithEmailHashSecret) {
  return hmacSha256(normalizedEmail, config.secrets.emailHashSecret);
}

export function hashNetworkFingerprint(raw: string, config: WithAppSecret, date = new Date()) {
  const day = date.toISOString().slice(0, 10);
  return hmacSha256(`${day}:${raw}`, config.secrets.appSecret);
}

export function encryptString(plainText: string, config: WithEmailEncryptionKey) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyBytes(config.secrets.emailEncryptionKey), iv);
  const ciphertext = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${base64url(iv)}.${base64url(tag)}.${base64url(ciphertext)}`;
}

export function decryptString(encrypted: string, config: WithEmailEncryptionKey) {
  const parts = encrypted.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error("Unsupported encrypted value");
  }
  const [, ivEncoded, tagEncoded, ciphertextEncoded] = parts;
  const decipher = createDecipheriv("aes-256-gcm", keyBytes(config.secrets.emailEncryptionKey), Buffer.from(ivEncoded, "base64url"));
  decipher.setAuthTag(Buffer.from(tagEncoded, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextEncoded, "base64url")), decipher.final()]).toString("utf8");
}

export function safeEqual(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}
