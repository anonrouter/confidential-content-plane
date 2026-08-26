import { ulid } from "ulid";

export function newId(prefix?: string) {
  const id = ulid().toLowerCase();
  return prefix ? `${prefix}_${id}` : id;
}
