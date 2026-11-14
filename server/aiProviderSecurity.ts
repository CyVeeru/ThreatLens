import { isIP } from "node:net";
import { isPrivateOrReservedAddress, isSafeSourceFetchUrl } from "./sourceFetch";
import type { AiProviderKind } from "@shared/schema";
import { env } from "./env";

const SAFE_AI_PORTS = new Set(["", "443"]);
const LOCAL_AI_ALLOWED = env("ALLOW_LOCAL_AI") === "1";
/** http://localhost[:port] — the only plaintext target the opt-in permits. */
const LOOPBACK_BASE_URL = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i;

function normalizeBaseUrl(baseUrl: string | null | undefined): string {
  return (baseUrl || "").trim().replace(/\/+$/, "");
}

export function aiProviderBaseUrlSyncFailure(baseUrl: string | null | undefined): string | null {
  const value = normalizeBaseUrl(baseUrl);
  if (!value) return null;
  if (LOCAL_AI_ALLOWED && LOOPBACK_BASE_URL.test(value)) {
    return null;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return "AI provider base URL must be a valid HTTPS URL.";
  }
  if (parsed.protocol !== "https:") {
    return "AI provider base URL must use HTTPS.";
  }
  if (!SAFE_AI_PORTS.has(parsed.port)) {
    return "AI provider base URL must use the default HTTPS port.";
  }
  const host = parsed.hostname.toLowerCase();
  const addressHost = host.replace(/^\[/, "").replace(/\]$/, "");
  if (
    host === "localhost"
    || host === "localhost."
    || host.endsWith(".localhost")
    || host.endsWith(".local")
    || host.endsWith(".internal")
  ) {
    return "AI provider base URL cannot target local or internal hosts.";
  }
  if (isIP(addressHost) && isPrivateOrReservedAddress(addressHost)) {
    return "AI provider base URL cannot target private or reserved IP space.";
  }
  return null;
}


export async function validateAiProviderBaseUrl(kind: AiProviderKind, baseUrl: string | null | undefined): Promise<string | null> {
  const value = normalizeBaseUrl(baseUrl);
  if (!value) return null;
  // THREATLENS_ALLOW_LOCAL_AI opts in to a loopback gateway for ANY provider
  // kind, not just Ollama: LM Studio, llama.cpp, LiteLLM and Ollama's own shim
  // all speak the OpenAI protocol, so restricting the escape hatch to
  // kind === "ollama" made the flag useless for the common case. The sync
  // check below already honours the flag; skipping isSafeSourceFetchUrl here
  // keeps the two halves consistent, since that helper always rejects
  // loopback.
  if (LOCAL_AI_ALLOWED && LOOPBACK_BASE_URL.test(value)) {
    return null;
  }
  const syncFailure = aiProviderBaseUrlSyncFailure(value);
  if (syncFailure) return syncFailure;
  if (!(await isSafeSourceFetchUrl(value))) {
    return "AI provider base URL failed outbound safety checks.";
  }
  return null;
}
