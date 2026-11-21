/**
 * obop-errors.ts: report an app's errors to BAPC Observability & Operations
 * (telemetry.bapc.app). Copy this one file into the app. No npm packages; runs
 * on Cloudflare Workers and Node 22.
 *
 *   import { reportError } from "./obop-errors";
 *   // Workers: ctx.waitUntil(reportError(env, err, { request }));
 *   // Node:    void reportError(process.env, err, { route: "/api/orders" });
 *
 * Settings (Worker secrets/vars, or process.env):
 *   OBOP_INGEST_TOKEN  required, from `npm run ops -- connect-app` (a secret)
 *   OBOP_SYSTEM_ID     required, e.g. "bapc-sys-43" (infrastructure) or "bapc-sys-101" (an app)
 *   OBOP_TENANT_ID     optional, default "bapc"
 *   OBOP_SERVICE_KEY   optional, default "web"
 *   OBOP_ENVIRONMENT   optional, default "production"
 *   OBOP_INGEST_URL    optional, default https://telemetry.bapc.app/api/v1/telemetry/ingest
 *
 * reportError never throws, gives up after 3 seconds, does nothing when the
 * token or system ID is missing, sends at most 20 events a minute per isolate
 * or process, and strips query strings, emails and token-like values first.
 * See docs/integrations/app-errors.md.
 */

export interface ErrorContext {
  /** The incoming request; only its method and path are sent (never the query string or headers). */
  readonly request?: { readonly method?: string; readonly url?: string };
  /** A route or job name, e.g. "/api/orders/:id" or "nightly-sync". */
  readonly route?: string;
  /** "high" (default) or "critical". */
  readonly severity?: "high" | "critical";
  /** The app's version or commit. */
  readonly release?: string;
  /** Extra details: short strings, numbers or booleans. Scrubbed like the message. */
  readonly attributes?: Readonly<Record<string, string | number | boolean>>;
}

type Env = Readonly<Record<string, unknown>> | undefined | null;

export const DEFAULT_INGEST_URL = "https://telemetry.bapc.app/api/v1/telemetry/ingest";
const TIMEOUT_MS = 3_000;
const MAX_PER_MINUTE = 20;
const SYSTEM_ID = /^bapc-sys-(?:\d{2}|1\d{2})$/;
const SLUG = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** Send times in the last minute, per isolate (Workers) or process (Node). */
const sent: number[] = [];

function allow(now: number): boolean {
  while (sent.length && now - sent[0]! >= 60_000) sent.shift();
  if (sent.length >= MAX_PER_MINUTE) return false;
  sent.push(now);
  return true;
}

const SECRET_KEYS = "access_token|refresh_token|id_token|token|client_secret|secret|password|passwd|pwd|api[_-]?key|apikey|private[_-]?key|authorization|session_?id|session|set-cookie|cookie|signature|otp|jwt";

/**
 * Removes what must never leave the app: query strings, emails, bearer and
 * BAPC tokens, JWTs, `secret=value` pairs and long random-looking strings.
 */
export function scrub(text: string): string {
  return text
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [token]")
    .replace(/\bobop\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{20,}/g, "[token]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[token]")
    .replace(/((?:https?:)?\/\/[^\s?#"'<>]+|(?:^|[\s"'(=])\/[^\s?#"'<>]*)\?[^\s#"'<>]*/g, "$1")
    .replace(/\?[^\s#"'<>]*=[^\s#"'<>]*/g, "")
    .replace(new RegExp(`\\b(${SECRET_KEYS})(["']?\\s*[:=]\\s*["']?)[^\\s"'&,;}]+`, "gi"), "$1$2[redacted]")
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email]")
    .replace(/\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{32,}\b/g, "[token]")
    .replace(/\b[0-9a-f]{24,}\b/gi, "[token]");
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

/** Only the path of a URL; no origin details beyond it, never the query or fragment. */
function pathOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url, "http://x").pathname.slice(0, 512);
  } catch {
    return undefined;
  }
}

function parts(error: unknown): { name: string; message: string; stack?: string } {
  if (error instanceof Error) return { name: error.name || "Error", message: error.message || error.name || "Error", ...(error.stack ? { stack: error.stack } : {}) };
  if (typeof error === "string") return { name: "Error", message: error };
  try {
    return { name: "Error", message: JSON.stringify(error) ?? String(error) };
  } catch {
    return { name: "Error", message: String(error) };
  }
}

/**
 * Builds the event the telemetry gateway accepts, or undefined when the app
 * isn't connected (no token or system ID). Exported for tests.
 */
export function buildErrorEvent(env: Env, error: unknown, context: ErrorContext = {}, now: Date = new Date()): { url: string; token: string; body: { events: [Record<string, unknown>] } } | undefined {
  const token = str(env?.OBOP_INGEST_TOKEN);
  const systemId = str(env?.OBOP_SYSTEM_ID);
  if (!token || !systemId || !SYSTEM_ID.test(systemId)) return undefined;
  const tenantId = str(env?.OBOP_TENANT_ID) ?? "bapc";
  const serviceKey = str(env?.OBOP_SERVICE_KEY) ?? "web";
  const environment = str(env?.OBOP_ENVIRONMENT) ?? "production";
  if (!SLUG.test(tenantId) || !SLUG.test(serviceKey) || !["development", "staging", "production"].includes(environment)) return undefined;

  const e = parts(error);
  const attributes: Record<string, string | number | boolean> = { "error.name": scrub(e.name).slice(0, 128) };
  if (e.stack) attributes["error.stack"] = scrub(e.stack).slice(0, 2000);
  const method = str(context.request?.method);
  if (method) attributes["http.method"] = method.toUpperCase().slice(0, 16);
  const path = pathOf(context.request?.url);
  if (path) attributes["http.path"] = scrub(path);
  if (context.route) attributes["app.route"] = scrub(context.route).slice(0, 256);
  if (context.release) attributes["app.release"] = scrub(context.release).slice(0, 128);
  for (const [k, v] of Object.entries(context.attributes ?? {}).slice(0, 40)) {
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(k) || k in attributes) continue;
    if (typeof v === "string") attributes[k] = scrub(v).slice(0, 1000);
    else if (typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) attributes[k] = v;
  }

  return {
    url: str(env?.OBOP_INGEST_URL) ?? DEFAULT_INGEST_URL,
    token,
    body: {
      events: [
        {
          schemaVersion: "1.0",
          eventId: crypto.randomUUID(),
          tenantId,
          systemId,
          serviceKey,
          environment,
          timestamp: now.toISOString(),
          eventType: "log.record",
          severity: context.severity === "critical" ? "critical" : "high",
          message: (scrub(`${e.name}: ${e.message}`).slice(0, 2000) || "Error"),
          attributes,
        },
      ],
    },
  };
}

/**
 * Reports one error. Resolves to true when the gateway accepted it, false
 * otherwise. Never throws; gives up after 3 seconds.
 */
export async function reportError(env: Env, error: unknown, context: ErrorContext = {}): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const built = buildErrorEvent(env, error, context);
    if (!built || !allow(Date.now())) return false;
    const abort = new AbortController();
    timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
    const res = await fetch(built.url, {
      method: "POST",
      headers: { authorization: `Bearer ${built.token}`, "content-type": "application/json" },
      body: JSON.stringify(built.body),
      signal: abort.signal,
    });
    // Read the body so the connection is released (Workers warns about unread bodies).
    await res.text().catch(() => "");
    return res.status === 202;
  } catch {
    return false;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
