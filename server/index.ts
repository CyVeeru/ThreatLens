import "dotenv/config";
import express, { Response, NextFunction } from 'express';
import type { Request } from 'express';
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { startOsintBackgroundJobs } from "./backgroundJobs";
import { assertModeConsistency, logProductionMode } from "./productionMode";
import { createServer } from "node:http";
import rateLimit from "express-rate-limit";
import { env } from "./env";

// Boot-time sanity check — fail loud if mutually-exclusive mode flags are set
// (THREATLENS_STRICT=1 AND THREATLENS_DEMO=1). Runs before any module-init so
// the operator sees a clear error instead of a half-strict half-demo box.
assertModeConsistency();

const app = express();
const httpServer = createServer(app);
app.set("trust proxy", process.env.TRUST_PROXY || "loopback, linklocal, uniquelocal");
const REQUEST_BODY_LIMIT = env("BODY_LIMIT") || "10mb";

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

app.use(
  express.json({
    limit: REQUEST_BODY_LIMIT,
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ limit: REQUEST_BODY_LIMIT, extended: false }));

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  const cleanSource = JSON.stringify(source.replace(/[\r\n\t]/g, " ").slice(0, 40));
  const cleanMessage = JSON.stringify(message.replace(/[\r\n\t]/g, " ").slice(0, 2000));
  console.log(`${formattedTime} source=${cleanSource} message=${cleanMessage}`);
}

function redactForLog(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[truncated]";
  if (value == null) return value;
  if (typeof value === "string") {
    return value.length > 240 ? `${value.slice(0, 240)}…[truncated]` : value;
  }
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redactForLog(v, depth + 1));
  if (typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (/password|token|secret|api[-_]?key|authorization|access_token/i.test(key)) {
      out[key] = "[redacted]";
    } else if (/body|content|payload|result|report|narrative|html|markdown|base64|data/i.test(key)) {
      out[key] = "[redacted]";
    } else {
      out[key] = redactForLog(raw, depth + 1);
    }
  }
  return out;
}

// Edge limiter for the credential endpoint. express-rate-limit evicts expired
// buckets itself; routes.ts adds a second, per-route limiter on the same path.
const loginRateLimit = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { detail: "too many requests" },
});

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  const connectSrc = process.env.NODE_ENV === "development"
    ? "'self' ws: wss: http://localhost:* http://127.0.0.1:*"
    : "'self'";
  const scriptSrc = process.env.NODE_ENV === "development"
    ? "'self' 'unsafe-inline' 'unsafe-eval'"
    : "'self'";
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    // client/index.html loads Inter + Geist Mono from Google Fonts.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: blob:",
    "font-src 'self' data: https://fonts.gstatic.com",
    `connect-src ${connectSrc}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; "));
  next();
});

app.use("/api/v1/auth/login", loginRateLimit);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        const safe = JSON.stringify(redactForLog(capturedJsonResponse));
        logLine += ` :: ${safe.length > 1200 ? `${safe.slice(0, 1200)}…[truncated]` : safe}`;
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  await registerRoutes(httpServer, app);

  app.use("/api", (_req: Request, res: Response) => {
    res.status(404).json({ detail: "API route not found" });
  });

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      return next(err);
    }

    // ThreatLens production mode — refuse to silently fall back to mock and
    // surface 409 so the dashboard shows a clear "configure a real provider"
    // hint rather than a generic 500.
    if (err && err.name === "MockFallbackBlockedError") {
      console.warn("MockFallbackBlockedError surfaced:", err.message);
      return res.status(409).json({
        detail: err.message,
        message: err.message,
        subsystem: err.subsystem,
      });
    }

    // Phase 0 — external scanner (CLI binary or API credential) not available.
    // 409 with structured body so the UI renders a "Install / Configure" CTA.
    if (err && err.name === "ToolUnavailableError") {
      console.warn(`ToolUnavailableError surfaced (${err.tool}):`, err.message);
      return res.status(409).json({
        detail: err.message,
        message: err.message,
        tool: err.tool,
        kind: err.kind,
        installHint: err.installHint,
        configHint: err.configHint,
      });
    }

    if (err && err.name === "PortraitGeneratorUnavailableError") {
      console.warn(`PortraitGeneratorUnavailableError surfaced (${err.tool}):`, err.message);
      return res.status(409).json({
        detail: err.message,
        message: err.message,
        tool: err.tool,
        installHint: err.installHint,
      });
    }

    // Phase 0 — external scanner timed out. 504 (gateway timeout) so it is
    // distinct from upstream-AI failures (LiveAiError → 502).
    if (err && err.name === "ToolTimeoutError") {
      console.warn(`ToolTimeoutError surfaced (${err.tool}):`, err.message);
      return res.status(504).json({
        detail: err.message,
        message: err.message,
        tool: err.tool,
        timeoutMs: err.timeoutMs,
        stderrTail: err.stderrTail,
      });
    }

    // Phase 0 — external scanner crashed or returned unparseable output. 502
    // so it groups with other "upstream failed" outcomes in monitoring.
    if (err && err.name === "ToolExecutionError") {
      console.warn(`ToolExecutionError surfaced (${err.tool}):`, err.message);
      return res.status(502).json({
        detail: err.message,
        message: err.message,
        tool: err.tool,
        exitCode: err.exitCode,
        stderrTail: err.stderrTail,
      });
    }

    // v2.26 — surface LiveAiError as 502 with the underlying provider reason
    // so the UI can show a real diagnostic instead of a generic 500.
    if (err && err.name === "LiveAiError") {
      console.warn("LiveAiError surfaced:", err.message);
      return res.status(502).json({
        detail: err.message,
        message: err.message,
        providerLabel: err.providerLabel,
        aiDiagnostic: {
          task: err.task,
          provider: err.provider,
          reason: err.reason,
          httpStatus: err.httpStatus,
          latencyMs: err.latencyMs,
        },
      });
    }

    const status = Number(err.status || err.statusCode) || 500;
    // 4xx messages are intentional (validation, not-found); 5xx messages can
    // carry SQL text or file paths, so only the log gets those in production.
    const exposeMessage = status < 500 || process.env.NODE_ENV !== "production";
    const message = exposeMessage ? (err.message || "Internal Server Error") : "Internal Server Error";

    console.error("Internal Server Error:", err);

    return res.status(status).json({ message, detail: message });
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 7099 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || "7099", 10);
  // `reusePort` is Linux-only. On macOS / FreeBSD it raises ENOTSUP and the
  // server fails to start. Enable it only when explicitly opted into via
  // env (`PORT_REUSE=1`) or when running on Linux — the typical container
  // / Compute-sandbox case where it is genuinely useful.
  const reusePort = process.env.PORT_REUSE === "1" || process.platform === "linux";
  // Loopback by default. ThreatLens is a single-operator workstation that
  // holds credentials, API keys and unreviewed intel; binding every interface
  // out of the box would expose all of that to the local network on first run.
  // Set THREATLENS_HOST=0.0.0.0 (and put it behind a reverse proxy with TLS)
  // to serve it to other machines deliberately.
  const host = (env("HOST") || "127.0.0.1").trim();
  httpServer.listen(
    {
      port,
      host,
      ...(reusePort ? { reusePort: true } : {}),
    },
    () => {
      log(`serving on http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}${host === "0.0.0.0" ? " (all interfaces)" : ""}`);
      logProductionMode();
      // v2.16 — boot the background OSINT scheduler. Per-tenant settings
      // (tenant_osint_settings) gate whether anything runs; default is OFF
      // for both fetch + analyze so existing tenants see no behaviour
      // change until they opt in.
      try {
        startOsintBackgroundJobs();
      } catch (e) {
        console.error("[osint-bg] failed to start:", e);
      }
    },
  );
})();
