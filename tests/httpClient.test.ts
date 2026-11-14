import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { httpRequest, outboundProtocolViolation } from "../server/httpClient";

// Local HTTP fixture. Production traffic is HTTPS-only; the tests opt in with
// `allowInsecure` so they can exercise the client without certificates.
let server: Server;
let base = "";

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url || "/", "http://x");
    if (url.pathname === "/slow") {
      const ms = Number(url.searchParams.get("ms") || "800");
      setTimeout(() => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true, echo: req.headers["x-probe"] ?? null }));
      }, ms);
      return;
    }
    if (url.pathname === "/redirect-http") {
      res.statusCode = 302;
      res.setHeader("location", "http://169.254.169.254/latest/meta-data/");
      res.end();
      return;
    }
    if (url.pathname === "/big") {
      res.setHeader("content-type", "text/plain");
      res.end("x".repeat(50_000));
      return;
    }
    res.statusCode = 404;
    res.end("nope");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("httpClient", () => {
  it("does not block the event loop while a provider call is in flight", async () => {
    let ticks = 0;
    const timer = setInterval(() => {
      ticks += 1;
    }, 20);
    const res = await httpRequest({
      url: `${base}/slow?ms=600`,
      timeoutSeconds: 10,
      allowInsecure: true,
      headers: { "x-probe": "1" },
    });
    clearInterval(timer);
    expect(res.ok).toBe(true);
    expect(JSON.parse(res.body).echo).toBe("1");
    // With the old spawnSync client this would have been 0.
    expect(ticks).toBeGreaterThan(10);
  });

  it("refuses plain-HTTP provider URLs unless loopback is explicitly allowed", async () => {
    expect(outboundProtocolViolation("https://api.openai.com/v1")).toBeNull();
    expect(outboundProtocolViolation("http://api.openai.com/v1")).toMatch(/HTTPS/);
    const res = await httpRequest({ url: `${base}/slow?ms=1`, timeoutSeconds: 5 });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(0);
    expect(res.error).toMatch(/HTTPS/);
  });

  it("blocks redirects that downgrade to http / internal targets", async () => {
    const res = await httpRequest({ url: `${base}/redirect-http`, timeoutSeconds: 5, allowInsecure: false });
    // The first hop is itself refused (http) — with allowInsecure the redirect target is still checked.
    expect(res.ok).toBe(false);
    const res2 = await httpRequest({ url: `${base}/redirect-http`, timeoutSeconds: 5, allowInsecure: true });
    expect(res2.ok).toBe(false);
    expect(res2.body).toBe("");
  });

  it("honours the abort signal", async () => {
    const controller = new AbortController();
    const started = Date.now();
    setTimeout(() => controller.abort(new Error("cancelled by test")), 100);
    const res = await httpRequest({
      url: `${base}/slow?ms=3000`,
      timeoutSeconds: 10,
      allowInsecure: true,
      signal: controller.signal,
    });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/cancelled by test/);
    expect(Date.now() - started).toBeLessThan(2500);
  });

  it("enforces the wall-clock timeout", async () => {
    const res = await httpRequest({ url: `${base}/slow?ms=3000`, timeoutSeconds: 1, allowInsecure: true });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/timed out/);
  });

  it("caps the response body at maxBytes", async () => {
    const res = await httpRequest({ url: `${base}/big`, timeoutSeconds: 5, allowInsecure: true, maxBytes: 1000 });
    expect(res.ok).toBe(true);
    expect(res.body.length).toBeLessThanOrEqual(1000);
  });
});
