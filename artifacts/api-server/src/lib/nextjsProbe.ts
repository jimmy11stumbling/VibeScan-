/**
 * Next.js-specific security probe.
 *
 * Checks for:
 * 1. Source map exposure via /_next/static chunks — leaks full application source.
 * 2. Build ID disclosure — fingerprints exact deployment version.
 * 3. Environment variable leakage via NEXT_PUBLIC_ prefix patterns in JS bundles.
 * 4. Debug/telemetry routes left enabled in production.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 8_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(
  url: string,
  options: RequestInit = {},
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal, redirect: "follow" });
    const body = await res.text().catch(() => "");
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Check if the page is a Next.js app. */
function isNextjsApp(html: string, rawHeaders: Record<string, string>): boolean {
  return (
    html.includes("/_next/") ||
    html.includes("__NEXT_DATA__") ||
    html.includes("next/dist") ||
    rawHeaders["x-powered-by"]?.toLowerCase().includes("next") === true
  );
}

/** Extract Next.js build manifest chunk URLs from HTML. */
function extractChunkUrls(html: string, origin: string): string[] {
  const urls: string[] = [];
  const re = /\/_next\/static\/chunks\/[^"'\s)]+\.js/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const path = m[0];
    if (!path.includes(".map")) {
      urls.push(`${origin}${path}`);
    }
  }
  return urls.slice(0, 5); // Only sample the first 5 chunks
}

/** Scan a JS chunk for exposed NEXT_PUBLIC_ env var values. */
function extractPublicEnvVars(body: string): string[] {
  const exposed: string[] = [];
  // Pattern: NEXT_PUBLIC_<NAME>:"<VALUE>" or similar
  const re = /NEXT_PUBLIC_([A-Z0-9_]+)['":\s]+['"`]([^'"`]{8,})/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const name = m[1]!;
    const value = m[2]!;
    // Skip obvious placeholders
    if (value === "undefined" || value === "null" || value === "false" || value === "true") continue;
    exposed.push(`NEXT_PUBLIC_${name}`);
  }
  return [...new Set(exposed)].slice(0, 10);
}

export async function runNextjsProbe(
  baseUrl: string,
  html: string,
  rawHeaders: Record<string, string> = {},
): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];

  // Only probe if this looks like a Next.js app
  if (!isNextjsApp(html, rawHeaders)) return [];

  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  // ── 1. BUILD ID EXPOSURE ──────────────────────────────────────────────────
  const buildIdRes = await safeGet(`${origin}/_next/BUILD_ID`);
  if (buildIdRes && buildIdRes.status === 200 && buildIdRes.body.trim().length > 0) {
    const buildId = buildIdRes.body.trim().slice(0, 64);
    findings.push(vuln({
      name: "Next.js Build ID Publicly Disclosed",
      severity: "info",
      category: "Information Disclosure",
      description:
        "The `/_next/BUILD_ID` endpoint is accessible and returns the exact build identifier. " +
        "Combined with source map exposure, this allows an attacker to precisely locate the correct " +
        "source map for every deployed JS chunk — mapping minified code back to your original source.",
      evidence: `/_next/BUILD_ID returned: ${buildId}`,
      url: `${origin}/_next/BUILD_ID`,
      solution:
        "Block `/_next/BUILD_ID` at the reverse proxy or CDN level. " +
        "In Vercel, this is already hidden. If self-hosting with nginx, add: `location = /_next/BUILD_ID { deny all; }`",
      cweId: "CWE-200",
      cvssScore: 3.1,
    }));
  }

  // ── 2. SOURCE MAP EXPOSURE ────────────────────────────────────────────────
  const chunkUrls = extractChunkUrls(html, origin);
  for (const chunkUrl of chunkUrls) {
    const mapUrl = `${chunkUrl}.map`;
    const mapRes = await safeGet(mapUrl);
    if (mapRes && mapRes.status === 200 &&
        (mapRes.headers["content-type"]?.includes("application/json") ||
         mapRes.body.startsWith('{"version":'))) {
      findings.push(vuln({
        name: "Next.js Source Maps Exposed in Production",
        severity: "high",
        category: "Information Disclosure",
        description:
          "JavaScript source map files (`.js.map`) are publicly accessible. " +
          "Source maps map minified/bundled production code back to the original TypeScript/JavaScript source, " +
          "including comments, variable names, business logic, and sometimes embedded secrets. " +
          "An attacker can reconstruct your entire application source code from the browser DevTools.",
        evidence: `Source map accessible at: ${mapUrl}`,
        url: mapUrl,
        solution:
          "In `next.config.js`, set `productionBrowserSourceMaps: false` (this is the default — check if you or a plugin enabled it). " +
          "Alternatively, block `.map` files at the CDN or nginx level: `location ~* \\.js\\.map$ { deny all; }`",
        cweId: "CWE-540",
        cvssScore: 7.5,
      }));
      break; // One is enough to prove the issue
    }
  }

  // ── 3. EXPOSED NEXT_PUBLIC_ ENV VARS IN BUNDLES ───────────────────────────
  // Only check if we have chunks to inspect
  const exposedEnvVars: string[] = [];
  for (const chunkUrl of chunkUrls.slice(0, 3)) {
    const chunkRes = await safeGet(chunkUrl);
    if (!chunkRes || chunkRes.status !== 200) continue;
    const vars = extractPublicEnvVars(chunkRes.body);
    exposedEnvVars.push(...vars);
  }

  const sensitiveEnvVarNames = exposedEnvVars.filter(
    (v) =>
      v.includes("KEY") ||
      v.includes("SECRET") ||
      v.includes("TOKEN") ||
      v.includes("PASSWORD") ||
      v.includes("AUTH") ||
      v.includes("API"),
  );

  if (sensitiveEnvVarNames.length > 0) {
    findings.push(vuln({
      name: "Sensitive NEXT_PUBLIC_ Environment Variables in Browser Bundle",
      severity: "medium",
      category: "Sensitive Data Exposure",
      description:
        "Environment variables with security-sensitive names (API keys, tokens, secrets) are prefixed with `NEXT_PUBLIC_` " +
        "and therefore embedded in the client-side JavaScript bundle, visible to any user. " +
        "While `NEXT_PUBLIC_` is intended for non-sensitive config, these variable names suggest they may hold credentials.",
      evidence: `Sensitive-looking public env vars found: ${sensitiveEnvVarNames.join(", ")}`,
      solution:
        "Move any credentials, API keys, or tokens to server-side only env vars (no `NEXT_PUBLIC_` prefix). " +
        "Server-side env vars are only available in `getServerSideProps`, `getStaticProps`, API routes, and Server Components — never in the browser bundle. " +
        "If these keys are intentionally public (e.g. Stripe publishable key), the names can be made less alarming.",
      cweId: "CWE-312",
      cvssScore: 5.5,
    }));
  }

  // ── 4. NEXT.JS DEBUG ENDPOINTS ────────────────────────────────────────────
  // /_next/webpack-hmr — Hot Module Replacement websocket should never be in prod
  const hmrRes = await safeGet(`${origin}/_next/webpack-hmr`);
  if (hmrRes && hmrRes.status === 200 && hmrRes.body.includes("webpack")) {
    findings.push(vuln({
      name: "Next.js HMR Dev Endpoint Exposed in Production",
      severity: "medium",
      category: "Misconfiguration",
      description:
        "The Next.js Hot Module Replacement (HMR) endpoint `/_next/webpack-hmr` is accessible. " +
        "This endpoint is only intended for local development and should never be reachable in production. " +
        "Its presence indicates the application may be running in development mode, which disables many security optimizations.",
      evidence: `/_next/webpack-hmr returned HTTP 200`,
      url: `${origin}/_next/webpack-hmr`,
      solution:
        "Ensure the application is started with `next start` (production mode) rather than `next dev`. " +
        "Set `NODE_ENV=production` in your deployment environment. " +
        "Block `/_next/webpack-hmr` at the reverse proxy level as a defence-in-depth measure.",
      cweId: "CWE-668",
      cvssScore: 5.0,
    }));
  }

  return findings;
}
