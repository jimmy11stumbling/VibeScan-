/**
 * BaaS open-data probes for PocketBase and Appwrite.
 *
 * Supabase and Firebase are handled by vibeStackProbes.ts (deeper coverage).
 * This module covers the other two common vibe-coding BaaS platforms.
 *
 * PocketBase — self-hosted Go backend popular with Lovable/Bolt/v0 projects.
 *   Checks: admin UI exposure, unauthenticated collections list, public rules.
 *
 * Appwrite — self-hosted BaaS with React SDK support.
 *   Checks: console exposure, unauthenticated project enumeration.
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

// ─────────────────────────────────────────────────────────────────────────────
// POCKETBASE DETECTION & PROBES
// ─────────────────────────────────────────────────────────────────────────────

/** Extract PocketBase base URL from HTML (env vars, SDK init calls, etc.) */
function detectPocketBase(html: string, baseUrl: string): string[] {
  const candidates: string[] = [];

  // Direct PocketBase URL patterns in JS
  const patterns = [
    /new\s+PocketBase\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /POCKETBASE_URL['":\s=]+['"`]([^'"`]+)['"`]/g,
    /PB_URL['":\s=]+['"`]([^'"`]+)['"`]/gi,
    /pocketbase\.url['":\s=]+['"`]([^'"`]+)['"`]/gi,
  ];

  for (const re of patterns) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(html)) !== null) {
      const u = m[1]?.trim();
      if (u && (u.startsWith("http://") || u.startsWith("https://"))) {
        candidates.push(u.replace(/\/$/, ""));
      }
    }
  }

  // Heuristic: same origin may be running PocketBase
  try {
    const origin = new URL(baseUrl).origin;
    candidates.push(origin);
  } catch { /* noop */ }

  // Deduplicate
  return [...new Set(candidates)];
}

async function runPocketBaseProbes(
  html: string,
  baseUrl: string,
): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];
  const candidates = detectPocketBase(html, baseUrl);

  for (const pbUrl of candidates) {
    // 1. Admin UI exposure — /_/ is PocketBase's built-in admin dashboard
    const adminUi = await safeGet(`${pbUrl}/_/`);
    if (adminUi && adminUi.status === 200 &&
        (adminUi.body.includes("PocketBase") || adminUi.body.includes("pb_admin"))) {
      findings.push(vuln({
        name: "PocketBase Admin UI Exposed",
        severity: "high",
        category: "Access Control",
        description:
          "The PocketBase admin dashboard is publicly accessible at `/_/`. " +
          "An attacker can attempt to brute-force the admin password or exploit any auth bypass vulnerability. " +
          "The admin UI grants full database access, file manager, and collection schema editing.",
        evidence: `Admin UI accessible at: ${pbUrl}/_/`,
        solution:
          "Restrict access to `/_/` using a reverse-proxy IP allowlist (nginx: `allow` / `deny` directives, or Caddy's `remote_ip` matcher). " +
          "Alternatively, set a strong random admin password (32+ characters) and consider disabling the UI in production via the `--dev` flag absence.",
        cweId: "CWE-306",
        cvssScore: 7.5,
      }));
    }

    // 2. Unauthenticated collections list — /api/collections
    const colList = await safeGet(`${pbUrl}/api/collections`, {
      headers: { "Accept": "application/json" },
    });
    if (
      colList &&
      colList.status === 200 &&
      colList.headers["content-type"]?.includes("application/json") &&
      colList.body.includes('"items"')
    ) {
      let collectionNames = "";
      try {
        const parsed = JSON.parse(colList.body) as { items?: Array<{ name?: string }> };
        const names = (parsed.items ?? []).map((c) => c.name).filter(Boolean).slice(0, 5);
        if (names.length) collectionNames = ` Collections found: ${names.join(", ")}.`;
      } catch { /* noop */ }

      findings.push(vuln({
        name: "PocketBase Collections Enumerable Without Auth",
        severity: "medium",
        category: "Information Disclosure",
        description:
          "The `/api/collections` endpoint returns the full collection schema without authentication. " +
          "This exposes your database structure — table names, field types, and index definitions — " +
          "which an attacker uses to craft targeted injection or enumeration attacks.",
        evidence: `${pbUrl}/api/collections returned HTTP 200 with collection data.${collectionNames}`,
        solution:
          "In PocketBase settings → Collections → (each collection) → API Rules, set a non-empty rule for `listRule`. " +
          "The default empty string means 'allow all'. Use `@request.auth.id != ''` to require authentication.",
        cweId: "CWE-200",
        cvssScore: 5.3,
      }));
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// APPWRITE DETECTION & PROBES
// ─────────────────────────────────────────────────────────────────────────────

function detectAppwrite(html: string, baseUrl: string): string[] {
  const candidates: string[] = [];

  const patterns = [
    /new\s+Client\s*\(\s*\)[^;]*\.setEndpoint\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /APPWRITE_ENDPOINT['":\s=]+['"`]([^'"`]+)['"`]/gi,
    /VITE_APPWRITE_URL['":\s=]+['"`]([^'"`]+)['"`]/gi,
    /appwrite['":\s]+{[^}]*endpoint['":\s=]+['"`]([^'"`]+)['"`]/gi,
  ];

  for (const re of patterns) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(html)) !== null) {
      const u = m[1]?.trim().replace(/\/$/, "");
      if (u && (u.startsWith("http://") || u.startsWith("https://"))) {
        candidates.push(u);
      }
    }
  }

  // Check if this site itself might be Appwrite (self-hosted)
  if (html.includes("appwrite") || html.includes("Appwrite")) {
    try {
      const origin = new URL(baseUrl).origin;
      candidates.push(origin);
    } catch { /* noop */ }
  }

  return [...new Set(candidates)];
}

async function runAppwriteProbes(
  html: string,
  baseUrl: string,
): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];
  const candidates = detectAppwrite(html, baseUrl);

  for (const awUrl of candidates) {
    // Appwrite console exposure at /console
    const console_ = await safeGet(`${awUrl}/console`);
    if (console_ && console_.status === 200 &&
        (console_.body.includes("Appwrite") || console_.body.includes("appwrite-console"))) {
      findings.push(vuln({
        name: "Appwrite Console Publicly Accessible",
        severity: "high",
        category: "Access Control",
        description:
          "The Appwrite management console is reachable from the public internet. " +
          "While it requires credentials to log in, exposing the console increases the attack surface " +
          "for credential brute-forcing and any future authentication CVEs.",
        evidence: `Appwrite console accessible at: ${awUrl}/console`,
        solution:
          "Restrict the console path using a reverse proxy or Appwrite's built-in `_APP_CONSOLE_WHITELIST_IPS` environment variable. " +
          "Set `_APP_CONSOLE_WHITELIST_ROOT=enabled` to limit console access to the root account only during initial setup.",
        cweId: "CWE-306",
        cvssScore: 5.8,
      }));
    }

    // Appwrite health endpoint — reveals version info
    const health = await safeGet(`${awUrl}/v1/health`, {
      headers: { "Accept": "application/json" },
    });
    if (health && health.status === 200 &&
        health.headers["content-type"]?.includes("application/json") &&
        (health.body.includes('"status"') || health.body.includes('"ping"'))) {
      findings.push(vuln({
        name: "Appwrite Health Endpoint Exposed",
        severity: "low",
        category: "Information Disclosure",
        description:
          "The Appwrite `/v1/health` endpoint is publicly accessible. " +
          "It reveals the Appwrite version, queue status, and storage health — " +
          "information useful for fingerprinting the exact version and targeting known CVEs.",
        evidence: `${awUrl}/v1/health returned HTTP 200 with health data`,
        solution:
          "Add an `_APP_CONSOLE_WHITELIST_IPS` restriction or use a reverse proxy to block `/v1/health` for external traffic.",
        cweId: "CWE-200",
        cvssScore: 3.7,
      }));
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function runBaasProbes(
  baseUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  const [pbFindings, awFindings] = await Promise.allSettled([
    runPocketBaseProbes(html, baseUrl),
    runAppwriteProbes(html, baseUrl),
  ]);

  return [
    ...(pbFindings.status === "fulfilled" ? pbFindings.value : []),
    ...(awFindings.status === "fulfilled" ? awFindings.value : []),
  ];
}
