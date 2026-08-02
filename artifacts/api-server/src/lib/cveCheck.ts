/**
 * CVE / known-vulnerability checker.
 *
 * Extracts software version numbers from page HTML and HTTP headers,
 * then cross-references them against the OSV.dev vulnerability database
 * (https://osv.dev — free, no API key required).
 *
 * Covers: jQuery, Bootstrap, Lodash, Moment.js, Vue.js, Angular,
 * React (CDN-hosted), WordPress, Drupal, Joomla, plus PHP, Nginx,
 * Apache, IIS, OpenResty end-of-life / CVE detection from headers.
 *
 * Results are cached in-process per (package, version, ecosystem) to
 * avoid duplicate OSV.dev API calls within the same server lifetime.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { logger } from "./logger";
import {
  getLivePhpEol,
  getLiveNginxEolCycles,
  getLiveApacheEolCycles,
  getEolDataFetchedAt,
} from "./eolFetcher";

const OSV_TIMEOUT_MS = 8_000;
const OSV_ENDPOINT = "https://api.osv.dev/v1/query";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// IN-PROCESS CACHE — avoids duplicate OSV.dev calls for same version
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Size-bounded Map with LRU eviction.
 *
 * JS Maps preserve insertion order. On `get()` the accessed entry is moved
 * to the end (most-recently-used). On `set()` when the map is full, the
 * first entry (least-recently-used) is deleted before inserting the new key.
 *
 * This gives O(1) get, set, and eviction — no extra bookkeeping needed.
 */
class BoundedMap<K, V> {
  private readonly map = new Map<K, V>();

  constructor(private readonly maxSize: number) {}

  has(key: K): boolean {
    return this.map.has(key);
  }

  get(key: K): V | undefined {
    if (!this.map.has(key)) return undefined;
    // Move to end (most-recently-used) by deleting and re-inserting
    const value = this.map.get(key)!;
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) {
      // Update existing key — delete first so re-insertion moves it to end
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      // Evict the least-recently-used entry (first key in insertion order)
      const lruKey = this.map.keys().next().value as K;
      this.map.delete(lruKey);
    }
    this.map.set(key, value);
  }

  get size(): number {
    return this.map.size;
  }
}

/**
 * Maximum number of (package, version, ecosystem) entries to keep in memory.
 * Override via OSV_CACHE_MAX_SIZE env var. Falls back to 1000 if unset or invalid.
 * Exported so the worker can log the effective value at startup.
 */
export const OSV_CACHE_MAX_SIZE = (() => {
  const raw = process.env["OSV_CACHE_MAX_SIZE"];
  if (!raw) return 1_000;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 1_000;
})();

const osvCache = new BoundedMap<string, OsvVuln[]>(OSV_CACHE_MAX_SIZE);

function osvCacheKey(packageName: string, version: string, ecosystem: string): string {
  return `${ecosystem}:${packageName}@${version}`;
}

// ─────────────────────────────────────────────────────────────────────────────
import { type DetectedVersion, type VersionPattern, VERSION_PATTERNS, PHP_EOL, NGINX_VULN_RANGES, APACHE_VULN_RANGES, IIS_EOL_MAJOR } from "./cve-patterns";


export function extractVersionedTechnologies(
  html: string,
  headers: Record<string, string>,
): DetectedVersion[] {
  const found: DetectedVersion[] = [];
  const seen = new Set<string>(); // avoid duplicates for same package

  const content = html.slice(0, 150_000); // only scan first 150KB

  for (const vp of VERSION_PATTERNS) {
    if (seen.has(vp.packageName)) continue;
    for (const rx of vp.patterns) {
      const m = rx.exec(content);
      if (m?.[1]) {
        const version = m[1].replace(/^[vV]/, "");
        if (/^\d+\.\d+/.test(version)) {
          found.push({
            displayName: vp.displayName,
            techName: vp.techName ?? vp.displayName,
            packageName: vp.packageName,
            ecosystem: vp.ecosystem,
            version,
          });
          seen.add(vp.packageName);
          break;
        }
      }
    }
  }

  // ── Headers: extract versioned server/runtime software ────────────────────

  const serverHeader = Object.entries(headers).find(([k]) => k.toLowerCase() === "server")?.[1] ?? "";
  const poweredBy = Object.entries(headers).find(([k]) => k.toLowerCase() === "x-powered-by")?.[1] ?? "";

  // PHP version from X-Powered-By header (not in OSV, checked locally)
  const phpMatch = /PHP\/(\d+\.\d+\.?\d*)/i.exec(poweredBy);
  if (phpMatch?.[1] && !seen.has("php")) {
    found.push({
      displayName: "PHP",
      techName: "PHP",
      packageName: "php",
      ecosystem: "local",
      version: phpMatch[1],
    });
    seen.add("php");
  }

  // Nginx version from Server header
  const nginxMatch = /nginx\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (nginxMatch?.[1] && !seen.has("nginx")) {
    found.push({ displayName: "Nginx", techName: "Nginx", packageName: "nginx", ecosystem: "local", version: nginxMatch[1] });
    seen.add("nginx");
  }

  // Apache version from Server header — techName matches detectTechnologies() output "Apache"
  const apacheMatch = /Apache\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (apacheMatch?.[1] && !seen.has("apache")) {
    found.push({ displayName: "Apache HTTPD", techName: "Apache", packageName: "apache", ecosystem: "local", version: apacheMatch[1] });
    seen.add("apache");
  }

  // Microsoft IIS version from Server header — techName matches detectTechnologies() output "IIS"
  const iisMatch = /Microsoft-IIS\/(\d+\.\d+)/i.exec(serverHeader);
  if (iisMatch?.[1] && !seen.has("iis")) {
    found.push({ displayName: "Microsoft IIS", techName: "IIS", packageName: "iis", ecosystem: "local", version: iisMatch[1] });
    seen.add("iis");
  }

  // OpenResty version from Server header
  const openrestyMatch = /openresty\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (openrestyMatch?.[1] && !seen.has("openresty")) {
    found.push({ displayName: "OpenResty", techName: "OpenResty", packageName: "openresty", ecosystem: "local", version: openrestyMatch[1] });
    seen.add("openresty");
  }

  // LiteSpeed version from Server header
  const litespeedMatch = /LiteSpeed\/(\d+\.\d+\.?\d*)/i.exec(serverHeader);
  if (litespeedMatch?.[1] && !seen.has("litespeed")) {
    found.push({ displayName: "LiteSpeed", techName: "LiteSpeed", packageName: "litespeed", ecosystem: "local", version: litespeedMatch[1] });
    seen.add("litespeed");
  }

  return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// OSV.dev QUERY (with in-process cache)
// ─────────────────────────────────────────────────────────────────────────────

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{
    ranges?: Array<{ events?: Array<{ fixed?: string }> }>;
  }>;
}

async function queryOsv(packageName: string, version: string, ecosystem: string): Promise<OsvVuln[]> {
  const cacheKey = osvCacheKey(packageName, version, ecosystem);
  if (osvCache.has(cacheKey)) {
    return osvCache.get(cacheKey)!;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    const res = await fetch(OSV_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version,
        package: { name: packageName, ecosystem },
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Cache definitive non-2xx responses (e.g. 404 — package not found in OSV)
      osvCache.set(cacheKey, []);
      return [];
    }
    const json = (await res.json()) as { vulns?: OsvVuln[] };
    const vulns = json.vulns ?? [];
    // Only cache definitive successful responses — not transient errors
    osvCache.set(cacheKey, vulns);
    return vulns;
  } catch {
    // Network errors and timeouts are transient — do NOT cache so the next
    // scan can retry. Just return empty for this request.
    return [];
  } finally {
    clearTimeout(timer);
  }
}

function extractCvss(vuln: OsvVuln): number | null {
  for (const s of vuln.severity ?? []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V4") {
      // Parse CVSS score from vector string
      const match = /\/(\d+\.\d+)$/.exec(s.score) || s.score.match(/^(\d+\.\d+)$/);
      if (match) return parseFloat(match[1]);
    }
  }
  // Try database_specific severity
  const dbSev = vuln.database_specific?.severity;
  if (dbSev === "CRITICAL") return 9.0;
  if (dbSev === "HIGH") return 7.5;
  if (dbSev === "MODERATE" || dbSev === "MEDIUM") return 5.5;
  if (dbSev === "LOW") return 3.1;
  return null;
}

function cvssToSeverity(score: number | null): ScanVulnerability["severity"] {
  if (!score) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

function extractFixedVersion(osvVuln: OsvVuln): string | null {
  for (const affected of osvVuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function cveIds(osvVuln: OsvVuln): string[] {
  return (osvVuln.aliases ?? [osvVuln.id]).filter((id) => id.startsWith("CVE-")).slice(0, 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL CHECKS (no network call)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL DATA FRESHNESS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ISO date when the local vuln tables below (PHP_EOL, NGINX_VULN_RANGES,
 * APACHE_VULN_RANGES, IIS_EOL_MAJOR) were last reviewed and updated.
 * Update this whenever you add, modify, or verify the data below.
 */
const LOCAL_VULN_DATA_UPDATED = "2026-05-05";

const LOCAL_DATA_STALE_DAYS = 90;

/**
 * Logs a warning at startup when the bundled local CVE / EOL data is older
 * than LOCAL_DATA_STALE_DAYS days. Call this once from startWorker().
 *
 * The warning reminds developers that PHP_EOL, NGINX_VULN_RANGES,
 * APACHE_VULN_RANGES, and IIS_EOL_MAJOR may need refreshing against
 * current vendor advisories and EOL schedules.
 */
export function warnIfLocalDataStale(): void {
  // Prefer the live EOL refresh timestamp (updated by eolFetcher.ts after each
  // successful daily fetch) over the static bundled date.  At initial startup
  // the live timestamp is null and we fall back to the bundled date.
  const liveDate = getEolDataFetchedAt();
  const bundledDate = new Date(LOCAL_VULN_DATA_UPDATED);
  const effectiveDate = liveDate && liveDate > bundledDate ? liveDate : bundledDate;
  const source = liveDate && liveDate > bundledDate ? "live EOL refresh" : "bundled tables";
  const ageDays = Math.floor((Date.now() - effectiveDate.getTime()) / (1000 * 60 * 60 * 24));

  if (ageDays > LOCAL_DATA_STALE_DAYS) {
    logger.warn(
      {
        effectiveDate: effectiveDate.toISOString(),
        source,
        ageDays,
        staleThresholdDays: LOCAL_DATA_STALE_DAYS,
        action: liveDate
          ? "Check EOL refresh schedule — daily pg-boss job may be failing"
          : "Review and update LOCAL_VULN_DATA_UPDATED and the local vuln tables in cveCheck.ts",
      },
      `[cveCheck] CVE/EOL data is ${ageDays} days old (threshold: ${LOCAL_DATA_STALE_DAYS} days). ` +
      `Source: ${source}. IIS_EOL_MAJOR and NGINX_VULN_RANGES / APACHE_VULN_RANGES CVE entries ` +
      `still require manual review — check current vendor advisories.`,
    );
  } else {
    logger.debug(
      { effectiveDate: effectiveDate.toISOString(), source, ageDays },
      "[cveCheck] CVE/EOL data freshness OK",
    );
  }
}

// PHP EOL dates — versions that are fully end-of-life as of 2026

function semverLt(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na < nb) return true;
    if (na > nb) return false;
  }
  return false;
}

function checkLocalVulns(detected: DetectedVersion[]): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];

  for (const d of detected) {
    if (d.packageName === "php") {
      const major = d.version.split(".").slice(0, 1).join(".");
      const majorMinor = d.version.split(".").slice(0, 2).join(".");
      const phpEol = getLivePhpEol();
      const eolMsg = phpEol[majorMinor] || phpEol[major];
      if (eolMsg) {
        findings.push(vuln({
          name: `PHP ${d.version} is End-of-Life`,
          severity: "high",
          category: "Outdated Software",
          description: `PHP ${d.version} is detected in the X-Powered-By header. PHP ${d.version} is no longer receiving security patches. ${eolMsg}. Running end-of-life PHP means known vulnerabilities will never be fixed and your runtime has no security support.`,
          evidence: `X-Powered-By: PHP/${d.version}`,
          solution: `Upgrade to PHP 8.2 or PHP 8.3 (current supported releases). Plan migration carefully as major version upgrades may require code changes. See https://www.php.net/supported-versions.php`,
          cweId: "CWE-1104",
          cvssScore: 7.5,
        }));
      }
    }

    if (d.packageName === "nginx") {
      let nginxCveFlagged = false;
      for (const vuln_entry of NGINX_VULN_RANGES) {
        if (semverLt(d.version, vuln_entry.lt)) {
          findings.push(vuln({
            name: `Nginx ${d.version} — Known Vulnerability (${vuln_entry.cve})`,
            severity: cvssToSeverity(vuln_entry.cvss),
            category: "Outdated Software",
            description: `Nginx ${d.version} is vulnerable to ${vuln_entry.cve}: ${vuln_entry.desc}. Versions before ${vuln_entry.lt} are affected.`,
            evidence: `Server: nginx/${d.version}`,
            solution: `Upgrade Nginx to version ${vuln_entry.lt} or later. Use your package manager: apt upgrade nginx, or yum update nginx. Verify with: nginx -v`,
            cweId: "CWE-1104",
            cvssScore: vuln_entry.cvss,
          }));
          nginxCveFlagged = true;
          break; // report worst one only
        }
      }
      // Supplement: if no CVE-specific finding was raised, check live EOL cycle data.
      // This catches versions in EOL cycles not covered by the hardcoded CVE ranges
      // (e.g. Nginx 1.24.x — EOL but newer than any hardcoded CVE threshold).
      if (!nginxCveFlagged) {
        const nginxCycle = d.version.split(".").slice(0, 2).join(".");
        if (getLiveNginxEolCycles().has(nginxCycle)) {
          findings.push(vuln({
            name: `Nginx ${d.version} — End-of-Life Release Cycle`,
            severity: "medium",
            category: "Outdated Software",
            description:
              `Nginx ${d.version} belongs to the ${nginxCycle}.x release cycle, which has reached ` +
              `end-of-life and no longer receives security patches from the Nginx team. ` +
              `Running an unsupported Nginx version means future CVEs will not be fixed for your release.`,
            evidence: `Server: nginx/${d.version}`,
            solution:
              `Upgrade to the current Nginx stable release. ` +
              `On Debian/Ubuntu: apt upgrade nginx. On RHEL/CentOS: yum update nginx. ` +
              `See https://nginx.org/en/download.html for the latest stable version.`,
            cweId: "CWE-1104",
            cvssScore: 6.5,
          }));
        }
      }
    }

    if (d.packageName === "apache") {
      let apacheCveFlagged = false;
      for (const vuln_entry of APACHE_VULN_RANGES) {
        if (semverLt(d.version, vuln_entry.lt)) {
          findings.push(vuln({
            name: `Apache ${d.version} — Known Vulnerability (${vuln_entry.cve})`,
            severity: cvssToSeverity(vuln_entry.cvss),
            category: "Outdated Software",
            description: `Apache HTTPD ${d.version} is vulnerable to ${vuln_entry.cve}: ${vuln_entry.desc}. Upgrade to ${vuln_entry.lt} or later.`,
            evidence: `Server: Apache/${d.version}`,
            solution: `Upgrade Apache to the latest stable release. On Debian/Ubuntu: apt upgrade apache2. On RHEL/CentOS: yum update httpd. Confirm with: apache2 -v`,
            cweId: "CWE-1104",
            cvssScore: vuln_entry.cvss,
            wstgId: "WSTG-INFO-02",
          }));
          apacheCveFlagged = true;
          break;
        }
      }
      // Supplement: if no CVE-specific finding was raised, check live EOL cycle data.
      // This catches EOL Apache branches (e.g. 2.2.x) not covered by CVE thresholds.
      if (!apacheCveFlagged) {
        const apacheCycle = d.version.split(".").slice(0, 2).join(".");
        if (getLiveApacheEolCycles().has(apacheCycle)) {
          findings.push(vuln({
            name: `Apache HTTPD ${d.version} — End-of-Life Release Branch`,
            severity: "medium",
            category: "Outdated Software",
            description:
              `Apache HTTPD ${d.version} belongs to the ${apacheCycle}.x branch, which has reached ` +
              `end-of-life and no longer receives security patches from the Apache Software Foundation. ` +
              `Running an unsupported branch means future CVEs will not be addressed for your version.`,
            evidence: `Server: Apache/${d.version}`,
            solution:
              `Upgrade to the current Apache HTTPD stable release. ` +
              `On Debian/Ubuntu: apt upgrade apache2. On RHEL/CentOS: yum update httpd. ` +
              `See https://httpd.apache.org/download.cgi for the latest stable version.`,
            cweId: "CWE-1104",
            cvssScore: 6.5,
            wstgId: "WSTG-INFO-02",
          }));
        }
      }
    }

    if (d.packageName === "iis") {
      // Only flag IIS 6.x — CVE-2017-7269 is specific to IIS 6 WebDAV (Windows Server 2003)
      const majorVer = d.version.split(".")[0] ?? "";
      if (majorVer === IIS_EOL_MAJOR) {
        findings.push(vuln({
          name: `Microsoft IIS ${d.version} — CVE-2017-7269 (End-of-Life)`,
          severity: "critical",
          category: "Outdated Software",
          description: `Microsoft IIS ${d.version} is detected. IIS 6.0 (Windows Server 2003) has a critical buffer overflow vulnerability (CVE-2017-7269, CVSS 9.8) in the WebDAV service that allows remote code execution. IIS 6 reached end-of-life in July 2015 and receives no security updates.`,
          evidence: `Server: Microsoft-IIS/${d.version}`,
          solution: `Upgrade to IIS 10.0 (Windows Server 2022) or IIS 10.0 on Server 2019/2016. As an immediate mitigation, disable WebDAV in IIS if it is not required.`,
          cweId: "CWE-119",
          cvssScore: 9.8,
        }));
      }
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function checkForKnownVulnerabilities(
  html: string,
  headers: Record<string, string>,
): Promise<ScanVulnerability[]> {
  const detected = extractVersionedTechnologies(html, headers);
  if (detected.length === 0) return [];

  const findings: ScanVulnerability[] = [];

  // 1. Local checks (instant, no network)
  findings.push(...checkLocalVulns(detected));

  // 2. OSV.dev queries for npm + CMS packages (parallel, cached per version)
  const osvTargets = detected.filter((d) => d.ecosystem !== "local");

  const osvResults = await Promise.allSettled(
    osvTargets.map((d) => queryOsv(d.packageName, d.version, d.ecosystem)),
  );

  for (let i = 0; i < osvTargets.length; i++) {
    const target = osvTargets[i];
    const result = osvResults[i];
    if (result?.status !== "fulfilled") continue;

    const vulns = result.value;
    if (vulns.length === 0) continue;

    // Sort by CVSS score descending, take worst 2
    const sorted = vulns
      .map((v) => ({ v, score: extractCvss(v) ?? 0 }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 2);

    for (const { v: osvVuln, score } of sorted) {
      const cves = cveIds(osvVuln);
      const fixedVersion = extractFixedVersion(osvVuln);
      const cveList = cves.length > 0 ? cves.join(", ") : osvVuln.id;

      findings.push(vuln({
        name: `${target.displayName} ${target.version} — Known Vulnerability (${cveList})`,
        severity: cvssToSeverity(score),
        category: "Outdated Software / Known CVE",
        description:
          `${target.displayName} version ${target.version} has a known vulnerability: ` +
          `${osvVuln.summary ?? "See CVE details."}` +
          (score > 0 ? ` CVSS score: ${score}.` : ""),
        evidence:
          `Detected: ${target.displayName} ${target.version}\n` +
          `CVE(s): ${cveList}\n` +
          (fixedVersion ? `Fixed in: ${fixedVersion}\n` : "") +
          (osvVuln.details ? `Details: ${osvVuln.details.slice(0, 300)}` : ""),
        solution:
          fixedVersion
            ? `Upgrade ${target.displayName} to version ${fixedVersion} or later. ` +
              `Update CDN reference URLs or your package.json dependency.`
            : `Upgrade ${target.displayName} to the latest stable version. ` +
              `Check ${target.ecosystem === "npm" ? "https://www.npmjs.com/package/" + target.packageName : "the vendor advisory"} for patched releases.`,
        cweId: "CWE-1104",
        cvssScore: score > 0 ? score : null,
        wstgId: "WSTG-INFO-09",
        cveId: cves[0] ?? null,
      }));
    }
  }

  return findings;
}
