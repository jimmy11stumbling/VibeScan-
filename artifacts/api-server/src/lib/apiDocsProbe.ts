/**
 * API documentation exposure probe.
 *
 * Checks for publicly accessible Swagger UI, OpenAPI specs, and Redoc instances.
 * Exposed API docs enumerate all endpoints, request shapes, and auth schemes —
 * giving attackers a ready-made attack surface map without any guesswork.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 7_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(
  url: string,
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "Accept": "text/html,application/json,application/yaml,*/*" },
    });
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

// Swagger / OpenAPI UI paths
const SWAGGER_UI_PATHS = [
  "/swagger-ui",
  "/swagger-ui.html",
  "/swagger-ui/index.html",
  "/api-docs",
  "/api/docs",
  "/docs/api",
  "/swagger",
];

// Raw OpenAPI spec paths
const OPENAPI_SPEC_PATHS = [
  "/openapi.json",
  "/openapi.yaml",
  "/api-docs.json",
  "/v2/api-docs",
  "/v3/api-docs",
  "/api/openapi.json",
  "/api/swagger.json",
  "/swagger.json",
  "/swagger.yaml",
];

// Redoc UI paths
const REDOC_PATHS = [
  "/redoc",
  "/api/redoc",
  "/docs",
  "/api/docs",
];

function isSwaggerUi(body: string): boolean {
  return (
    body.includes("swagger-ui") ||
    body.includes("SwaggerUI") ||
    body.includes("Swagger UI") ||
    body.includes("swagger-ui-bundle") ||
    body.includes("openapi: ") ||
    body.includes('"openapi"')
  );
}

function isOpenApiSpec(body: string, contentType: string): boolean {
  if (contentType.includes("application/json") || contentType.includes("application/yaml") || contentType.includes("text/yaml")) {
    return (
      body.includes('"openapi"') ||
      body.includes('"swagger"') ||
      body.includes("openapi: ") ||
      body.includes("swagger: ")
    );
  }
  return false;
}

function isRedoc(body: string): boolean {
  return body.includes("redoc") && (body.includes("<redoc") || body.includes("ReDoc") || body.includes("redoc-container"));
}

/** Extract API path count from an OpenAPI spec for evidence. */
function countApiPaths(body: string): number {
  try {
    const json = JSON.parse(body) as { paths?: Record<string, unknown> };
    if (json.paths) return Object.keys(json.paths).length;
  } catch { /* noop */ }
  // YAML: count lines starting with "  /"
  const matches = body.match(/^\s{2}\/\S/gm);
  return matches?.length ?? 0;
}

export async function runApiDocsProbe(baseUrl: string): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];

  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  let foundSwagger = false;
  let foundOpenApiSpec = false;
  let foundRedoc = false;

  // Check Swagger UI
  for (const path of SWAGGER_UI_PATHS) {
    if (foundSwagger) break;
    const res = await safeGet(`${origin}${path}`);
    if (!res || res.status !== 200) continue;

    if (isSwaggerUi(res.body)) {
      foundSwagger = true;
      findings.push(vuln({
        name: "Swagger UI Publicly Accessible",
        severity: "medium",
        category: "Information Disclosure",
        description:
          "The Swagger UI (interactive API documentation) is accessible without authentication. " +
          "It documents every API endpoint, the exact request/response shape, authentication schemes, " +
          "and allows live API calls directly from the browser. " +
          "Attackers use this to enumerate endpoints and test access controls systematically.",
        evidence: `Swagger UI accessible at: ${origin}${path}`,
        url: `${origin}${path}`,
        solution:
          "Move API documentation behind authentication, or restrict access to internal/corporate networks only. " +
          "In Express: add auth middleware before the swagger route. " +
          "In production deployments, consider disabling swagger entirely via an environment variable check.",
        cweId: "CWE-200",
        cvssScore: 5.3,
        wstgId: "WSTG-CONF-05",
      }));
    }
  }

  // Check raw OpenAPI spec
  for (const path of OPENAPI_SPEC_PATHS) {
    if (foundOpenApiSpec) break;
    const res = await safeGet(`${origin}${path}`);
    if (!res || res.status !== 200) continue;

    const ct = res.headers["content-type"] ?? "";
    if (isOpenApiSpec(res.body, ct)) {
      foundOpenApiSpec = true;
      const pathCount = countApiPaths(res.body);
      findings.push(vuln({
        name: "OpenAPI Specification File Publicly Accessible",
        severity: "medium",
        category: "Information Disclosure",
        description:
          "A raw OpenAPI/Swagger JSON or YAML specification file is accessible without authentication. " +
          "This machine-readable format is used by automated tools to generate attack scripts, " +
          "fuzzing payloads, and full API client code — reducing the effort to attack your application to near zero.",
        evidence:
          `OpenAPI spec at \`${origin}${path}\` returned HTTP 200.` +
          (pathCount ? ` ${pathCount} API paths documented.` : ""),
        url: `${origin}${path}`,
        solution:
          "Serve the OpenAPI spec only from behind authentication, or remove the spec endpoint entirely in production. " +
          "If needed for CI/CD tooling, use a build-time step to generate specs rather than serving them at runtime.",
        cweId: "CWE-200",
        cvssScore: 5.3,
      }));
    }
  }

  // Check Redoc
  for (const path of REDOC_PATHS) {
    if (foundRedoc || foundSwagger) break;
    const res = await safeGet(`${origin}${path}`);
    if (!res || res.status !== 200) continue;

    if (isRedoc(res.body)) {
      foundRedoc = true;
      findings.push(vuln({
        name: "Redoc API Documentation Publicly Accessible",
        severity: "medium",
        category: "Information Disclosure",
        description:
          "A Redoc API documentation UI is publicly accessible. Like Swagger UI, Redoc renders " +
          "your full OpenAPI specification — exposing all endpoints, parameters, and auth flows " +
          "without requiring the attacker to do any discovery work.",
        evidence: `Redoc UI accessible at: ${origin}${path}`,
        url: `${origin}${path}`,
        solution:
          "Restrict the Redoc route behind authentication or remove it from production. " +
          "API documentation should only be accessible to authenticated developers.",
        cweId: "CWE-200",
        cvssScore: 5.3,
      }));
    }
  }

  return findings;
}
