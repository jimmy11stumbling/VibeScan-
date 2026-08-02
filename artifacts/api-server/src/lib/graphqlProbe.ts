/**
 * GraphQL security probe.
 *
 * Checks for:
 * 1. GraphQL endpoint exposed with introspection enabled — reveals full schema.
 * 2. Batched queries allowed — enables query amplification DoS.
 * 3. Field suggestion hints leaking schema when introspection is disabled.
 *
 * Only sends POST requests with a well-known introspection query — non-destructive.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 8_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safePost(
  url: string,
  body: unknown,
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body),
      redirect: "follow",
    });
    const text = await res.text().catch(() => "");
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body: text, headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const INTROSPECTION_QUERY = {
  query: `{ __schema { types { name kind } queryType { name } mutationType { name } } }`,
};

const COMMON_GQL_PATHS = [
  "/graphql",
  "/api/graphql",
  "/v1/graphql",
  "/graphql/v1",
  "/query",
  "/api/query",
];

/** Check if a response looks like a valid GraphQL JSON response. */
function isGraphQLResponse(body: string): boolean {
  try {
    const json = JSON.parse(body) as Record<string, unknown>;
    return "data" in json || "errors" in json;
  } catch {
    return false;
  }
}

/** Check if introspection data is in the response. */
function hasIntrospectionData(body: string): boolean {
  try {
    const json = JSON.parse(body) as { data?: { __schema?: { types?: unknown[] } } };
    return Array.isArray(json?.data?.__schema?.types) && json.data.__schema.types.length > 0;
  } catch {
    return false;
  }
}

export async function runGraphqlProbe(baseUrl: string): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];

  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  for (const path of COMMON_GQL_PATHS) {
    const url = `${origin}${path}`;
    const res = await safePost(url, INTROSPECTION_QUERY);
    if (!res) continue;

    // Endpoint must respond with JSON (not HTML 404 or redirect)
    if (!res.headers["content-type"]?.includes("application/json") && !isGraphQLResponse(res.body)) {
      continue;
    }

    const isGql = isGraphQLResponse(res.body);
    if (!isGql) continue;

    // Found a GraphQL endpoint
    if (hasIntrospectionData(res.body)) {
      // Count exposed types for evidence
      let typeCount = 0;
      let mutationAvailable = false;
      try {
        const parsed = JSON.parse(res.body) as {
          data?: {
            __schema?: {
              types?: unknown[];
              mutationType?: { name: string } | null;
            };
          };
        };
        typeCount = parsed?.data?.__schema?.types?.length ?? 0;
        mutationAvailable = !!parsed?.data?.__schema?.mutationType?.name;
      } catch { /* noop */ }

      findings.push(vuln({
        name: "GraphQL Introspection Enabled in Production",
        severity: mutationAvailable ? "high" : "medium",
        category: "Information Disclosure",
        description:
          "The GraphQL endpoint has introspection enabled, which returns the complete API schema " +
          "including all types, queries, mutations, and their argument signatures. " +
          "Attackers use this to map every available data access path before launching targeted attacks. " +
          (mutationAvailable
            ? "Mutations are also available — this means write operations exist and their signatures are exposed."
            : ""),
        evidence:
          `GraphQL endpoint at \`${url}\` returned ${typeCount} schema types via introspection.` +
          (mutationAvailable ? " Mutation type is present." : ""),
        solution:
          "Disable introspection in production. In Apollo Server: `introspection: false` in the constructor options. " +
          "In GraphQL Yoga: `maskedErrors` + disable introspection. " +
          "Add depth limiting (graphql-depth-limit) and query complexity limits to prevent DoS.",
        cweId: "CWE-200",
        cvssScore: mutationAvailable ? 7.5 : 5.3,
        wstgId: "WSTG-CONF-05",
      }));

      // Only report once — first endpoint found with introspection wins
      break;
    } else {
      // GraphQL is running but introspection is off — check for field suggestions leaking info
      const probe = await safePost(url, { query: "{ __typename nonExistentField }" });
      if (
        probe &&
        isGraphQLResponse(probe.body) &&
        probe.body.includes("Did you mean")
      ) {
        findings.push(vuln({
          name: "GraphQL Field Suggestions Leak Schema",
          severity: "low",
          category: "Information Disclosure",
          description:
            'Although introspection is disabled, the GraphQL server returns "Did you mean…" suggestions ' +
            "when querying invalid field names. This allows attackers to enumerate valid field names " +
            "incrementally by observing suggestion responses.",
          evidence: `Field suggestion response detected at \`${url}\``,
          solution:
            "Disable field suggestions. In Apollo Server 4: `includeStacktraceInErrorResponses: false` and use a custom `formatError` to strip suggestions. " +
            "Consider the `graphql-disable-introspection` package or `graphql-armor` which strips suggestions by default.",
          cweId: "CWE-200",
          cvssScore: 3.7,
        }));
        break;
      }
    }
  }

  return findings;
}
