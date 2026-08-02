/**
 * Cloud storage misconfiguration probe.
 *
 * Detects publicly accessible cloud storage buckets referenced in the scanned page:
 * - AWS S3 buckets (s3.amazonaws.com, s3-<region>.amazonaws.com)
 * - Google Cloud Storage buckets (storage.googleapis.com)
 * - Azure Blob Storage accounts (blob.core.windows.net)
 * - Cloudflare R2 (r2.dev public buckets)
 *
 * Only tests buckets actually referenced in the page HTML — no guessing.
 * Checks for public LIST access (the worst case — full inventory enumeration).
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 8_000;

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
      headers: { "Accept": "application/xml,application/json,*/*" },
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

interface StorageBucket {
  type: "s3" | "gcs" | "azure" | "r2";
  listUrl: string;
  bucketName: string;
  region?: string;
}

/** Extract all cloud storage bucket URLs from HTML and JS content. */
function extractBuckets(html: string): StorageBucket[] {
  const buckets: StorageBucket[] = [];
  const seen = new Set<string>();

  // S3: https://<bucket>.s3.amazonaws.com, https://s3.amazonaws.com/<bucket>,
  //     https://s3-<region>.amazonaws.com/<bucket>, https://<bucket>.s3.<region>.amazonaws.com
  const s3Patterns = [
    /https?:\/\/([a-z0-9][a-z0-9.-]{2,62})\.s3(?:[-.]([a-z0-9-]+))?\.amazonaws\.com/gi,
    /https?:\/\/s3(?:[-.]([a-z0-9-]+))?\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{2,62})/gi,
  ];

  for (const re of s3Patterns) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(html)) !== null) {
      const bucketName = (m[1] || m[2] || "").toLowerCase().replace(/\.s3.*/, "");
      const region = (m[2] || m[1] || "us-east-1").replace(/^s3-?/, "");
      if (!bucketName || seen.has(`s3:${bucketName}`)) continue;
      seen.add(`s3:${bucketName}`);

      // Build the canonical list URL
      const listUrl = region && region !== "us-east-1"
        ? `https://${bucketName}.s3.${region}.amazonaws.com/?list-type=2&max-keys=5`
        : `https://${bucketName}.s3.amazonaws.com/?list-type=2&max-keys=5`;

      buckets.push({ type: "s3", listUrl, bucketName, region });
    }
  }

  // GCS: https://storage.googleapis.com/<bucket> or https://<bucket>.storage.googleapis.com
  const gcsRe = /https?:\/\/(?:storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61})|([a-z0-9][a-z0-9._-]{1,61})\.storage\.googleapis\.com)/gi;
  let gm: RegExpExecArray | null;
  while ((gm = gcsRe.exec(html)) !== null) {
    const bucketName = (gm[1] || gm[2] || "").toLowerCase();
    if (!bucketName || seen.has(`gcs:${bucketName}`)) continue;
    seen.add(`gcs:${bucketName}`);
    buckets.push({
      type: "gcs",
      listUrl: `https://storage.googleapis.com/storage/v1/b/${bucketName}/o?maxResults=5`,
      bucketName,
    });
  }

  // Azure Blob: https://<account>.blob.core.windows.net/<container>
  const azureRe = /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9][a-z0-9-]{1,62})/gi;
  let am: RegExpExecArray | null;
  while ((am = azureRe.exec(html)) !== null) {
    const account = am[1]!.toLowerCase();
    const container = am[2]!.toLowerCase();
    const key = `azure:${account}/${container}`;
    if (seen.has(key)) continue;
    seen.add(key);
    buckets.push({
      type: "azure",
      listUrl: `https://${account}.blob.core.windows.net/${container}?restype=container&comp=list&maxresults=5`,
      bucketName: `${account}/${container}`,
    });
  }

  // Cloudflare R2 public buckets: https://<hash>.r2.dev
  const r2Re = /https?:\/\/([a-z0-9]{32})\.r2\.dev/gi;
  let r2m: RegExpExecArray | null;
  while ((r2m = r2Re.exec(html)) !== null) {
    const bucketId = r2m[1]!.toLowerCase();
    if (seen.has(`r2:${bucketId}`)) continue;
    seen.add(`r2:${bucketId}`);
    buckets.push({
      type: "r2",
      listUrl: `https://${bucketId}.r2.dev/`,
      bucketName: bucketId,
    });
  }

  return buckets.slice(0, 10); // Cap at 10 buckets per scan
}

function isPublicListResponse(body: string, type: StorageBucket["type"]): boolean {
  switch (type) {
    case "s3":
      return body.includes("<ListBucketResult") || body.includes("<Contents>");
    case "gcs":
      try {
        const json = JSON.parse(body) as { kind?: string; items?: unknown[] };
        return json.kind === "storage#objects";
      } catch { return false; }
    case "azure":
      return body.includes("<EnumerationResults") || body.includes("<Blobs>");
    case "r2":
      return body.includes("<ListBucketResult") || body.includes("<Key>");
    default:
      return false;
  }
}

const PROVIDER_NAMES: Record<StorageBucket["type"], string> = {
  s3: "AWS S3",
  gcs: "Google Cloud Storage",
  azure: "Azure Blob Storage",
  r2: "Cloudflare R2",
};

const FIX_BY_PROVIDER: Record<StorageBucket["type"], string> = {
  s3: "In the AWS S3 console, enable 'Block Public Access' settings on the bucket. Remove any bucket policy or ACL that grants `s3:ListBucket` or `s3:GetObject` to `Principal: *`.",
  gcs: "In Google Cloud Console, remove the `allUsers` and `allAuthenticatedUsers` principals from the bucket's IAM permissions. Use signed URLs for any content that needs to be publicly shared.",
  azure: "Set the container's public access level to 'Private' in Azure Portal. Remove any Shared Access Signatures (SAS) with public list permissions.",
  r2: "In Cloudflare R2 settings, disable the public development URL and use a custom domain with Worker-based auth instead.",
};

export async function runStorageProbe(
  _baseUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];
  const buckets = extractBuckets(html);
  if (buckets.length === 0) return [];

  const results = await Promise.allSettled(
    buckets.map(async (bucket) => {
      const res = await safeGet(bucket.listUrl);
      if (!res) return null;
      if (res.status !== 200) return null;
      if (!isPublicListResponse(res.body, bucket.type)) return null;
      return bucket;
    }),
  );

  const publicBuckets = results
    .filter((r): r is PromiseFulfilledResult<StorageBucket | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((b): b is StorageBucket => b !== null);

  for (const bucket of publicBuckets) {
    const provider = PROVIDER_NAMES[bucket.type];
    findings.push(vuln({
      name: `${provider} Bucket Publicly Listable`,
      severity: "high",
      category: "Sensitive Data Exposure",
      description:
        `A ${provider} bucket referenced in this application allows unauthenticated directory listing. ` +
        "An attacker can enumerate every file stored in the bucket and download any file not individually protected. " +
        "Public bucket listings frequently expose user uploads, database backups, internal documents, and build artifacts.",
      evidence: `Bucket \`${bucket.bucketName}\` returned a public file listing at: ${bucket.listUrl}`,
      url: bucket.listUrl,
      solution: FIX_BY_PROVIDER[bucket.type],
      cweId: "CWE-552",
      cvssScore: 7.5,
      wstgId: "WSTG-CONF-10",
    }));
  }

  return findings;
}
