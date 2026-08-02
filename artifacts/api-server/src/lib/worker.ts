/**
 * pg-boss worker — processes scan jobs from the queue.
 * Registered at startup by index.ts.
 *
 * Job lifecycle per scan:
 *   queued → scanning → analyzing → complete
 *              ↓ (on error)
 *            failed
 */

import { db, scansTable, reportsTable, monitorSubscriptionsTable, dismissedFindingsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { getBoss, SCAN_QUEUE, type ScanJobData } from "./queue";
import { runScan, computeRiskScore, computeGrade, type ScanVulnerability } from "./scanner";
import { corroborateMerge } from "./scoring";
import { findingFingerprint, normalizeEvidenceKey, canonicalizeTargetUrl } from "./fingerprint";
import { runRecon } from "./recon";
import { warnIfLocalDataStale, OSV_CACHE_MAX_SIZE } from "./cveCheck";
import { refreshEolData, loadEolCacheFromDb, EOL_REFRESH_QUEUE } from "./eolFetcher";
import { callDeepSeek } from "./deepseek";
import { checkSslLabs } from "./ssllabs";
import { sendReportReadyEmail } from "./mailer";
import { logger } from "./logger";
import { randomUUID } from "node:crypto";
import type { Job } from "pg-boss";

type ScanJob = Job<ScanJobData>;

// ─── Differential re-probe ────────────────────────────────────────────────────

import { reprobe } from "./reprobe";

/**
 * For borderline findings (50 ≤ confidence < 70), makes a second HTTP request
 * to the target URL and re-verifies header-based conditions.
 * Confirmed findings get +10 confidence; contradicted ones get -20.
 */


/**
 * Validates DNS-based security findings against live TXT record data from
 * a DNS-over-HTTPS probe. Returns true if the finding is confirmed (issue
 * still present), false if disconfirmed, or null if undecidable.
 */


async function processScanJob(job: ScanJob): Promise<void> {
  const { scanId, userId, targetUrl, tier, monitorSubscriptionId } = job.data;
  const log = logger.child({ scanId, targetUrl, tier, monitorSubscriptionId });

  log.info("Scan job started");

  // ── 1. Mark as scanning + initialise per-probe step list ─────────────
  type ScanStep = {
    key: string; label: string;
    status: "pending" | "running" | "done" | "error";
    findings?: number; startedAt?: string; doneAt?: string;
  };

  const BASIC_STEPS: ScanStep[] = [
    { key: "ssl",        label: "TLS / SSL Assessment",           status: "pending" },
    { key: "recon",      label: "Reconnaissance",                  status: "pending" },
    { key: "crawl",      label: "Site Crawl & Link Analysis",      status: "pending" },
    { key: "headers",    label: "Security Headers",                status: "pending" },
    { key: "dns",        label: "DNS Security",                    status: "pending" },
    { key: "cve",        label: "Known Vulnerability Matching",    status: "pending" },
    { key: "jwt",        label: "JWT Token Analysis",              status: "pending" },
    { key: "takeover",   label: "Subdomain Takeover",              status: "pending" },
    { key: "sourcemaps", label: "Source Map Exposure",             status: "pending" },
    { key: "vibestack",  label: "Supabase / Firebase Security",    status: "pending" },
    { key: "baas",       label: "BaaS Open Data",                  status: "pending" },
    { key: "graphql",    label: "GraphQL Introspection",           status: "pending" },
    { key: "apidocs",    label: "API Documentation Exposure",      status: "pending" },
    { key: "nextjs",     label: "Next.js Configuration",           status: "pending" },
    { key: "storage",    label: "Cloud Storage Buckets",           status: "pending" },
  ];
  const DEEP_STEPS: ScanStep[] = [
    { key: "jssecrets",  label: "JavaScript Secret Scanning",      status: "pending" },
    { key: "traversal",  label: "Path Traversal Probing",          status: "pending" },
  ];

  const allSteps: ScanStep[] = [...BASIC_STEPS, ...(tier === "deep" ? DEEP_STEPS : [])];
  const stepsMap = new Map<string, ScanStep>(allSteps.map((s) => [s.key, { ...s }]));

  await db
    .update(scansTable)
    .set({ status: "scanning", startedAt: new Date(), steps: allSteps })
    .where(eq(scansTable.id, scanId));

  /** Called by scanner probes and by ssl/recon wrappers below */
  const onStep = (key: string, status: "running" | "done" | "error", findings?: number): void => {
    const step = stepsMap.get(key);
    if (!step) return;
    step.status = status;
    if (status === "running") step.startedAt = new Date().toISOString();
    else { step.doneAt = new Date().toISOString(); if (findings !== undefined) step.findings = findings; }
    db.update(scansTable)
      .set({ steps: Array.from(stepsMap.values()) })
      .where(eq(scansTable.id, scanId))
      .catch(() => {});
  };

  // ── 2. Run header scan + SSL Labs check in parallel ───────────────────
  log.info("Starting HTTP scan, SSL Labs check, and reconnaissance in parallel");

  // SSL Labs is best-effort and can take up to 120 seconds — start it early
  onStep("ssl", "running");
  const sslLabsPromise = checkSslLabs(targetUrl)
    .then((r) => { onStep("ssl", r ? "done" : "error"); return r; })
    .catch((err) => {
      onStep("ssl", "error");
      log.warn({ err }, "SSL Labs check failed (non-fatal)");
      return null;
    });

  // Recon runs concurrently: DNS enumeration, subdomain brute-force, port scan
  onStep("recon", "running");
  const reconPromise = runRecon(targetUrl)
    .then((r) => { onStep("recon", r ? "done" : "error"); return r; })
    .catch((err) => {
      onStep("recon", "error");
      log.warn({ err }, "Recon failed (non-fatal)");
      return null;
    });

  // Hard deadline for the entire HTTP scan phase.
  // Individual probes have per-request timeouts (5–10 s each) but the aggregate
  // across all deep-scan probes can still hang indefinitely on complex targets.
  // 3 minutes is generous for any legitimate target; it prevents zombie jobs.
  const SCAN_HTTP_TIMEOUT_MS = 3 * 60 * 1_000;

  let scanResult;
  try {
    const scanTimeout = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`HTTP scan timed out after ${SCAN_HTTP_TIMEOUT_MS / 1000}s`)),
        SCAN_HTTP_TIMEOUT_MS,
      ),
    );
    scanResult = await Promise.race([runScan(targetUrl, tier, onStep), scanTimeout]);
    log.info(
      { vulnCount: scanResult.vulnerabilities.length, durationMs: scanResult.requestDurationMs },
      "HTTP scan complete",
    );
  } catch (scanErr) {
    const errMsg = scanErr instanceof Error ? scanErr.message : String(scanErr);
    log.error({ err: scanErr }, "Scan failed during HTTP fetch");
    await db
      .update(scansTable)
      .set({ status: "failed", error: errMsg, completedAt: new Date() })
      .where(eq(scansTable.id, scanId));
    return;
  }

  // Wait for SSL Labs (it was started in parallel with the header scan)
  log.info("Waiting for SSL Labs assessment to complete");
  const sslLabsResult = await sslLabsPromise;
  if (sslLabsResult) {
    log.info({ grade: sslLabsResult.grade, issues: sslLabsResult.issues.length }, "SSL Labs assessment complete");
    // Override the basic TLS grade with the real SSL Labs grade
    scanResult.tlsGrade = sslLabsResult.grade;

    // Add SSL Labs findings as vulnerabilities
    if (sslLabsResult.grade && /^[C-F]$/.test(sslLabsResult.grade)) {
      scanResult.vulnerabilities.push({
        id: randomUUID(),
        name: `Weak TLS Configuration (SSL Labs Grade: ${sslLabsResult.grade})`,
        severity: sslLabsResult.grade === "F" ? "critical" : sslLabsResult.grade === "D" ? "high" : "medium",
        category: "Transport Security",
        description: `SSL Labs graded your TLS configuration as ${sslLabsResult.grade}. This indicates weak cipher suites, outdated protocol support, or certificate issues that could expose users to downgrade attacks.`,
        evidence: sslLabsResult.issues.join("; ") || null,
        solution: "Use a modern TLS configuration: TLS 1.2 minimum, TLS 1.3 preferred, disable RC4/3DES/CBC-mode cipher suites, and enable HSTS. Use Mozilla's SSL Configuration Generator for server-specific settings.",
        cweId: "CWE-326",
        cvssScore: sslLabsResult.grade === "F" ? 9.1 : sslLabsResult.grade === "D" ? 7.5 : 5.3,
      } satisfies ScanVulnerability);
    }
  } else {
    log.warn("SSL Labs assessment not available — using basic TLS detection");
  }

  // ── 2b. Merge reconnaissance results ─────────────────────────────────
  log.info("Waiting for reconnaissance to complete");
  const reconRunResult = await reconPromise;
  if (reconRunResult) {
    // Dangerous-port findings surface as first-class vulnerabilities
    scanResult.vulnerabilities.push(...reconRunResult.vulns);
    log.info(
      {
        portVulns: reconRunResult.vulns.length,
        openPorts: reconRunResult.recon.openPorts.length,
        subdomains: reconRunResult.recon.subdomains.length,
        dnsRecords: reconRunResult.recon.dnsRecords.length,
      },
      "Recon complete — merged into scan result",
    );
  } else {
    log.warn("Recon results unavailable — continuing without reconnaissance data");
  }

  // ── 2c. Corroboration merge — deduplicate duplicate-root-cause findings ──
  const preCorrobCount = scanResult.vulnerabilities.length;
  scanResult.vulnerabilities = corroborateMerge(scanResult.vulnerabilities);
  log.info(
    { before: preCorrobCount, after: scanResult.vulnerabilities.length },
    "Corroboration merge complete",
  );

  // ── 2d. Differential re-probe — re-verify borderline findings ────────
  scanResult.vulnerabilities = await reprobe(targetUrl, scanResult.vulnerabilities, log);

  // ── 2e. Filter previously dismissed false positives ───────────────────
  // Use the same canonicalized URL as the dismissals route so DB keys always match.
  // canonicalizeTargetUrl: lowercase scheme+host, strip trailing slash on non-root paths.
  const canonicalUrl = canonicalizeTargetUrl(scanResult.finalUrl ?? targetUrl);
  const dismissals = await db
    .select({ fingerprint: dismissedFindingsTable.findingFingerprint })
    .from(dismissedFindingsTable)
    .where(
      and(
        eq(dismissedFindingsTable.userId, userId),
        eq(dismissedFindingsTable.targetUrl, canonicalUrl),
      ),
    );

  let autoSuppressedCount = 0;
  if (dismissals.length > 0) {
    const dismissedFps = new Set(dismissals.map((d) => d.fingerprint));
    const beforeDismiss = scanResult.vulnerabilities.length;
    scanResult.vulnerabilities = scanResult.vulnerabilities.filter(
      (v) => !dismissedFps.has(findingFingerprint(v.category, v.name, normalizeEvidenceKey(v.evidence))),
    );
    autoSuppressedCount = beforeDismiss - scanResult.vulnerabilities.length;
    if (autoSuppressedCount > 0) {
      log.info({ autoSuppressedCount }, "Auto-suppressed previously dismissed findings");
    }
  }

  // ── 3. Mark as analyzing (AI phase) ──────────────────────────────────
  await db
    .update(scansTable)
    .set({ status: "analyzing" })
    .where(eq(scansTable.id, scanId));

  // ── 4. AI analysis (deep tier only) ──────────────────────────────────
  // Note: pack_5/pack_20 are credit-purchase tiers — scan records are always
  // created with "basic" or "deep", so only "deep" needs to be checked here.
  let aiAnalysis = null;
  if (tier === "deep") {
    log.info("Calling DeepSeek AI analysis");
    // Confidence gate: only pass high-confidence findings to the AI to reduce noise
    const AI_CONFIDENCE_GATE = 65;
    const vulnsForAi = scanResult.vulnerabilities.filter(
      (v) => (v.confidence ?? 100) >= AI_CONFIDENCE_GATE,
    );
    log.info(
      { total: scanResult.vulnerabilities.length, gated: vulnsForAi.length },
      "Confidence-gated findings passed to AI",
    );
    aiAnalysis = await callDeepSeek(
      targetUrl,
      vulnsForAi,
      scanResult.technologies,
      tier,
    );
    if (aiAnalysis) {
      log.info("DeepSeek analysis complete");
    } else {
      log.warn("DeepSeek analysis skipped or failed — continuing without AI");
    }
  }

  // ── 5. Build report data ──────────────────────────────────────────────
  const riskScore = computeRiskScore(scanResult.vulnerabilities);
  const grade = computeGrade(riskScore);

  const severityCounts = scanResult.vulnerabilities.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const executiveSummary = buildExecutiveSummary(
    grade,
    riskScore,
    targetUrl,
    scanResult.vulnerabilities.length,
    severityCounts,
  );

  const reportData = {
    targetUrl: scanResult.finalUrl || targetUrl,
    vulnerabilities: scanResult.vulnerabilities,
    technologies: scanResult.technologies,
    server: scanResult.server,
    tlsGrade: scanResult.tlsGrade,
    pagesScanned: scanResult.pagesScanned,
    probedNotFound: scanResult.probedNotFound,
    summary: {
      totalVulnerabilities: scanResult.vulnerabilities.length,
      critical: severityCounts["critical"] ?? 0,
      high: severityCounts["high"] ?? 0,
      medium: severityCounts["medium"] ?? 0,
      low: severityCounts["low"] ?? 0,
      info: severityCounts["info"] ?? 0,
      riskScore,
      grade,
      executiveSummary,
    },
    recon: reconRunResult?.recon ?? undefined,
    aiAnalysis: aiAnalysis ?? undefined,
    autoSuppressedCount: autoSuppressedCount > 0 ? autoSuppressedCount : undefined,
  };

  // ── 6. Persist report ─────────────────────────────────────────────────
  const completedAt = new Date();

  try {
    const [report] = await db
      .insert(reportsTable)
      .values({
        scanId,
        userId,
        targetUrl: scanResult.finalUrl || targetUrl,
        tier: tier as "basic" | "deep" | "pack_5" | "pack_20",
        duration: scanResult.requestDurationMs,
        data: reportData,
      })
      .returning();

    log.info({ reportId: report.id }, "Report saved to database");

    // ── 7. Mark scan complete ─────────────────────────────────────────
    await db
      .update(scansTable)
      .set({ status: "complete", completedAt })
      .where(eq(scansTable.id, scanId));

    log.info({ reportId: report.id, grade, riskScore }, "Scan complete");

    // ── 8. Update monitor subscription if this was a monitored scan ───
    if (monitorSubscriptionId) {
      try {
        // Adaptive cadence: if new high/critical findings, rescan in 3 days;
        // otherwise use the standard 7-day interval.
        const hasNewHighFindings = scanResult.vulnerabilities.some(
          (v) => v.severity === "critical" || v.severity === "high",
        );
        const cadenceDays = hasNewHighFindings ? 3 : 7;
        const nextScanAt = new Date(completedAt.getTime() + cadenceDays * 24 * 60 * 60 * 1000);

        const [updatedSub] = await db
          .update(monitorSubscriptionsTable)
          .set({
            lastScanAt: completedAt,
            lastReportId: report.id,
            nextScanAt,
          })
          .where(
            and(
              eq(monitorSubscriptionsTable.id, monitorSubscriptionId),
              eq(monitorSubscriptionsTable.userId, userId),
            ),
          )
          .returning();

        log.info(
          { monitorSubscriptionId, reportId: report.id, cadenceDays, nextScanAt },
          "Monitor subscription updated with adaptive cadence",
        );

        // Fire webhook if configured
        if (updatedSub?.webhookUrl) {
          const webhookPayload = {
            event: "scan_complete",
            subscriptionId: monitorSubscriptionId,
            targetUrl,
            reportId: report.id,
            grade,
            riskScore,
            vulnerabilityCount: scanResult.vulnerabilities.length,
            highCriticalCount: scanResult.vulnerabilities.filter(
              (v) => v.severity === "critical" || v.severity === "high",
            ).length,
            scannedAt: completedAt.toISOString(),
            nextScanAt: nextScanAt.toISOString(),
            reportUrl: `${process.env.APP_ORIGIN ?? "https://vibescan.app"}/report/${report.id}`,
          };
          fetch(updatedSub.webhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": "VibeScan-Webhook/1.0" },
            body: JSON.stringify(webhookPayload),
            signal: AbortSignal.timeout(10_000),
          }).catch((err) => log.warn({ err, webhookUrl: updatedSub.webhookUrl }, "Webhook delivery failed (non-fatal)"));
        }
      } catch (monitorErr) {
        log.warn({ err: monitorErr }, "Failed to update monitor subscription (non-fatal)");
      }
    }

    // ── 9. Send report-ready email ────────────────────────────────────
    // Deep scans and monitor-triggered scans always send email.
    if (tier === "deep") {
      const [scan] = await db
        .select({ userEmail: scansTable.userEmail })
        .from(scansTable)
        .where(eq(scansTable.id, scanId));

      if (scan?.userEmail) {
        const appOrigin = process.env.APP_ORIGIN ?? "https://vibescan.app";
        await sendReportReadyEmail({
          toEmail: scan.userEmail,
          targetUrl: scanResult.finalUrl || targetUrl,
          grade,
          riskScore,
          totalVulns: scanResult.vulnerabilities.length,
          reportUrl: `${appOrigin}/report/${report.id}`,
          tier,
        });
      }
    }
  } catch (dbErr) {
    log.error({ err: dbErr }, "Failed to save report to database");
    await db
      .update(scansTable)
      .set({
        status: "failed",
        error: "Failed to save report — please contact support",
        completedAt,
      })
      .where(eq(scansTable.id, scanId));
  }
}

function buildExecutiveSummary(
  grade: string,
  riskScore: number,
  targetUrl: string,
  totalVulns: number,
  counts: Record<string, number>,
): string {
  const domain = (() => {
    try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
  })();

  const critical = counts["critical"] ?? 0;
  const high = counts["high"] ?? 0;

  if (totalVulns === 0) {
    return `${domain} passed all security checks with a grade of ${grade}. No significant vulnerabilities were detected during this scan. Continue following security best practices and re-scan regularly.`;
  }

  const urgencyPhrase =
    critical > 0
      ? `${critical} critical issue${critical > 1 ? "s" : ""} requiring immediate attention`
      : high > 0
        ? `${high} high-severity issue${high > 1 ? "s" : ""} that should be addressed promptly`
        : `${totalVulns} security findings, none of which are immediately critical`;

  return `Security scan of ${domain} identified ${urgencyPhrase}, yielding an overall grade of ${grade} with a risk score of ${riskScore}/100. Review the findings below and prioritise the high and critical items first.`;
}

export async function startWorker(): Promise<void> {
  // Log the effective OSV cache size so operators can confirm env var took effect
  logger.info(
    { osvCacheMaxSize: OSV_CACHE_MAX_SIZE, envVar: "OSV_CACHE_MAX_SIZE" },
    "[cveCheck] OSV cache initialised",
  );

  // Hydrate EOL cache from the last DB-persisted fetch BEFORE the staleness check
  // so that warnIfLocalDataStale() uses the live fetchedAt timestamp, not the
  // bundled LOCAL_VULN_DATA_UPDATED date, when persisted data is available.
  await loadEolCacheFromDb();

  // Check freshness — uses live DB timestamp when available, bundled date otherwise
  warnIfLocalDataStale();

  const boss = await getBoss();

  // pg-boss v12 requires queues to be explicitly created before workers can bind
  await boss.createQueue(SCAN_QUEUE, {
    retryLimit: 2,
    retryDelay: 30,
    expireInSeconds: 7200,
  });

  await boss.work<ScanJobData>(SCAN_QUEUE, { localConcurrency: 2 }, async (jobs) => {
    for (const job of jobs) {
      try {
        await processScanJob(job);
      } catch (err) {
        logger.error({ err, jobId: job.id }, "Unexpected error processing scan job");
        throw err;
      }
    }
  });

  logger.info({ queue: SCAN_QUEUE }, "Scan worker registered and listening");

  // ── EOL data auto-refresh ─────────────────────────────────────────────────
  // Scheduled daily at 03:00 UTC to keep PHP / Nginx / Apache EOL tables
  // current without manual code changes (fetches from endoflife.date API).
  await boss.createQueue(EOL_REFRESH_QUEUE);
  await boss.schedule(EOL_REFRESH_QUEUE, "0 3 * * *", {});
  await boss.work(EOL_REFRESH_QUEUE, async () => {
    await refreshEolData();
  });
  logger.info(
    { queue: EOL_REFRESH_QUEUE, cron: "0 3 * * *" },
    "EOL refresh schedule registered (daily 03:00 UTC)",
  );

  // Kick off a fresh fetch in the background to update the in-memory cache and DB.
  // Failures are logged at WARN; the DB-loaded or bundled fallback data stays active.
  void refreshEolData();
}
