/**
 * Monitor Scheduler — registers two pg-boss recurring jobs:
 *
 *  1. monitor-weekly-scans  (cron: 0 2 * * 0 — every Sunday 02:00 UTC)
 *     Fans out a deep rescan for every active monitor subscription whose
 *     last scan is older than 6 days.
 *
 *  2. monitor-cve-check  (cron: 0 6 * * * — every day 06:00 UTC)
 *     Fetches CVEs published in the last 24 h from NVD, matches them
 *     against each active subscription's most-recent tech stack, creates
 *     cve_alerts rows, and enqueues immediate rescans for matches.
 */

import { getBoss } from "./queue";
import { db, monitorSubscriptionsTable, cveAlertsTable, reportsTable, scansTable } from "@workspace/db";
import { eq, and, lt, desc } from "drizzle-orm";
import { enqueueScan } from "./queue";
import { logger } from "./logger";
import { fetchRecentCves, matchCvesToTechnologies } from "./cveMonitor";
import { sendMonitorCveAlertEmail, sendMonitorScanQueuedEmail } from "./mailer";
import { randomUUID } from "node:crypto";

const WEEKLY_QUEUE    = "monitor-weekly-scans";
const CVE_QUEUE       = "monitor-cve-check";
const SIX_DAYS_MS     = 6 * 24 * 60 * 60 * 1000;
const SEVEN_DAYS_MS   = 7 * 24 * 60 * 60 * 1000;
const THREE_DAYS_MS   = 3 * 24 * 60 * 60 * 1000;

// ─── Weekly rescan ────────────────────────────────────────────────────────────

async function runWeeklyScans(): Promise<void> {
  const log = logger.child({ job: "monitor-weekly-scans" });
  log.info("Running weekly monitor rescans");

  const now = new Date();
  const cutoff = new Date(now.getTime() - SIX_DAYS_MS);

  const subscriptions = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const due = subscriptions.filter((sub) => {
    if (sub.status !== "active") return false;
    if (sub.expiresAt <= now) return false;
    if (!sub.lastScanAt) return true;
    // Use nextScanAt for adaptive cadence; fall back to 6-day cutoff for older rows
    if (sub.nextScanAt) return sub.nextScanAt <= now;
    return sub.lastScanAt <= cutoff;
  });

  log.info({ total: subscriptions.length, due: due.length }, "Subscriptions due for weekly rescan");

  for (const sub of due) {
    try {
      const [scan] = await db
        .insert(scansTable)
        .values({
          userId: sub.userId,
          userEmail: sub.userEmail,
          targetUrl: sub.targetUrl,
          tier: "deep",
          status: "paid",
        })
        .returning();

      await enqueueScan({
        scanId: scan.id,
        userId: sub.userId,
        targetUrl: sub.targetUrl,
        tier: "deep",
        monitorSubscriptionId: sub.id,
      });

      await db
        .update(scansTable)
        .set({ status: "queued", startedAt: new Date() })
        .where(eq(scansTable.id, scan.id));

      log.info({ subscriptionId: sub.id, scanId: scan.id, targetUrl: sub.targetUrl }, "Weekly rescan queued");

      if (sub.userEmail) {
        const appOrigin = process.env.APP_ORIGIN ?? "https://vibescan.app";
        await sendMonitorScanQueuedEmail({
          toEmail: sub.userEmail,
          targetUrl: sub.targetUrl,
          scanId: scan.id,
          reason: "weekly",
          dashboardUrl: `${appOrigin}/monitor`,
        });
      }
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "Failed to enqueue weekly rescan");
    }
  }
}

// ─── Daily CVE check ──────────────────────────────────────────────────────────

async function runCveCheck(): Promise<void> {
  const log = logger.child({ job: "monitor-cve-check" });
  log.info("Running daily CVE check");

  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const cves = await fetchRecentCves(yesterday, now);
  log.info({ cveCount: cves.length }, "Fetched CVEs from NVD");

  if (cves.length === 0) return;

  const activeSubscriptions = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const validSubs = activeSubscriptions.filter((s) => s.expiresAt > now);
  log.info({ subscriptions: validSubs.length }, "Checking active subscriptions against CVEs");

  const appOrigin = process.env.APP_ORIGIN ?? "https://vibescan.app";

  for (const sub of validSubs) {
    try {
      // Get the most recent completed report for this subscription's target URL
      const [latestReport] = await db
        .select({ id: reportsTable.id, data: reportsTable.data })
        .from(reportsTable)
        .where(
          and(
            eq(reportsTable.userId, sub.userId),
            eq(reportsTable.targetUrl, sub.targetUrl),
          ),
        )
        .orderBy(desc(reportsTable.createdAt))
        .limit(1);

      if (!latestReport) continue;

      const reportData = latestReport.data as { technologies?: string[] };
      const technologies = reportData.technologies ?? [];
      if (technologies.length === 0) continue;

      const matches = matchCvesToTechnologies(technologies, cves);
      if (matches.length === 0) continue;

      log.info(
        { subscriptionId: sub.id, targetUrl: sub.targetUrl, matches: matches.length },
        "CVE matches found — triggering rescan",
      );

      // Create a new scan triggered by CVE match
      const [scan] = await db
        .insert(scansTable)
        .values({
          userId: sub.userId,
          userEmail: sub.userEmail,
          targetUrl: sub.targetUrl,
          tier: "deep",
          status: "paid",
        })
        .returning();

      await enqueueScan({
        scanId: scan.id,
        userId: sub.userId,
        targetUrl: sub.targetUrl,
        tier: "deep",
        monitorSubscriptionId: sub.id,
      });

      await db
        .update(scansTable)
        .set({ status: "queued", startedAt: new Date() })
        .where(eq(scansTable.id, scan.id));

      // Record each CVE alert
      for (const { cve, matchedTech } of matches) {
        await db.insert(cveAlertsTable).values({
          subscriptionId: sub.id,
          cveId: cve.id,
          cveSummary: cve.description.slice(0, 500),
          affectedTech: matchedTech,
          severity: cve.severity,
          triggerScanId: scan.id,
        });
      }

      // Send CVE alert email
      if (sub.userEmail) {
        await sendMonitorCveAlertEmail({
          toEmail: sub.userEmail,
          targetUrl: sub.targetUrl,
          cveMatches: matches.map(({ cve, matchedTech }) => ({
            cveId: cve.id,
            summary: cve.description.slice(0, 200),
            severity: cve.severity,
            affectedTech: matchedTech,
          })),
          scanId: scan.id,
          dashboardUrl: `${appOrigin}/monitor`,
        });
      }
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "CVE check failed for subscription");
    }
  }
}

// ─── Scheduler registration ───────────────────────────────────────────────────

export async function startMonitorScheduler(): Promise<void> {
  const boss = await getBoss();

  await boss.createQueue(WEEKLY_QUEUE);
  await boss.createQueue(CVE_QUEUE);

  await boss.schedule(WEEKLY_QUEUE, "0 2 * * 0", {});
  await boss.schedule(CVE_QUEUE, "0 6 * * *", {});

  await boss.work(WEEKLY_QUEUE, async () => {
    await runWeeklyScans();
  });

  await boss.work(CVE_QUEUE, async () => {
    await runCveCheck();
  });

  logger.info("Monitor scheduler registered (weekly scans + daily CVE check)");
}
