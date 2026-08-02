import { Router, type IRouter } from "express";
import { db, monitorSubscriptionsTable, cveAlertsTable, reportsTable } from "@workspace/db";
import { eq, and, desc, count } from "drizzle-orm";
import { z } from "zod";
import { enqueueScan } from "../lib/queue";
import { scansTable } from "@workspace/db";
import { logger } from "../lib/logger";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

/** Fetch the most recent completed report for a user+URL pair. */
async function fetchLatestReport(userId: string, targetUrl: string) {
  const [report] = await db
    .select({
      id: reportsTable.id,
      scannedAt: reportsTable.scannedAt,
      data: reportsTable.data,
    })
    .from(reportsTable)
    .where(and(eq(reportsTable.userId, userId), eq(reportsTable.targetUrl, targetUrl)))
    .orderBy(desc(reportsTable.scannedAt))
    .limit(1);
  return report ?? null;
}

const router: IRouter = Router();

const CreateMonitorBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
  webhookUrl: z.string().url("Webhook must be a valid URL").optional().or(z.literal("")),
});

// ── POST /api/monitor/subscriptions ──────────────────────────────────────────
// Create a new monitoring subscription for a URL.
// With DISABLE_PAYMENTS=true this is granted immediately.

router.post("/monitor/subscriptions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateMonitorBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }

  const { targetUrl, webhookUrl } = parsed.data;

  // Check for an existing active subscription for this user+URL
  const [existing] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.userId, req.user.id),
        eq(monitorSubscriptionsTable.targetUrl, targetUrl),
        eq(monitorSubscriptionsTable.status, "active"),
      ),
    );

  if (existing) {
    res.status(409).json({ error: "You already have an active monitor subscription for this URL." });
    return;
  }

  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setFullYear(expiresAt.getFullYear() + 1);

  // Seed from the most recent existing report for this URL so the card
  // immediately shows the last grade/scan date instead of "Never".
  const existingReport = await fetchLatestReport(req.user.id, targetUrl);
  const seedReportId = existingReport?.id ?? null;
  const seedScanAt = existingReport?.scannedAt ?? null;

  const [sub] = await db
    .insert(monitorSubscriptionsTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      status: "active",
      expiresAt,
      lastReportId: seedReportId,
      lastScanAt: seedScanAt,
      webhookUrl: webhookUrl || null,
      nextScanAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    })
    .returning();

  // Always trigger a baseline deep scan immediately on subscription activation.
  // The card is already seeded with the most recent report above so it shows
  // historical data while the new scan runs.
  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl,
        tier: "deep",
        status: "paid",
      })
      .returning();

    await enqueueScan({
      scanId: scan.id,
      userId: req.user.id,
      targetUrl,
      tier: "deep",
      monitorSubscriptionId: sub.id,
    });

    await db
      .update(scansTable)
      .set({ status: "queued", startedAt: new Date() })
      .where(eq(scansTable.id, scan.id));

    logger.info({ subscriptionId: sub.id, scanId: scan.id }, "Initial monitor scan queued");

    res.status(201).json({
      subscription: sub,
      initialScanId: scan.id,
    });
  } catch (err) {
    logger.error({ err }, "Failed to enqueue initial monitor scan");
    res.status(201).json({ subscription: sub, initialScanId: null });
  }
});

// ── GET /api/monitor/subscriptions ───────────────────────────────────────────
// List all monitor subscriptions for the authenticated user.

router.get("/monitor/subscriptions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subs = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.userId, req.user.id))
    .orderBy(desc(monitorSubscriptionsTable.createdAt));

  // Attach latest report info and alert count to each subscription
  const enriched = await Promise.all(
    subs.map(async (sub) => {
      // Resolve the report: prefer lastReportId, fall back to most-recent report for the URL
      let resolvedReport: { id: string; scannedAt: Date; data: unknown } | null = null;

      if (sub.lastReportId) {
        const [r] = await db
          .select({ id: reportsTable.id, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
          .from(reportsTable)
          .where(eq(reportsTable.id, sub.lastReportId));
        resolvedReport = r ?? null;
      }

      // Fallback: look up the most recent report for this user+URL
      if (!resolvedReport) {
        resolvedReport = await fetchLatestReport(sub.userId, sub.targetUrl);
        // If we found one via fallback, backfill the subscription row so future
        // calls use the fast path.
        if (resolvedReport) {
          await db
            .update(monitorSubscriptionsTable)
            .set({
              lastReportId: resolvedReport.id,
              lastScanAt: resolvedReport.scannedAt,
            })
            .where(eq(monitorSubscriptionsTable.id, sub.id));
        }
      }

      let lastReport: { id: string; grade: string | null; riskScore: number | null } | null = null;
      if (resolvedReport) {
        const data = resolvedReport.data as { summary?: { grade?: string; riskScore?: number } };
        lastReport = {
          id: resolvedReport.id,
          grade: data.summary?.grade ?? null,
          riskScore: data.summary?.riskScore ?? null,
        };
      }

      // Count CVE alerts
      const [{ value: alertCount }] = await db
        .select({ value: count() })
        .from(cveAlertsTable)
        .where(eq(cveAlertsTable.subscriptionId, sub.id));

      // Use the resolved scanAt so the card shows the correct date even before
      // the subscription row was backfilled.
      const lastScanAt = sub.lastScanAt ?? resolvedReport?.scannedAt ?? null;

      return {
        ...sub,
        lastScanAt,
        lastReport,
        alertCount,
      };
    }),
  );

  res.json(enriched);
});

// ── DELETE /api/monitor/subscriptions/:id ────────────────────────────────────
// Cancel a monitor subscription.

router.delete("/monitor/subscriptions/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  await db
    .update(monitorSubscriptionsTable)
    .set({ status: "cancelled" })
    .where(eq(monitorSubscriptionsTable.id, subId));

  res.json({ success: true });
});

// ── GET /api/monitor/subscriptions/:id/history ───────────────────────────────
// Return all completed reports for the subscription's URL, newest first.

router.get("/monitor/subscriptions/:id/history", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, req.params.id),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  const reports = await db
    .select({
      id: reportsTable.id,
      scanId: reportsTable.scanId,
      scannedAt: reportsTable.scannedAt,
      tier: reportsTable.tier,
      data: reportsTable.data,
    })
    .from(reportsTable)
    .where(
      and(
        eq(reportsTable.userId, req.user.id),
        eq(reportsTable.targetUrl, sub.targetUrl),
      ),
    )
    .orderBy(desc(reportsTable.scannedAt))
    .limit(20);

  const history = reports.map((r) => {
    const data = r.data as {
      summary?: { grade?: string; riskScore?: number; vulnCount?: number };
    };
    return {
      id: r.id,
      scanId: r.scanId,
      scannedAt: r.scannedAt,
      tier: r.tier,
      grade: data.summary?.grade ?? null,
      riskScore: data.summary?.riskScore ?? null,
      vulnCount: data.summary?.vulnCount ?? null,
    };
  });

  res.json(history);
});

// ── GET /api/monitor/subscriptions/:id/alerts ────────────────────────────────
// List CVE alerts for a subscription.

router.get("/monitor/subscriptions/:id/alerts", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  const alerts = await db
    .select()
    .from(cveAlertsTable)
    .where(eq(cveAlertsTable.subscriptionId, subId))
    .orderBy(desc(cveAlertsTable.detectedAt));

  res.json(alerts);
});

export default router;
