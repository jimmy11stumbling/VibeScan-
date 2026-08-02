import { pgTable, text, uuid, integer, timestamp, jsonb, index, uniqueIndex } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const scansTable = pgTable("scans", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  targetUrl: text("target_url").notNull(),
  tier: text("tier", { enum: ["basic", "deep", "pack_5", "pack_20"] }).notNull(),
  status: text("status", {
    enum: ["pending", "paid", "queued", "scanning", "analyzing", "complete", "failed"],
  }).notNull().default("pending"),
  stripeSessionId: text("stripe_session_id"),
  stripePaymentIntentId: text("stripe_payment_intent_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  error: text("error"),
  /** Live per-probe checklist — array of ScanStep objects written during scanning */
  steps: jsonb("steps"),
}, (table) => [
  index("idx_scans_user_id").on(table.userId),
  index("idx_scans_status").on(table.status),
]);

export const reportsTable = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  scanId: uuid("scan_id").references(() => scansTable.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull(),
  targetUrl: text("target_url").notNull(),
  tier: text("tier", { enum: ["basic", "deep", "pack_5", "pack_20"] }).notNull(),
  scannedAt: timestamp("scanned_at", { withTimezone: true }).notNull().defaultNow(),
  duration: integer("duration"),
  data: jsonb("data").notNull(),
  pdfUrl: text("pdf_url"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_reports_user_id").on(table.userId),
  index("idx_reports_scan_id").on(table.scanId),
]);

export const creditsTable = pgTable("credits", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull().unique(),
  balance: integer("balance").notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const monitorSubscriptionsTable = pgTable("monitor_subscriptions", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  targetUrl: text("target_url").notNull(),
  status: text("status", { enum: ["active", "cancelled", "expired"] }).notNull().default("active"),
  subscribedAt: timestamp("subscribed_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  lastScanAt: timestamp("last_scan_at", { withTimezone: true }),
  lastReportId: uuid("last_report_id"),
  nextScanAt: timestamp("next_scan_at", { withTimezone: true }),
  webhookUrl: text("webhook_url"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_monitor_user_id").on(table.userId),
  index("idx_monitor_status").on(table.status),
  index("idx_monitor_target").on(table.targetUrl),
]);

export const cveAlertsTable = pgTable("cve_alerts", {
  id: uuid("id").primaryKey().defaultRandom(),
  subscriptionId: uuid("subscription_id").notNull().references(() => monitorSubscriptionsTable.id, { onDelete: "cascade" }),
  cveId: text("cve_id").notNull(),
  cveSummary: text("cve_summary").notNull(),
  affectedTech: text("affected_tech").notNull(),
  severity: text("severity").notNull(),
  triggerScanId: uuid("trigger_scan_id"),
  detectedAt: timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_cve_alerts_subscription_id").on(table.subscriptionId),
  index("idx_cve_alerts_cve_id").on(table.cveId),
]);

export const insertScanSchema = createInsertSchema(scansTable).omit({
  id: true,
  createdAt: true,
  startedAt: true,
  completedAt: true,
});
export type InsertScan = typeof scansTable.$inferInsert;
export type Scan = typeof scansTable.$inferSelect;

export const insertReportSchema = createInsertSchema(reportsTable).omit({
  id: true,
  scannedAt: true,
  createdAt: true,
});
export type InsertReport = typeof reportsTable.$inferInsert;
export type Report = typeof reportsTable.$inferSelect;

export const insertCreditSchema = createInsertSchema(creditsTable).omit({
  id: true,
  updatedAt: true,
});
export type InsertCredit = typeof creditsTable.$inferInsert;
export type Credit = typeof creditsTable.$inferSelect;

export const insertMonitorSubscriptionSchema = createInsertSchema(monitorSubscriptionsTable).omit({
  id: true,
  subscribedAt: true,
  createdAt: true,
});
export type InsertMonitorSubscription = typeof monitorSubscriptionsTable.$inferInsert;
export type MonitorSubscription = typeof monitorSubscriptionsTable.$inferSelect;

export const insertCveAlertSchema = createInsertSchema(cveAlertsTable).omit({
  id: true,
  detectedAt: true,
});
export type InsertCveAlert = typeof cveAlertsTable.$inferInsert;
export type CveAlert = typeof cveAlertsTable.$inferSelect;

export const dismissedFindingsTable = pgTable("dismissed_findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  targetUrl: text("target_url").notNull(),
  findingFingerprint: text("finding_fingerprint").notNull(),
  findingName: text("finding_name").notNull(),
  findingCategory: text("finding_category").notNull(),
  reason: text("reason").default("false_positive"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_dismissed_user_target").on(table.userId, table.targetUrl),
  uniqueIndex("uq_dismissed_user_target_fp").on(table.userId, table.targetUrl, table.findingFingerprint),
]);

export type DismissedFinding = typeof dismissedFindingsTable.$inferSelect;

export const reportSharesTable = pgTable("report_shares", {
  id: uuid("id").primaryKey().defaultRandom(),
  reportId: uuid("report_id").notNull().references(() => reportsTable.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull(),
  token: text("token").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  uniqueIndex("uq_report_shares_token").on(table.token),
  index("idx_report_shares_report_id").on(table.reportId),
  index("idx_report_shares_user_id").on(table.userId),
]);

export type ReportShare = typeof reportSharesTable.$inferSelect;

/**
 * Single-row key-value store for persisting EOL data fetched from endoflife.date.
 * Used by eolFetcher.ts to survive server restarts between daily pg-boss schedule runs.
 */
export const eolCacheTable = pgTable("eol_cache", {
  key: text("key").primaryKey(),
  payload: jsonb("payload").notNull(),
  fetchedAt: timestamp("fetched_at", { withTimezone: true }).notNull(),
});
