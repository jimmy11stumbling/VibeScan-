import { customFetch } from "@workspace/api-client-react";

export interface MonitorSubscription {
  id: string;
  userId: string;
  userEmail: string;
  targetUrl: string;
  status: "active" | "cancelled" | "expired";
  subscribedAt: string;
  expiresAt: string;
  lastScanAt: string | null;
  lastReportId: string | null;
  nextScanAt: string | null;
  webhookUrl: string | null;
  createdAt: string;
  lastReport: { id: string; grade: string | null; riskScore: number | null } | null;
  alertCount: number;
}

export interface CveAlert {
  id: string;
  subscriptionId: string;
  cveId: string;
  cveSummary: string;
  affectedTech: string;
  severity: string;
  triggerScanId: string | null;
  detectedAt: string;
}

export async function listMonitorSubscriptions(): Promise<MonitorSubscription[]> {
  return customFetch<MonitorSubscription[]>("/api/monitor/subscriptions");
}

export async function createMonitorSubscription(
  targetUrl: string,
  webhookUrl?: string,
): Promise<{ subscription: MonitorSubscription; initialScanId: string | null }> {
  return customFetch("/api/monitor/subscriptions", {
    method: "POST",
    body: JSON.stringify({ targetUrl, webhookUrl: webhookUrl || undefined }),
    headers: { "Content-Type": "application/json" },
  });
}

export async function cancelMonitorSubscription(id: string): Promise<void> {
  await customFetch(`/api/monitor/subscriptions/${id}`, { method: "DELETE" });
}

export async function listCveAlerts(subscriptionId: string): Promise<CveAlert[]> {
  return customFetch<CveAlert[]>(`/api/monitor/subscriptions/${subscriptionId}/alerts`);
}

export interface ScanHistoryEntry {
  id: string;
  scanId: string | null;
  scannedAt: string;
  tier: string;
  grade: string | null;
  riskScore: number | null;
  vulnCount: number | null;
}

export async function listSubscriptionHistory(subscriptionId: string): Promise<ScanHistoryEntry[]> {
  return customFetch<ScanHistoryEntry[]>(`/api/monitor/subscriptions/${subscriptionId}/history`);
}
