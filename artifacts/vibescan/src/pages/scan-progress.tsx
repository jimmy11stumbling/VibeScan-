import { useState, useEffect, useRef } from "react";
import { useParams, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import {
  Shield, Loader2, CheckCircle2, XCircle, Clock,
  Lock, Radar, Globe, ShieldCheck, Server,
  AlertTriangle, Key, Link2, FileCode2, Database,
  Box, Layers, FileText, Cpu, HardDrive, Eye, FolderOpen,
  ArrowRight, ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type StepStatus = "pending" | "running" | "done" | "error";

interface ScanStep {
  key: string;
  label: string;
  status: StepStatus;
  findings?: number;
  startedAt?: string;
  doneAt?: string;
}

type ScanStatus =
  | "pending" | "paid" | "queued"
  | "scanning" | "analyzing"
  | "complete" | "failed";

interface ScanStatusResponse {
  id: string;
  targetUrl: string;
  tier: "basic" | "deep" | "pack_5" | "pack_20";
  status: ScanStatus;
  progress: number;
  createdAt: string;
  startedAt?: string | null;
  completedAt?: string | null;
  error?: string | null;
  reportId?: string | null;
  grade?: string | null;
  steps?: ScanStep[] | null;
}

// ─── Icon map per step key ────────────────────────────────────────────────────

const STEP_ICONS: Record<string, React.ElementType> = {
  ssl:        Lock,
  recon:      Radar,
  crawl:      Globe,
  headers:    ShieldCheck,
  dns:        Server,
  cve:        AlertTriangle,
  jwt:        Key,
  takeover:   Link2,
  sourcemaps: FileCode2,
  vibestack:  Database,
  baas:       Box,
  graphql:    Layers,
  apidocs:    FileText,
  nextjs:     Cpu,
  storage:    HardDrive,
  jssecrets:  Eye,
  traversal:  FolderOpen,
};

// ─── Individual step row ──────────────────────────────────────────────────────

function StepRow({ step }: { step: ScanStep }) {
  const Icon = STEP_ICONS[step.key] ?? Shield;

  return (
    <div
      className={cn(
        "flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300",
        step.status === "running"  && "bg-primary/10 border border-primary/30",
        step.status === "done"     && "bg-emerald-500/5 border border-emerald-500/20",
        step.status === "error"    && "bg-red-500/5 border border-red-500/15",
        step.status === "pending"  && "border border-white/5",
      )}
    >
      {/* Status circle */}
      <div className="shrink-0 w-5 h-5 flex items-center justify-center">
        {step.status === "pending" && (
          <div className="w-2 h-2 rounded-full bg-white/20" />
        )}
        {step.status === "running" && (
          <Loader2 className="w-4 h-4 text-primary animate-spin" />
        )}
        {step.status === "done" && (
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
        )}
        {step.status === "error" && (
          <XCircle className="w-4 h-4 text-red-400" />
        )}
      </div>

      {/* Category icon */}
      <Icon
        className={cn(
          "w-4 h-4 shrink-0",
          step.status === "running"  && "text-primary",
          step.status === "done"     && "text-emerald-400",
          step.status === "error"    && "text-red-400",
          step.status === "pending"  && "text-white/25",
        )}
      />

      {/* Label */}
      <span
        className={cn(
          "flex-1 text-sm font-medium transition-colors",
          step.status === "pending"  && "text-white/30",
          step.status === "running"  && "text-foreground",
          step.status === "done"     && "text-foreground/80",
          step.status === "error"    && "text-red-300",
        )}
      >
        {step.label}
      </span>

      {/* Right-side badge */}
      <div className="shrink-0 text-xs tabular-nums">
        {step.status === "running" && (
          <span className="text-primary/80 animate-pulse">Scanning…</span>
        )}
        {step.status === "done" && step.findings !== undefined && step.findings > 0 && (
          <span className="px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 font-semibold">
            {step.findings} {step.findings === 1 ? "finding" : "findings"}
          </span>
        )}
        {step.status === "done" && (step.findings === undefined || step.findings === 0) && (
          <span className="text-emerald-400/60">Clear</span>
        )}
        {step.status === "error" && (
          <span className="text-red-400/70">Skipped</span>
        )}
      </div>
    </div>
  );
}

// ─── Grade badge ──────────────────────────────────────────────────────────────

function GradeBadge({ grade }: { grade: string }) {
  const color =
    grade === "A+" || grade === "A"
      ? "text-emerald-400 border-emerald-400/30 bg-emerald-400/10"
      : grade === "B"
      ? "text-sky-400 border-sky-400/30 bg-sky-400/10"
      : grade === "C"
      ? "text-amber-400 border-amber-400/30 bg-amber-400/10"
      : "text-red-400 border-red-400/30 bg-red-400/10";
  return (
    <span className={cn("inline-flex items-center px-3 py-1 rounded-xl border text-2xl font-black", color)}>
      {grade}
    </span>
  );
}

// ─── Progress calculation ─────────────────────────────────────────────────────

function computeProgress(status: ScanStatus, steps: ScanStep[] | null | undefined): number {
  if (status === "complete") return 100;
  if (status === "analyzing") return 90;
  if (status === "failed") return 0;
  if (!steps || steps.length === 0) {
    return status === "queued" ? 5 : status === "scanning" ? 15 : 0;
  }
  const done = steps.filter((s) => s.status === "done" || s.status === "error").length;
  return Math.round(10 + (done / steps.length) * 80);
}

// ─── Elapsed time hook ────────────────────────────────────────────────────────

function useElapsed(startedAt: string): number {
  const startMs = new Date(startedAt).getTime();
  const [elapsed, setElapsed] = useState(() => Math.floor((Date.now() - startMs) / 1000));
  useEffect(() => {
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - startMs) / 1000)), 1000);
    return () => clearInterval(id);
  }, [startMs]);
  return elapsed;
}

// ─── Elapsed timer component ──────────────────────────────────────────────────

function ElapsedTimer({ startedAt }: { startedAt: string }) {
  const elapsed = useElapsed(startedAt);
  return (
    <p className="mt-4 text-center text-xs text-muted-foreground/50 flex items-center justify-center gap-1.5">
      <Clock className="w-3 h-3" />
      {elapsed}s elapsed · Deep scans typically take 60–90 seconds
    </p>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

const STATUS_LABEL: Record<ScanStatus, string> = {
  pending:   "Preparing scan…",
  paid:      "Payment confirmed, queuing…",
  queued:    "Waiting in queue…",
  scanning:  "Running security probes…",
  analyzing: "Generating AI report…",
  complete:  "Scan complete!",
  failed:    "Scan failed",
};

export default function ScanProgressPage() {
  const { id } = useParams<{ id: string }>();
  const [, setLocation] = useLocation();
  const redirectedRef = useRef(false);

  const { data } = useQuery<ScanStatusResponse>({
    queryKey: ["scan-status", id],
    queryFn: () => customFetch(`/api/scans/${id}/status`),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      if (!s || s === "complete" || s === "failed") return false;
      return 2000;
    },
    enabled: !!id,
  });

  // Auto-redirect to report 1.5 s after completion
  useEffect(() => {
    const reportId = data?.reportId;
    if (data?.status !== "complete" || !reportId || redirectedRef.current) return;
    redirectedRef.current = true;
    const t = setTimeout(() => setLocation(`/report/${reportId}`), 1500);
    return () => clearTimeout(t);
  }, [data, setLocation]);

  const status = data?.status ?? "queued";
  const steps  = data?.steps ?? null;
  const progress = computeProgress(status, steps);
  const isActive = status !== "complete" && status !== "failed";

  const hostname = (() => {
    try { return new URL(data?.targetUrl ?? "").hostname; }
    catch { return data?.targetUrl ?? ""; }
  })();

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* ── Header ── */}
      <div className="mb-8 text-center">
        <div
          className={cn(
            "w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-5 border transition-all",
            status === "complete"
              ? "bg-emerald-500/10 border-emerald-500/30"
              : status === "failed"
              ? "bg-red-500/10 border-red-500/30"
              : "bg-primary/10 border-primary/20",
          )}
        >
          {status === "complete" ? (
            <CheckCircle2 className="w-8 h-8 text-emerald-400" />
          ) : status === "failed" ? (
            <XCircle className="w-8 h-8 text-red-400" />
          ) : (
            <Shield className={cn("w-8 h-8 text-primary", isActive && "animate-pulse")} />
          )}
        </div>

        <h1 className="text-2xl font-bold tracking-tight mb-1">
          {STATUS_LABEL[status] ?? "Scanning…"}
        </h1>
        {hostname && (
          <p className="text-muted-foreground text-sm font-mono mt-1">{hostname}</p>
        )}
        {data?.tier === "deep" && (
          <span className="inline-flex items-center gap-1 mt-2 px-2 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-medium">
            <Shield className="w-3 h-3" /> Deep Scan
          </span>
        )}
      </div>

      {/* ── Progress bar ── */}
      <div className="mb-6">
        <div className="flex justify-between text-xs text-muted-foreground mb-2">
          <span>{progress}% complete</span>
          {steps && (
            <span>
              {steps.filter((s) => s.status === "done" || s.status === "error").length}
              {" / "}
              {steps.length} checks
            </span>
          )}
        </div>
        <div className="h-2 rounded-full bg-white/5 overflow-hidden">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-700",
              status === "complete" ? "bg-emerald-500" :
              status === "failed"   ? "bg-red-500" :
              "bg-primary",
              isActive && progress < 100 && "animate-pulse",
            )}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* ── Failed state ── */}
      {status === "failed" && (
        <div className="glass-card rounded-2xl p-5 mb-6 border border-red-500/20 bg-red-500/5">
          <p className="text-sm text-red-400 font-medium">
            {data?.error ??
              "The scan encountered an unexpected error. The target URL may be unreachable or timed out."}
          </p>
          <button
            onClick={() => setLocation("/scan")}
            className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-primary hover:text-primary/80 transition-colors"
          >
            Try a different URL <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ── Complete — grade + CTA ── */}
      {status === "complete" && (
        <div className="glass-card rounded-2xl p-5 mb-6 flex items-center gap-4">
          {data?.grade && <GradeBadge grade={data.grade} />}
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-sm">Report ready</p>
            <p className="text-xs text-muted-foreground">Redirecting to your report…</p>
          </div>
          {data?.reportId && (
            <button
              onClick={() => setLocation(`/report/${data.reportId}`)}
              className="shrink-0 flex items-center gap-1.5 px-4 py-2 bg-primary text-primary-foreground text-sm font-semibold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all"
            >
              View Report <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      )}

      {/* ── Queued / no steps yet ── */}
      {(status === "queued" || status === "pending" || status === "paid") && !steps && (
        <div className="glass-card rounded-2xl p-6 flex items-center gap-4 mb-4">
          <Loader2 className="w-6 h-6 text-primary animate-spin shrink-0" />
          <div>
            <p className="font-medium text-sm">Waiting for a scanner…</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Your scan will start within a few seconds.
            </p>
          </div>
        </div>
      )}

      {/* ── Analyzing — AI step after probes ── */}
      {status === "analyzing" && (
        <div className="glass-card rounded-2xl p-4 mb-4 flex items-center gap-3 border border-indigo-500/20 bg-indigo-500/5">
          <Loader2 className="w-5 h-5 text-indigo-400 animate-spin shrink-0" />
          <p className="text-sm font-medium text-indigo-300">
            AI is generating your security report and remediation guide…
          </p>
        </div>
      )}

      {/* ── Per-probe checklist ── */}
      {steps && steps.length > 0 && (
        <div className="glass-card rounded-2xl overflow-hidden">
          <div className="px-4 py-3 border-b border-white/5">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Security Checks
            </h2>
          </div>
          <div className="p-3 flex flex-col gap-1.5">
            {steps.map((step) => (
              <StepRow key={step.key} step={step} />
            ))}
          </div>
        </div>
      )}

      {/* ── Scanning but steps not yet written ── */}
      {status === "scanning" && !steps && (
        <div className="glass-card rounded-2xl p-6 flex items-center gap-4">
          <Loader2 className="w-6 h-6 text-primary animate-spin shrink-0" />
          <div>
            <p className="font-medium text-sm">Probes starting…</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              The checklist will appear momentarily.
            </p>
          </div>
        </div>
      )}

      {/* ── Elapsed timer ── */}
      {isActive && data?.startedAt && (
        <ElapsedTimer startedAt={data.startedAt} />
      )}
    </div>
  );
}
