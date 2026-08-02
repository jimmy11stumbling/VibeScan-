import { useState, useMemo, useCallback, useContext, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  CheckCircle2, Globe, Server, Package, AlertTriangle, Network,
  HelpCircle, Flag, RotateCcw, Filter, ChevronDown, Search, Minus,
  Sparkles, Zap, Code2, Database, Terminal, Check, Copy, ExternalLink,
} from "lucide-react";
import { cn, getSeverityColors, getGradeColor } from "@/lib/utils";
import type { Vulnerability } from "@workspace/api-client-react";
import { DismissalsContext, vulnUniqueKey, type DismissalEntry } from "./report-viewer-context";
import {
  getCategoryMeta, getVerificationNote, parseTechVersion, wstgCategoryPath,
  SEVERITY_ORDER, VERIFICATION_THRESHOLD,
} from "./report-viewer-utils";

// ─── Grade ring ───────────────────────────────────────────────────────────────

export function GradeRing({ grade, score }: { grade: string; score: number }) {
  const colorMap: Record<string, string> = {
    A: "#34d399", B: "#a3e635", C: "#facc15", D: "#fb923c", F: "#f87171",
  };
  const color = colorMap[grade] || "#94a3b8";

  return (
    <div className="relative w-48 h-48 flex items-center justify-center">
      <svg className="w-full h-full transform -rotate-90 absolute inset-0">
        <circle cx="96" cy="96" r="88" fill="none" stroke="currentColor" strokeWidth="8" className="text-secondary" />
        <circle
          cx="96" cy="96" r="88" fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${2 * Math.PI * 88}`}
          strokeDashoffset={`${2 * Math.PI * 88 * (1 - score / 100)}`}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="flex flex-col items-center justify-center bg-background w-36 h-36 rounded-full border-4 border-card shadow-2xl z-10 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-white/5 to-transparent rounded-full" />
        <span className={cn("text-6xl font-black font-display leading-none", getGradeColor(grade))}>
          {grade}
        </span>
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-widest mt-1">
          Risk: {score}
        </span>
      </div>
    </div>
  );
}

// ─── Inner-page source extractor ─────────────────────────────────────────────

const INNER_PAGE_CATEGORIES = new Set([
  "Security Header Inconsistency",
  "Session Management",
]);

/**
 * Tries to extract a non-root path from a finding's evidence field.
 * Only applies to "Security Header Inconsistency" and "Session Management" categories.
 *
 * Handles two evidence formats produced by the crawler:
 *   1. Session Management: "GET https://host/path\nSet-Cookie: ..."
 *      → extracts the pathname from the full URL
 *   2. Security Header Inconsistency: "Routes missing X:\n  • /path (crawled)\n..."
 *      → extracts the first bullet-list path
 *
 * Returns the pathname (e.g. "/api/v1") when it's a non-root inner page, else null.
 */
export function extractInnerPageSource(
  evidence: string | null | undefined,
  rootUrl: string,
  category: string,
): string | null {
  if (!evidence || !INNER_PAGE_CATEGORIES.has(category)) return null;

  // Format 1: "GET https://host/path" — Session Management cookie findings
  // Also matches "[Direct probe] GET https://host/path" prefix variant
  const getMatch = /^(?:\[[^\]]*\]\s+)?GET\s+(https?:\/\/\S+)/m.exec(evidence);
  if (getMatch) {
    try {
      const url = new URL(getMatch[1]);
      const root = new URL(rootUrl);
      if (url.hostname !== root.hostname) return null;
      const path = url.pathname;
      if (!path || path === "/" || path === root.pathname) return null;
      return path;
    } catch {
      return null;
    }
  }

  // Format 2: "Routes missing X:\n  • /path (crawled)" — Security Header Inconsistency
  const bulletMatch = /•\s+(\/[^\s(]*)/.exec(evidence);
  if (bulletMatch) {
    const path = bulletMatch[1];
    try {
      const root = new URL(rootUrl);
      if (!path || path === "/" || path === root.pathname) return null;
    } catch {
      // ignore URL parse errors; still return the path
    }
    return path;
  }

  return null;
}

/**
 * Extracts the first CVE ID from a finding's evidence string.
 * Used as a fallback for older findings that pre-date the structured `cveId` field.
 */
function extractCveFromEvidence(evidence: string | null | undefined): string | null {
  if (!evidence) return null;
  const m = /CVE-\d{4}-\d{4,}/i.exec(evidence);
  return m ? m[0].toUpperCase() : null;
}

// ─── Vuln card ────────────────────────────────────────────────────────────────

export function VulnCard({
  vuln,
  index,
  needsVerification,
  rootUrl,
}: {
  vuln: Vulnerability;
  index: number;
  needsVerification?: boolean;
  rootUrl?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const { dismiss, undismiss, dismissedFps, vulnFpMap, optimisticDismissKeys } = useContext(DismissalsContext);
  const vKey = vulnUniqueKey(vuln);
  const fp = vulnFpMap.get(vKey);
  const isDismissed = optimisticDismissKeys.has(vKey) || (fp !== undefined && dismissedFps.has(fp));
  const [dismissPending, setDismissPending] = useState(false);
  const meta = getCategoryMeta(vuln.category);

  // Extract the affected component for CVE / outdated-software findings.
  // Hoisted here so both the header chip and the expanded detail share the same value.
  const isCveCategory =
    vuln.category === "Outdated Software / Known CVE" ||
    vuln.category === "Outdated Software";
  const rawComponent = isCveCategory
    ? (/^(.+?)\s+—/.exec(vuln.name)?.[1] ??
       /^Detected:\s+(.+)$/m.exec(vuln.evidence ?? "")?.[1] ??
       null)
    : null;
  const { name: compName, version: compVersion } = rawComponent
    ? parseTechVersion(rawComponent)
    : { name: null, version: null };

  // Extract inner-page source path (e.g. "/api/v1") for crawler findings
  // Only shown for Security Header Inconsistency and Session Management categories
  const innerPageSource = rootUrl
    ? extractInnerPageSource(vuln.evidence, rootUrl, vuln.category)
    : null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(0.05 * index, 0.4) }}
      className="glass-card rounded-xl overflow-hidden border border-white/5"
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-5 flex items-start sm:items-center justify-between text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-3 flex-1 min-w-0">
          <span className={cn("px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider shrink-0 border", getSeverityColors(vuln.severity))}>
            {vuln.severity}
          </span>
          <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 min-w-0">
            <h4 className="text-base font-bold text-foreground leading-snug">{vuln.name}</h4>
            {compName && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-yellow-500/10 border border-yellow-500/20 rounded text-[10px] font-mono leading-none text-yellow-400/80 shrink-0 self-start sm:self-auto">
                <Package className="w-2.5 h-2.5" />
                {compName}{compVersion ? `@${compVersion}` : ""}
              </span>
            )}
            {innerPageSource && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-sky-500/10 border border-sky-500/20 rounded text-[10px] font-mono leading-none text-sky-400/70 shrink-0 self-start sm:self-auto" title={`Found on inner page: ${innerPageSource}`}>
                <Globe className="w-2.5 h-2.5" />
                {innerPageSource}
              </span>
            )}
            {vuln.url && (
              <a
                href={vuln.url}
                target="_blank"
                rel="noreferrer noopener"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/25 rounded text-[10px] font-mono leading-none text-orange-400/80 hover:bg-orange-500/20 hover:text-orange-300 transition-colors shrink-0 self-start sm:self-auto"
                title={`Open exposed page: ${vuln.url}`}
              >
                <ExternalLink className="w-2.5 h-2.5" />
                Open
              </a>
            )}
          </div>
        </div>
        <div className={cn("hidden md:flex items-center gap-1.5 text-xs font-medium shrink-0 ml-4", meta.color)}>
          {meta.icon}
          <span className="whitespace-nowrap">{meta.label}</span>
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="p-5 pt-0 border-t border-white/5 mt-2 bg-secondary/20">
              {needsVerification && (
                <div className="mt-4 mb-1 flex gap-3 p-3 rounded-lg bg-amber-500/8 border border-amber-500/25">
                  <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-semibold text-amber-300 mb-0.5">Manual verification recommended</p>
                    <p className="text-xs text-amber-200/70 leading-relaxed">{getVerificationNote(vuln.category)}</p>
                  </div>
                </div>
              )}
              {/* Detected component badge for CVE/outdated-software findings */}
              {compName && (
                <div className="mt-4 flex items-center gap-2">
                  <span className="text-xs text-muted-foreground font-medium">Detected component:</span>
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-secondary rounded-md border border-white/10 text-xs font-mono">
                    <Package className="w-3 h-3 text-yellow-400 shrink-0" />
                    <span className="font-medium text-foreground/90">{compName}</span>
                    {compVersion && (
                      <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] rounded border border-yellow-500/20 leading-none font-mono">
                        {compVersion}
                      </span>
                    )}
                  </span>
                </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-5">
                <div className="flex flex-col gap-4">
                  <div>
                    <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Description</h5>
                    <p className="text-sm text-foreground/90 leading-relaxed">{vuln.description}</p>
                  </div>
                  {vuln.evidence && (
                    <div>
                      <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Evidence</h5>
                      <div className="bg-background border border-white/10 rounded-lg p-3 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                        {vuln.evidence}
                      </div>
                    </div>
                  )}
                </div>
                <div>
                  <h5 className="text-xs font-bold text-primary uppercase tracking-wider mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> Recommended Fix
                  </h5>
                  <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 text-sm text-foreground/90 leading-relaxed">
                    <div className="whitespace-pre-wrap">{vuln.solution}</div>
                  </div>

                  {/* Exposed page link — full-width button in the detail pane */}
                  {vuln.url && (
                    <a
                      href={vuln.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="mt-4 flex items-center justify-between gap-3 px-4 py-3 rounded-lg bg-orange-500/8 border border-orange-500/25 hover:bg-orange-500/15 hover:border-orange-500/40 transition-colors group"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <ExternalLink className="w-4 h-4 text-orange-400 shrink-0" />
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-orange-300 leading-none mb-0.5">Exposed page</p>
                          <p className="text-xs font-mono text-orange-400/70 truncate">{vuln.url}</p>
                        </div>
                      </div>
                      <span className="text-xs text-orange-400/60 group-hover:text-orange-300 shrink-0 transition-colors">Open ↗</span>
                    </a>
                  )}

                  {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId || vuln.confidence != null || vuln.cveId || extractCveFromEvidence(vuln.evidence)) && (
                    <div className="mt-4 flex gap-3 flex-wrap">
                      {/* CVE → NVD link */}
                      {(vuln.cveId ?? extractCveFromEvidence(vuln.evidence)) && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId ?? extractCveFromEvidence(vuln.evidence)}`}
                          target="_blank" rel="noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-red-300 bg-red-950/60 border border-red-500/30 px-2 py-1 rounded hover:bg-red-900/60 hover:border-red-500/50 transition-colors"
                        >
                          <ExternalLink className="w-3 h-3" />
                          {vuln.cveId ?? extractCveFromEvidence(vuln.evidence)}
                        </a>
                      )}
                      {vuln.cweId && (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace("CWE-", "")}.html`}
                          target="_blank" rel="noreferrer"
                          className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                        >
                          {vuln.cweId}
                        </a>
                      )}
                      {vuln.cvssScore != null && (
                        <span className={cn(
                          "text-xs px-2 py-1 rounded font-medium",
                          vuln.cvssScore >= 9 ? "bg-red-950 text-red-400" :
                          vuln.cvssScore >= 7 ? "bg-orange-950 text-orange-400" :
                          vuln.cvssScore >= 4 ? "bg-yellow-950 text-yellow-400" :
                          "bg-secondary text-muted-foreground",
                        )}>
                          CVSS {vuln.cvssScore.toFixed(1)}
                        </span>
                      )}
                      {vuln.wstgId && (
                        <a
                          href={`https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/${wstgCategoryPath(vuln.wstgId)}`}
                          target="_blank" rel="noreferrer"
                          className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                        >
                          {vuln.wstgId}
                        </a>
                      )}
                      {vuln.confidence != null && (
                        <span
                          title="Confidence: how certain the scanner is this is a real finding, not a false positive"
                          className={cn(
                            "text-xs px-2 py-1 rounded font-medium",
                            vuln.confidence >= 85 ? "bg-emerald-950 text-emerald-400" :
                            vuln.confidence >= 70 ? "bg-teal-950 text-teal-400" :
                            vuln.confidence >= 55 ? "bg-yellow-950 text-yellow-500" :
                            "bg-secondary text-muted-foreground",
                          )}
                        >
                          {vuln.confidence}% confidence
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* False positive dismissal */}
            <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
              <p className="text-xs text-muted-foreground">Not applicable to your setup?</p>
              {isDismissed ? (
                <button
                  onClick={async (e) => {
                    e.stopPropagation();
                    setDismissPending(true);
                    await undismiss(vuln);
                    setDismissPending(false);
                  }}
                  disabled={dismissPending}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                >
                  <RotateCcw className="w-3 h-3" />
                  Undo dismissal
                </button>
              ) : (
                <button
                  onClick={async (e) => {
                    e.stopPropagation();
                    if (!rootUrl) return;
                    setDismissPending(true);
                    await dismiss(vuln, rootUrl);
                    setDismissPending(false);
                  }}
                  disabled={dismissPending || !rootUrl}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-secondary border border-white/10 text-muted-foreground hover:text-foreground hover:border-white/20 transition-colors disabled:opacity-50"
                >
                  <Flag className="w-3 h-3" />
                  Mark as false positive
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── Recon card ───────────────────────────────────────────────────────────────

const DANGEROUS_RECON_PORTS = new Set([23, 445, 2375, 6379, 27017, 9200, 1433, 3306, 5432, 3389, 11211, 5984, 1521, 27018]);
const MEDIUM_RECON_PORTS = new Set([2376, 8888, 9000]);

export interface ReconData {
  subdomains?: Array<{ subdomain: string; ip?: string | null; cname?: string | null; source: string }>;
  openPorts?: Array<{ port: number; service: string; banner?: string | null }>;
  dnsRecords?: Array<{ type: string; value: string; ttl?: number }>;
  reconDurationMs?: number;
}

export function ReconCard({ recon }: { recon: ReconData }) {
  const [section, setSection] = useState<"ports" | "dns" | "subdomains">("ports");

  const portCount = recon.openPorts?.length ?? 0;
  const dnsCount = recon.dnsRecords?.length ?? 0;
  const subCount = recon.subdomains?.length ?? 0;

  if (portCount === 0 && dnsCount === 0 && subCount === 0) return null;

  const tabs = [
    { key: "ports" as const,      label: "Open Ports",  count: portCount,  show: true },
    { key: "dns" as const,        label: "DNS Records", count: dnsCount,   show: dnsCount > 0 },
    { key: "subdomains" as const, label: "Subdomains",  count: subCount,   show: subCount > 0 },
  ].filter((t) => t.show);

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between p-5 border-b border-white/5">
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Network className="w-4 h-4 text-violet-400" />
          Reconnaissance
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 font-medium leading-none">
            red team
          </span>
        </h3>
        {recon.reconDurationMs != null && (
          <span className="text-[10px] text-muted-foreground font-mono">
            {(recon.reconDurationMs / 1000).toFixed(1)}s
          </span>
        )}
      </div>

      {/* Tab nav */}
      <div className="flex border-b border-white/5">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setSection(tab.key)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px",
              section === tab.key
                ? "border-violet-500 text-violet-400"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
            <span className={cn(
              "px-1.5 py-0.5 rounded-full text-[10px] font-bold",
              section === tab.key ? "bg-violet-500/20 text-violet-400" : "bg-secondary text-muted-foreground",
            )}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      <div className="p-4 max-h-72 overflow-y-auto">
        {/* Ports */}
        {section === "ports" && (
          portCount > 0 ? (
            <div className="space-y-1.5">
              {recon.openPorts!.map((p, i) => {
                const isDangerous = DANGEROUS_RECON_PORTS.has(p.port);
                const isMedium = MEDIUM_RECON_PORTS.has(p.port);
                return (
                  <div
                    key={i}
                    className={cn(
                      "flex items-start gap-3 p-2.5 rounded-lg text-xs border",
                      isDangerous ? "bg-red-500/5 border-red-500/20" :
                      isMedium   ? "bg-yellow-500/5 border-yellow-500/20" :
                                   "bg-secondary/40 border-white/5",
                    )}
                  >
                    <span className={cn(
                      "font-mono font-bold shrink-0 min-w-[3rem] text-right tabular-nums",
                      isDangerous ? "text-red-400" : isMedium ? "text-yellow-400" : "text-emerald-400",
                    )}>
                      {p.port}
                    </span>
                    <div className="flex-1 min-w-0">
                      <span className={cn(
                        "font-medium",
                        isDangerous ? "text-red-300" : isMedium ? "text-yellow-300" : "text-foreground/80",
                      )}>
                        {p.service}
                      </span>
                      {p.banner && (
                        <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate" title={p.banner}>
                          {p.banner}
                        </div>
                      )}
                    </div>
                    {isDangerous && (
                      <span className="shrink-0 px-1.5 py-0.5 bg-red-500/15 text-red-400 border border-red-500/25 rounded text-[10px] font-bold leading-none">
                        !
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No open ports detected in the scanned range.
            </div>
          )
        )}

        {/* DNS */}
        {section === "dns" && (
          dnsCount > 0 ? (
            <div className="space-y-0.5">
              {recon.dnsRecords!.map((r, i) => (
                <div key={i} className="flex items-start gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
                  <span className="shrink-0 px-1.5 py-0.5 bg-teal-500/10 border border-teal-500/20 text-teal-400 rounded font-mono text-[10px] font-bold min-w-[3rem] text-center leading-none mt-0.5">
                    {r.type}
                  </span>
                  <span className="font-mono text-muted-foreground break-all leading-relaxed">{r.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">No DNS records found.</div>
          )
        )}

        {/* Subdomains */}
        {section === "subdomains" && (
          subCount > 0 ? (
            <div className="space-y-0.5">
              {recon.subdomains!.map((s, i) => (
                <div key={i} className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
                  <Globe className="w-3 h-3 text-muted-foreground/50 shrink-0" />
                  <span className="font-mono text-foreground/80 truncate flex-1">{s.subdomain}</span>
                  {s.ip && (
                    <span className="font-mono text-muted-foreground text-[10px] shrink-0 tabular-nums">{s.ip}</span>
                  )}
                  <span className={cn(
                    "shrink-0 text-[9px] px-1 py-0.5 rounded font-medium border leading-none",
                    s.source === "crt.sh"
                      ? "bg-sky-500/10 text-sky-400/70 border-sky-500/20"
                      : "bg-secondary text-muted-foreground/50 border-white/5",
                  )}>
                    {s.source}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">No subdomains discovered.</div>
          )
        )}
      </div>
    </div>
  );
}

// ─── Agent Fix Prompt card ────────────────────────────────────────────────────

export type AgentEnvironment = "lovable" | "nextjs" | "bolt" | "wordpress" | "supabase" | "generic";

export interface AgentMeta {
  label: string;
  copyLabel: string;
  description: string;
  icon: React.ReactNode;
  accentClass: string;
}

export function getAgentMeta(agent: AgentEnvironment): AgentMeta {
  switch (agent) {
    case "lovable":
      return {
        label: "Fix in Lovable",
        copyLabel: "Copy Lovable prompt",
        description: "Paste this directly into the Lovable chat to fix all security issues at once.",
        icon: <Sparkles className="w-5 h-5 text-pink-400" />,
        accentClass: "border-t-pink-500",
      };
    case "nextjs":
      return {
        label: "Fix with Cursor / Claude Code",
        copyLabel: "Copy Cursor prompt",
        description: "Paste into Cursor Composer or Claude Code — includes exact file paths and code changes.",
        icon: <Code2 className="w-5 h-5 text-blue-400" />,
        accentClass: "border-t-blue-500",
      };
    case "bolt":
      return {
        label: "Fix in Bolt.new",
        copyLabel: "Copy Bolt.new prompt",
        description: "Paste this into Bolt.new or Replit Agent to apply all fixes with complete file updates.",
        icon: <Zap className="w-5 h-5 text-yellow-400" />,
        accentClass: "border-t-yellow-500",
      };
    case "wordpress":
      return {
        label: "Fix your WordPress site",
        copyLabel: "Copy WordPress instructions",
        description: "Follow these WordPress-specific steps — plugins to install, wp-config.php changes, and admin settings.",
        icon: <Globe className="w-5 h-5 text-sky-400" />,
        accentClass: "border-t-sky-500",
      };
    case "supabase":
      return {
        label: "Fix in Supabase",
        copyLabel: "Copy Supabase fix",
        description: "SQL policies to run in the SQL Editor, dashboard settings to change, and code updates.",
        icon: <Database className="w-5 h-5 text-emerald-400" />,
        accentClass: "border-t-emerald-500",
      };
    case "generic":
    default:
      return {
        label: "Fix with your AI agent",
        copyLabel: "Copy prompt",
        description: "Paste into Cursor, Claude, GitHub Copilot, or any coding agent to get all findings fixed at once.",
        icon: <Terminal className="w-5 h-5 text-violet-400" />,
        accentClass: "border-t-violet-500",
      };
  }
}

export function AgentFixPromptCard({ prompt, detectedAgent }: { prompt: string; detectedAgent?: string }) {
  const [copied, setCopied] = useState(false);
  const agent = (detectedAgent ?? "generic") as AgentEnvironment;
  const meta = getAgentMeta(agent);

  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(prompt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Clipboard API unavailable (insecure context or permission denied) — fail silently
    });
  }, [prompt]);

  return (
    <div className={cn("glass-card rounded-2xl p-6 border-t-4", meta.accentClass)}>
      <div className="flex items-start justify-between gap-4 mb-1">
        <h3 className="text-lg font-bold flex items-center gap-2">
          {meta.icon}
          {meta.label}
        </h3>
        {agent !== "generic" && (
          <span className="shrink-0 inline-flex items-center text-xs font-medium text-muted-foreground bg-white/5 border border-white/10 rounded-full px-2 py-0.5">
            Formatted for your stack
          </span>
        )}
      </div>
      <p className="text-xs text-muted-foreground mb-4">
        {meta.description}
      </p>
      <div className="relative mb-3 rounded-lg overflow-hidden border border-white/20 bg-black/40">
        <div className="flex items-center justify-between px-4 py-2 border-b border-white/10 bg-white/5">
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Paste-ready prompt</span>
          <button
            onClick={handleCopy}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-all duration-200",
              copied
                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                : "bg-violet-500/20 text-violet-300 border border-violet-500/30 hover:bg-violet-500/30",
            )}
          >
            {copied ? (
              <><Check className="w-3 h-3" /> Copied!</>
            ) : (
              <><Copy className="w-3 h-3" /> {meta.copyLabel}</>
            )}
          </button>
        </div>
        <div className="p-4 max-h-72 overflow-y-auto">
          <pre className="text-xs font-mono text-foreground/85 whitespace-pre-wrap leading-relaxed">{prompt}</pre>
        </div>
      </div>
    </div>
  );
}

// ─── Pages Scanned card ───────────────────────────────────────────────────────

export function PagesScannedCard({
  rootUrl,
  pagesScanned,
  probedNotFound,
}: {
  rootUrl: string;
  pagesScanned: string[];
  probedNotFound?: string[];
}) {
  const [open, setOpen] = useState(false);

  const allPages = useMemo(() => {
    const pages: { label: string; url: string; isRoot: boolean }[] = [
      { label: rootUrl, url: rootUrl, isRoot: true },
    ];
    for (const url of pagesScanned) {
      try {
        const path = new URL(url).pathname;
        pages.push({ label: path, url, isRoot: false });
      } catch {
        pages.push({ label: url, url, isRoot: false });
      }
    }
    return pages;
  }, [rootUrl, pagesScanned]);

  const notFoundPages = useMemo(() => {
    return (probedNotFound ?? []).map((url) => {
      try { return { label: new URL(url).pathname, url }; }
      catch { return { label: url, url }; }
    });
  }, [probedNotFound]);

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-white/[0.02] transition-colors"
      >
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Search className="w-4 h-4 text-sky-400" />
          Pages Scanned
          <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground">{allPages.length}</span>
          {notFoundPages.length > 0 && (
            <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground/60">
              {notFoundPages.length} not found
            </span>
          )}
        </h3>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 border-t border-white/5 pt-3 space-y-1">
              <p className="text-xs text-muted-foreground mb-3">All URLs visited during this scan, including the root page and crawled inner pages.</p>
              {allPages.map((page, i) => (
                <div key={i} className="flex items-center gap-2 py-1">
                  <Globe className={cn("w-3 h-3 shrink-0", page.isRoot ? "text-sky-400" : "text-muted-foreground/50")} />
                  <a
                    href={page.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-muted-foreground hover:text-foreground transition-colors truncate"
                    title={page.url}
                  >
                    {page.label}
                  </a>
                  {page.isRoot && (
                    <span className="shrink-0 text-[9px] px-1 py-0.5 bg-sky-500/10 text-sky-400/70 border border-sky-500/20 rounded font-medium leading-none">
                      root
                    </span>
                  )}
                </div>
              ))}

              {notFoundPages.length > 0 && (
                <div className="mt-4 pt-3 border-t border-white/5">
                  <p className="text-xs text-muted-foreground/60 mb-2 font-medium">Probed (not found)</p>
                  {notFoundPages.map((page, i) => (
                    <div key={i} className="flex items-center gap-2 py-1">
                      <Minus className="w-3 h-3 shrink-0 text-muted-foreground/30" />
                      <span
                        className="text-xs font-mono text-muted-foreground/40 truncate"
                        title={page.url}
                      >
                        {page.label}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Software Inventory card ──────────────────────────────────────────────────

export function SoftwareInventoryCard({
  technologies,
  vulnerabilities,
}: {
  technologies: string[];
  vulnerabilities: Vulnerability[];
}) {
  const versionedTechs = useMemo(() => {
    const seen = new Set<string>();
    return technologies
      .map(parseTechVersion)
      .filter((t) => {
        if (t.version === null) return false;
        const key = `${t.name.toLowerCase()}@${t.version.toLowerCase()}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }, [technologies]);

  // Count CVEs per tech by matching vuln names like "jQuery 1.11.3 — Known Vulnerability ..."
  // or evidence lines like "Detected: jQuery 1.11.3" as a fallback
  const cveCountFor = useCallback(
    (name: string, version: string) => {
      const namePrefix = `${name.toLowerCase()} ${version.toLowerCase()} \u2014`; // em dash separator
      const evidenceTag = `detected: ${name.toLowerCase()} ${version.toLowerCase()}`;
      return vulnerabilities.filter((v) =>
        v.name.toLowerCase().startsWith(namePrefix) ||
        (v.evidence?.toLowerCase().includes(evidenceTag) ?? false)
      ).length;
    },
    [vulnerabilities],
  );

  const cveTotal = useMemo(
    () => versionedTechs.reduce((sum, t) => sum + cveCountFor(t.name, t.version!), 0),
    [versionedTechs, cveCountFor],
  );

  const [open, setOpen] = useState(() => cveTotal > 0);

  if (versionedTechs.length === 0) return null;

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-white/[0.02] transition-colors"
      >
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Package className="w-4 h-4 text-yellow-400" />
          Software Inventory
          <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground">{versionedTechs.length}</span>
          {cveTotal > 0 && (
            <span className="flex items-center gap-1 text-[11px] font-semibold text-red-400 bg-red-950/60 px-2 py-0.5 rounded-full border border-red-500/25 leading-none">
              <AlertTriangle className="w-3 h-3" />
              {cveTotal} CVE{cveTotal !== 1 ? "s" : ""}
            </span>
          )}
        </h3>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 space-y-2 border-t border-white/5 pt-3">
              <p className="text-xs text-muted-foreground mb-3">Versioned components found during the scan that were checked for known CVEs.</p>
              {versionedTechs.map((t, i) => {
                const cveCount = cveCountFor(t.name, t.version!);
                return (
                  <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-foreground/90">{t.name}</span>
                      <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] font-mono rounded border border-yellow-500/20 leading-none">
                        {t.version}
                      </span>
                    </div>
                    {cveCount > 0 ? (
                      <span className="flex items-center gap-1 text-xs font-semibold text-red-400 bg-red-950/50 px-2 py-0.5 rounded-full border border-red-500/20">
                        <AlertTriangle className="w-3 h-3" /> {cveCount} CVE{cveCount !== 1 ? "s" : ""}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">No CVEs found</span>
                    )}
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Grouped category section ─────────────────────────────────────────────────

export function CategorySection({
  category,
  vulns,
  defaultOpen = true,
  needsVerification = false,
  globalIndex,
  rootUrl,
}: {
  category: string;
  vulns: Vulnerability[];
  defaultOpen?: boolean;
  needsVerification?: boolean;
  globalIndex: number;
  rootUrl?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = getCategoryMeta(category);

  const highestSeverity = vulns.reduce<string | null>((acc, v) => {
    if (acc === null) return v.severity;
    return (SEVERITY_ORDER[v.severity] ?? 99) < (SEVERITY_ORDER[acc] ?? 99) ? v.severity : acc;
  }, null);

  return (
    <div className="rounded-xl overflow-hidden border border-white/5 bg-secondary/10">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={`${meta.label} — ${vulns.length} finding${vulns.length !== 1 ? "s" : ""}, ${open ? "collapse" : "expand"}`}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.03] transition-colors text-left"
      >
        <span className={meta.color}>{meta.icon}</span>
        <span className="font-bold text-sm text-foreground flex-1">{meta.label}</span>
        {highestSeverity && (
          <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border shrink-0", getSeverityColors(highestSeverity))}>
            {highestSeverity}
          </span>
        )}
        <span className="text-xs font-bold bg-secondary rounded-full w-6 h-6 flex items-center justify-center text-muted-foreground shrink-0">
          {vulns.length}
        </span>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform shrink-0", open && "rotate-180")} />
      </button>

      {open && (
        <div className="px-3 pb-3 pt-1 space-y-2 border-t border-white/5">
          {vulns.map((v, i) => (
            <VulnCard
              key={v.id}
              vuln={v}
              index={globalIndex + i}
              needsVerification={needsVerification}
              rootUrl={rootUrl}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Category filter pill ─────────────────────────────────────────────────────

export function CategoryPill({
  category, count, active, onClick,
}: { category: string; count: number; active: boolean; onClick: () => void }) {
  const meta = getCategoryMeta(category);
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all",
        active
          ? "bg-primary/15 border-primary/40 text-foreground"
          : "bg-secondary/50 border-white/5 text-muted-foreground hover:border-white/15 hover:text-foreground",
      )}
    >
      <span className={cn(active ? "text-primary" : meta.color)}>{meta.icon}</span>
      <span>{meta.label}</span>
      <span className={cn(
        "ml-1 rounded-full px-1.5 py-0.5 font-bold",
        active ? "bg-primary/20 text-primary" : "bg-white/10 text-muted-foreground",
      )}>{count}</span>
    </button>
  );
}

// ─── Summary new-findings callout ─────────────────────────────────────────────

export const NEW_CATEGORY_LABELS: Record<string, string> = {
  "Email Security":                  "email spoofing risks",
  "Source Code Exposure":            "exposed source code",
  "Credential Exposure":             "exposed credentials",
  "Data Exposure":                   "exposed data files",
  "Exposed Secrets / Credentials":   "hardcoded secrets in JavaScript",
  "CORS Misconfiguration":           "CORS bypass issues",
  "Unvalidated Redirects":           "open redirect vulnerabilities",
  "HTTP Security":                   "dangerous HTTP methods",
  "Supply Chain Security":           "supply chain weaknesses",
  "Session Management":              "JWT / session token weaknesses",
  "Brute Force Protection":          "missing rate limiting",
  "DNS Security":                    "DNS / subdomain takeover risks",
  "Information Disclosure":          "information disclosure (robots.txt, error pages, exposed files)",
  "Transport Security":              "transport security issues (HTTP redirect, HSTS)",
  "UI Security":                     "UI security gaps (clickjacking protection)",
  "Security Header Inconsistency":   "header inconsistencies across pages",
  "Outdated Software / Known CVE":   "outdated software with known CVEs",
};

export function SummaryNewFindings({ categories }: { categories: Record<string, number> }) {
  const notable = Object.entries(NEW_CATEGORY_LABELS)
    .filter(([cat]) => (categories[cat] ?? 0) > 0)
    .map(([, label]) => label);

  if (notable.length === 0) return null;

  return (
    <div className="mt-4 p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 text-sm text-amber-200/80 leading-relaxed">
      <span className="font-semibold text-amber-300">Also detected: </span>
      {notable.join(", ")}.
    </div>
  );
}
