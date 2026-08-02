import { useState } from "react";
import { useLocation } from "wouter";
import { useCreateScan, useGetCredits } from "@workspace/api-client-react";
import { Shield, Zap, Globe, Lock, CheckCircle2, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ScanTier } from "@workspace/api-client-react";

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/<!DOCTYPE|<html|<head|<body/i.test(msg)) return "Server is unavailable right now. Please wait a moment and try again.";
  if (/failed to fetch|networkerror|load failed/i.test(msg)) return "Could not reach the server. Check your connection and try again.";
  if (/invalid url/i.test(msg)) return msg;
  if (/unauthorized|401/i.test(msg)) return "Session token missing. Please refresh the page and try again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 120 ? clean.slice(0, 120) + "…" : clean;
}

type TierConfig = {
  id: ScanTier;
  name: string;
  desc: string;
  features: string[];
  popular?: boolean;
};

const TIERS: TierConfig[] = [
  {
    id: "basic",
    name: "Basic Scan",
    desc: "Core OWASP checks and headers",
    features: ["Header analysis", "SSL/TLS grading", "Tech fingerprint"],
  },
  {
    id: "deep",
    name: "Deep Scan",
    desc: "Full analysis + AI-powered report",
    features: ["Everything in Basic", "AI security analysis", "Remediation guide"],
    popular: true,
  },
];

export default function ScanFormPage() {
  const [url, setUrl] = useState("");
  const [tier, setTier] = useState<ScanTier>("deep");
  const [, setLocation] = useLocation();

  const { data: credits, isLoading: loadingCredits } = useGetCredits();
  const createScan = useCreateScan();

  const selectedTier = TIERS.find((t) => t.id === tier);
  const hasCredits = credits && credits.balance > 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    let targetUrl = url;
    if (!url.trim()) return;
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = "https://" + targetUrl;
    }

    createScan.mutate(
      { data: { targetUrl, tier } },
      {
        onSuccess: (data) => {
          if (data.checkoutUrl) {
            window.location.href = data.checkoutUrl;
          } else {
            setLocation(`/scan/${data.scanId}`);
          }
        },
      },
    );
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-10">
        <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-6 border border-primary/20">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">
          Launch Security Scan
        </h1>
        <p className="text-muted-foreground text-lg">
          Paste any publicly accessible URL — your app, a client's site, or any live website.
        </p>
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl">
        <form onSubmit={handleSubmit} className="flex flex-col gap-10">
          {/* URL Input */}
          <div className="flex flex-col gap-3">
            <label htmlFor="url" className="text-sm font-semibold flex items-center gap-2">
              <Globe className="w-4 h-4 text-primary" /> Target URL
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Lock className="w-5 h-5 text-muted-foreground" />
              </div>
              <input
                id="url"
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full bg-background border-2 border-white/10 rounded-xl py-4 pl-12 pr-4 text-lg focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-muted-foreground/50"
              />
            </div>
            <p className="text-xs text-muted-foreground ml-1">
              Any publicly accessible website works. Only scan sites you have permission to test.
            </p>
          </div>

          {/* Tier Selection */}
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <label className="text-sm font-semibold flex items-center gap-2">
                <Zap className="w-4 h-4 text-primary" /> Scan Depth
              </label>

              {!loadingCredits && hasCredits && (
                <div className="flex items-center gap-1.5 px-3 py-1 bg-primary/10 border border-primary/20 rounded-full text-xs font-medium text-primary">
                  <Zap className="w-3.5 h-3.5" />
                  {credits.balance} Credit{credits.balance !== 1 ? "s" : ""} Available
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {TIERS.map((t) => (
                <label
                  key={t.id}
                  className={cn(
                    "relative flex flex-col p-5 rounded-2xl cursor-pointer transition-all border-2",
                    tier === t.id
                      ? "bg-primary/5 border-primary shadow-[0_0_20px_rgba(20,184,120,0.15)]"
                      : "bg-secondary/50 border-white/5 hover:bg-secondary hover:border-white/10",
                  )}
                >
                  <input
                    type="radio"
                    name="tier"
                    value={t.id}
                    checked={tier === t.id}
                    onChange={() => setTier(t.id)}
                    className="sr-only"
                  />
                  {t.popular && (
                    <span className="absolute -top-3 right-4 px-2 py-0.5 bg-primary text-primary-foreground text-[10px] font-bold uppercase tracking-wider rounded-full">
                      Recommended
                    </span>
                  )}
                  <div className="mb-2">
                    <div className="font-bold text-lg">{t.name}</div>
                    <div className="text-sm text-muted-foreground">{t.desc}</div>
                  </div>
                  <ul className="mt-4 flex flex-col gap-1.5 flex-1">
                    {t.features.map((f, i) => (
                      <li key={i} className="text-xs flex items-center gap-1.5 text-muted-foreground">
                        <CheckCircle2 className="w-3.5 h-3.5 text-primary/70 shrink-0" /> {f}
                      </li>
                    ))}
                  </ul>

                  <div
                    className={cn(
                      "mt-5 w-full py-2 rounded-lg text-center text-sm font-semibold transition-colors",
                      tier === t.id
                        ? "bg-primary text-primary-foreground"
                        : "bg-white/5 text-muted-foreground",
                    )}
                  >
                    {tier === t.id ? "Selected" : "Select"}
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Submit */}
          <div className="pt-6 border-t border-white/5 flex flex-col items-center gap-4">
            <button
              type="submit"
              disabled={createScan.isPending || !url.trim()}
              className="w-full sm:w-auto min-w-[260px] px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center gap-2"
            >
              {createScan.isPending ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" /> Processing...
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" /> {selectedTier?.id === "deep" ? "Run Deep Scan" : "Run Basic Scan"}
                </>
              )}
            </button>

            {createScan.isError && (
              <p className="text-red-400 text-sm text-center">
                {getFriendlyError(createScan.error)}
              </p>
            )}

            <p className="text-xs text-muted-foreground text-center">
              Only scan sites you own or have explicit permission to test.
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
