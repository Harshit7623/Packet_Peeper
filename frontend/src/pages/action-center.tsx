import { useMemo, useState } from "react";
import { useLocation } from "wouter";
import {
  Activity,
  ArrowRight,
  Download,
  ShieldAlert,
  ShieldCheck,
  Search,
  Power,
  Settings,
  Wifi,
} from "lucide-react";
import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { socketService } from "@/services/socketService";
import { useToast } from "@/hooks/use-toast";
import { AIHealthWidget } from "@/components/AIAssistant";

export default function ActionCenter() {
  const { alerts, devices, stats, isSniffing, setSniffing } = useMonitorStore();
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [scanning, setScanning] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [toggling, setToggling] = useState(false);

  const criticalCount = alerts.filter((alert) => alert.severity === "critical").length;
  const highCount = alerts.filter((alert) => alert.severity === "high").length;
  const mediumCount = alerts.filter((alert) => alert.severity === "medium").length;

  const actionItems = useMemo(() => {
    const items = [] as Array<{
      id: string;
      title: string;
      description: string;
      status: "critical" | "warning" | "clear";
      cta: string;
      icon: typeof ShieldAlert;
      onClick: () => void | Promise<void>;
    }>;

    if (criticalCount > 0) {
      items.push({
        id: "critical-alerts",
        title: "Critical alerts need action",
        description: `${criticalCount} critical alerts are waiting for review and remediation guidance.`,
        status: "critical",
        cta: "Review alerts",
        icon: ShieldAlert,
        onClick: () => setLocation("/alerts"),
      });
    } else {
      items.push({
        id: "all-clear",
        title: "No critical threats detected",
        description: "Your network is stable. Keep monitoring and run periodic scans.",
        status: "clear",
        cta: "View alerts",
        icon: ShieldCheck,
        onClick: () => setLocation("/alerts"),
      });
    }

    items.push({
      id: "scan-network",
      title: "Scan for new devices",
      description: "Run a fresh scan to catch unknown or recently connected devices.",
      status: devices.length === 0 ? "warning" : "clear",
      cta: scanning ? "Scanning..." : "Scan network",
      icon: Search,
      onClick: async () => {
        if (scanning) return;
        setScanning(true);
        try {
          const result = await apiService.scanNetwork();
          toast({
            title: "Network scan started",
            description: result.message ?? "Scanning for devices...",
          });
        } catch {
          toast({
            title: "Scan failed",
            description: "Unable to scan right now. Please try again.",
            variant: "destructive",
          });
        } finally {
          setScanning(false);
        }
      },
    });

    items.push({
      id: "monitoring",
      title: isSniffing ? "Monitoring active" : "Monitoring paused",
      description: isSniffing
        ? "Packet capture is running. Stop if you need a quiet window."
        : "Resume monitoring to keep visibility on your network.",
      status: isSniffing ? "clear" : "warning",
      cta: toggling ? "Updating..." : isSniffing ? "Pause monitoring" : "Start monitoring",
      icon: Activity,
      onClick: async () => {
        if (toggling) return;
        setToggling(true);
        try {
          if (isSniffing) {
            socketService.stopSniffing();
            setSniffing(false, null);
          } else {
            socketService.startSniffing("auto");
            setSniffing(true, "auto");
          }
        } finally {
          setToggling(false);
        }
      },
    });

    items.push({
      id: "export-report",
      title: "Download a safety report",
      description: "Capture alerts and traffic stats for support or audits.",
      status: "clear",
      cta: exporting ? "Exporting..." : "Export report",
      icon: Download,
      onClick: async () => {
        if (exporting) return;
        setExporting(true);
        try {
          await apiService.downloadReport("json");
          toast({
            title: "Report ready",
            description: "Your security report has been downloaded.",
          });
        } catch {
          toast({
            title: "Export failed",
            description: "Unable to generate a report right now.",
            variant: "destructive",
          });
        } finally {
          setExporting(false);
        }
      },
    });

    items.push({
      id: "secure-settings",
      title: "Review protection settings",
      description: "Confirm alert preferences and auto-blocking rules.",
      status: "warning",
      cta: "Open settings",
      icon: Settings,
      onClick: () => setLocation("/settings"),
    });

    return items;
  }, [criticalCount, devices.length, exporting, isSniffing, scanning, setLocation, setSniffing, toast, toggling]);

  const totalPackets = stats?.totalPackets || stats?.total_packets || 0;

  const summaryBadges = [
    { label: "Critical", value: criticalCount, color: "text-red-400 border-red-500/40" },
    { label: "High", value: highCount, color: "text-orange-400 border-orange-500/40" },
    { label: "Medium", value: mediumCount, color: "text-amber-400 border-amber-500/40" },
  ];

  return (
    <MainLayout>
      <div className="space-y-8">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="text-xs font-mono tracking-[0.35em] text-primary">ACTION CENTER</div>
            <h1 className="mt-2 text-3xl font-black text-foreground">Guided Response Plan</h1>
            <p className="mt-2 text-sm text-muted-foreground max-w-2xl">
              Prioritized actions for keeping your network safe, based on what Packet Peeper sees right now.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {summaryBadges.map((badge) => (
              <Badge key={badge.label} variant="outline" className={`px-3 py-1 ${badge.color}`}>
                {badge.label}: {badge.value}
              </Badge>
            ))}
            <Badge variant="outline" className="px-3 py-1 text-cyan-300 border-cyan-500/40">
              Devices: {devices.length}
            </Badge>
            <Badge variant="outline" className="px-3 py-1 text-primary border-primary/40">
              Packets: {totalPackets.toLocaleString()}
            </Badge>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
          <div className="space-y-4">
            {actionItems.map((item) => {
              const Icon = item.icon;
              const statusStyles =
                item.status === "critical"
                  ? "border-red-500/40 bg-red-500/10"
                  : item.status === "warning"
                  ? "border-amber-500/40 bg-amber-500/10"
                  : "border-emerald-500/30 bg-emerald-500/10";

              return (
                <Card key={item.id} className={`border ${statusStyles} rounded-2xl`}> 
                  <CardContent className="p-6 flex flex-col gap-4">
                    <div className="flex items-start gap-4">
                      <div className="h-12 w-12 rounded-xl bg-background/50 flex items-center justify-center">
                        <Icon className="h-6 w-6 text-foreground" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-foreground">{item.title}</h3>
                        <p className="text-sm text-muted-foreground mt-1">{item.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="text-xs uppercase tracking-[0.2em]">
                        {item.status === "critical" ? "Immediate" : item.status === "warning" ? "Soon" : "Stable"}
                      </Badge>
                      <Button
                        onClick={item.onClick}
                        className="rounded-full px-5"
                        variant={item.status === "critical" ? "default" : "outline"}
                      >
                        {item.cta}
                        <ArrowRight className="ml-2 h-4 w-4" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <div className="space-y-6">
            <AIHealthWidget />

            <Card className="border-border/60 rounded-2xl bg-card/60">
              <CardHeader>
                <CardTitle className="text-lg">Live Snapshot</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Wifi className="h-4 w-4" />
                    Devices online
                  </div>
                  <span className="font-semibold text-foreground">{devices.length}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Power className="h-4 w-4" />
                    Monitoring status
                  </div>
                  <span className={`font-semibold ${isSniffing ? "text-emerald-400" : "text-amber-400"}`}>
                    {isSniffing ? "Active" : "Paused"}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <ShieldAlert className="h-4 w-4" />
                    Alerts awaiting review
                  </div>
                  <span className="font-semibold text-foreground">{alerts.length}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Activity className="h-4 w-4" />
                    Current bandwidth
                  </div>
                  <span className="font-semibold text-foreground">
                    {((stats?.currentBandwidth || 0) / 1024 / 1024).toFixed(2)} MB/s
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 rounded-2xl bg-card/60">
              <CardHeader>
                <CardTitle className="text-lg">Security Playbook</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-muted-foreground">
                <p>1. Review critical alerts first and follow guided remediation steps.</p>
                <p>2. Scan for unknown devices after any threat spike.</p>
                <p>3. Export reports weekly for your records.</p>
                <p>4. Keep router firmware and passwords updated.</p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
