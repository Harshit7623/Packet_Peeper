import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { AlertTriangle, Shield, CheckCircle, Clock, Filter, Info, Trash2, Zap, Radio, ShieldAlert, ShieldCheck, Bell, Activity, Eye, XCircle, Bot, Sparkles, Loader2, X, ChevronDown, Search } from "lucide-react";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AIHelpButton, AIHealthWidget } from "@/components/AIAssistant";
import { SystemStatusBar } from "@/components/SystemStatusBar";
import { cn } from "@/lib/utils";

interface AlertFilter {
  severity: string;
  alert_type: string;
  source_ip: string;
  search: string;
  resolved: string;
}

const ALERT_TYPE_OPTIONS = ['all', 'port_scan', 'ddos', 'brute_force', 'dns_tunneling', 'suspicious_traffic', 'anomaly'];
const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'];
const RESOLVED_OPTIONS = ['all', 'true', 'false'];

export default function Alerts() {
  const { alerts, setAlerts, clearAlerts } = useMonitorStore();
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [isScanning, setIsScanning] = useState(true);
  const [newAlertFlash, setNewAlertFlash] = useState(false);
  const [dismissingId, setDismissingId] = useState<number | null>(null);
  const [isClearing, setIsClearing] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [alertFilters, setAlertFilters] = useState<AlertFilter>({
    severity: 'all', alert_type: 'all', source_ip: '', search: '', resolved: 'all',
  });
  const [serverAlerts, setServerAlerts] = useState<any[]>([]);
  const [serverTotal, setServerTotal] = useState(0);
  const [isFiltering, setIsFiltering] = useState(false);
  const [useServerFilter, setUseServerFilter] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setIsScanning(prev => !prev);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (alerts.length > 0) {
      setNewAlertFlash(true);
      const timer = setTimeout(() => setNewAlertFlash(false), 1000);
      return () => clearTimeout(timer);
    }
  }, [alerts.length]);

  const applyServerFilters = useCallback(async () => {
    const hasFilters = alertFilters.severity !== 'all'
      || alertFilters.alert_type !== 'all'
      || alertFilters.source_ip
      || alertFilters.search
      || alertFilters.resolved !== 'all';

    if (!hasFilters) {
      setUseServerFilter(false);
      setServerAlerts([]);
      setServerTotal(0);
      return;
    }

    setIsFiltering(true);
    setUseServerFilter(true);
    try {
      const params: any = { limit: 200 };
      if (alertFilters.severity !== 'all') params.severity = alertFilters.severity;
      if (alertFilters.alert_type !== 'all') params.alert_type = alertFilters.alert_type;
      if (alertFilters.source_ip) params.source_ip = alertFilters.source_ip;
      if (alertFilters.search) params.search = alertFilters.search;
      if (alertFilters.resolved !== 'all') params.resolved = alertFilters.resolved === 'true';

      const result = await apiService.getAlerts(params);
      setServerAlerts(result.data || []);
      setServerTotal(result.total || 0);
    } catch (err) {
      console.error('Server filter failed:', err);
    } finally {
      setIsFiltering(false);
    }
  }, [alertFilters]);

  useEffect(() => {
    const timer = setTimeout(applyServerFilters, 300);
    return () => clearTimeout(timer);
  }, [applyServerFilters]);

  const handleDismissAlert = async (alertId: number) => {
    setDismissingId(alertId);
    try {
      await apiService.dismissAlert(alertId);
    } catch (err: any) {
      if (err?.status === 401) {
        setDismissingId(null);
        return;
      }
      console.error('Failed to dismiss alert:', err);
      setDismissingId(null);
      return;
    }
    setTimeout(() => {
      setAlerts(alerts.filter(a => a.id !== alertId));
      setDismissingId(null);
    }, 300);
  };

  const handleClearAll = async () => {
    if (alerts.length === 0) return;

    const confirmed = window.confirm('Are you sure you want to clear all alerts?');
    if (!confirmed) return;

    setIsClearing(true);
    try {
      await apiService.clearAlerts();
    } catch (err: any) {
      if (err?.status === 401) {
        alert('Session expired. Please log in again.');
      } else {
        console.error('Failed to clear alerts:', err);
        alert('Failed to clear alerts. Please try again.');
      }
      setIsClearing(false);
      return;
    }
    clearAlerts();
    setAlerts([]);
    setIsClearing(false);
  };

  const clearFilters = () => {
    setAlertFilters({ severity: 'all', alert_type: 'all', source_ip: '', search: '', resolved: 'all' });
    setFilter('all');
    setUseServerFilter(false);
    setServerAlerts([]);
    setServerTotal(0);
  };

  const hasActiveFilters = alertFilters.severity !== 'all'
    || alertFilters.alert_type !== 'all'
    || alertFilters.source_ip
    || alertFilters.search
    || alertFilters.resolved !== 'all';

  const mapAlert = (a: any) => ({
    id: a.id,
    type: a.type || a.alert_type,
    alert_type: a.alert_type || a.type,
    severity: a.severity,
    title: a.title,
    description: a.description,
    source: a.source || a.source_ip,
    time: new Date(a.timestamp).toLocaleTimeString(),
    status: a.severity === 'critical' ? 'Action Required' : 'Review',
    recommendation: a.additional_info?.recommendation || 'Review this alert for more details.',
    evidence: a.evidence || a.additional_info?.evidence || {}
  });

  const baseAlerts = useServerFilter
    ? serverAlerts.map(mapAlert)
    : alerts.map(mapAlert);

  const displayAlerts = (!useServerFilter && filter !== 'all')
    ? baseAlerts.filter(a => a.severity === filter)
    : baseAlerts;

  const criticalCount = baseAlerts.filter(a => a.severity === 'critical').length;
  const highCount = baseAlerts.filter(a => a.severity === 'high').length;
  const mediumCount = baseAlerts.filter(a => a.severity === 'medium').length;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return { bg: 'bg-red-500', text: 'text-red-400', glow: 'shadow-[0_0_20px_rgba(239,68,68,0.5)]', border: 'border-red-500/50' };
      case 'high': return { bg: 'bg-orange-500', text: 'text-orange-400', glow: 'shadow-[0_0_15px_rgba(249,115,22,0.4)]', border: 'border-orange-500/50' };
      case 'medium': return { bg: 'bg-amber-500', text: 'text-amber-400', glow: '', border: 'border-amber-500/50' };
      default: return { bg: 'bg-blue-500', text: 'text-blue-400', glow: '', border: 'border-blue-500/50' };
    }
  };

  return (
    <MainLayout>
      <div className="flex flex-col gap-6">
        <motion.div
          className="flex flex-col md:flex-row md:items-center justify-between gap-4"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div>
            <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
              <ShieldAlert className="text-primary" />
              Security Center
              <motion.div
                className="flex items-center gap-2 ml-4 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30"
                animate={{ opacity: isScanning ? [1, 0.5, 1] : 1 }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-xs font-medium text-emerald-400">LIVE</span>
              </motion.div>
            </h1>
            <p className="text-muted-foreground text-lg flex items-center gap-2 mt-1">
              <Activity size={16} className="text-primary animate-pulse" />
              Real-time threat detection active
            </p>
          </div>

          <motion.div
            className="flex flex-wrap gap-2"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            {['all', 'critical', 'high', 'medium'].map((f) => (
              <Button
                key={f}
                variant={filter === f ? 'default' : 'outline'}
                size="sm"
                className={`rounded-full transition-all ${filter === f ? 'shadow-lg' : ''}`}
                onClick={() => setFilter(f as any)}
              >
                {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
                {f !== 'all' && (
                  <span className="ml-1.5 px-1.5 py-0.5 rounded-full bg-white/10 text-[10px]">
                    {f === 'critical' ? criticalCount : f === 'high' ? highCount : mediumCount}
                  </span>
                )}
              </Button>
            ))}
            <Button
              variant={showFilters ? "default" : "outline"}
              size="sm"
              className="rounded-full gap-1"
              onClick={() => setShowFilters(!showFilters)}
            >
              <Filter size={14} />
              {hasActiveFilters && (
                <span className="px-1.5 py-0.5 rounded-full bg-primary text-[10px] text-primary-foreground font-bold">Active</span>
              )}
              <ChevronDown size={14} className={cn("transition-transform", showFilters && "rotate-180")} />
            </Button>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" className="rounded-full gap-1 text-muted-foreground" onClick={clearFilters}>
                <X size={14} /> Clear
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              className="rounded-full text-destructive hover:text-destructive border-destructive/30 hover:border-destructive/50 disabled:opacity-50"
              onClick={handleClearAll}
              disabled={isClearing || alerts.length === 0}
            >
              {isClearing ? (
                <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Clearing...</>
              ) : (
                <><Trash2 className="mr-2 h-4 w-4" /> Clear All</>
              )}
            </Button>
          </motion.div>
        </motion.div>

        <AnimatePresence>
          {showFilters && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <Card className="p-4 bg-card/40 border-border/50 rounded-2xl">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-1 block">Severity</label>
                    <Select value={alertFilters.severity} onValueChange={(v) => setAlertFilters(f => ({ ...f, severity: v }))}>
                      <SelectTrigger className="h-8 text-xs rounded-lg bg-black/20 border-none">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITY_OPTIONS.map(s => (
                          <SelectItem key={s} value={s}>{s === 'all' ? 'All Severities' : s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-1 block">Alert Type</label>
                    <Select value={alertFilters.alert_type} onValueChange={(v) => setAlertFilters(f => ({ ...f, alert_type: v }))}>
                      <SelectTrigger className="h-8 text-xs rounded-lg bg-black/20 border-none">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ALERT_TYPE_OPTIONS.map(t => (
                          <SelectItem key={t} value={t}>{t === 'all' ? 'All Types' : t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-1 block">Source IP</label>
                    <Input
                      placeholder="e.g. 192.168.1"
                      className="h-8 text-xs font-mono bg-black/20 rounded-lg border-none"
                      value={alertFilters.source_ip}
                      onChange={(e) => setAlertFilters(f => ({ ...f, source_ip: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-1 block">Search</label>
                    <div className="relative">
                      <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
                      <Input
                        placeholder="Search alerts..."
                        className="h-8 text-xs pl-7 bg-black/20 rounded-lg border-none"
                        value={alertFilters.search}
                        onChange={(e) => setAlertFilters(f => ({ ...f, search: e.target.value }))}
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-1 block">Resolved</label>
                    <Select value={alertFilters.resolved} onValueChange={(v) => setAlertFilters(f => ({ ...f, resolved: v }))}>
                      <SelectTrigger className="h-8 text-xs rounded-lg bg-black/20 border-none">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RESOLVED_OPTIONS.map(r => (
                          <SelectItem key={r} value={r}>{r === 'all' ? 'Any Status' : r === 'true' ? 'Resolved' : 'Unresolved'}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        <SystemStatusBar />

        <div className="grid gap-4 md:grid-cols-4">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.1 }}>
            <Card className={`rounded-2xl overflow-hidden transition-all hover:scale-[1.02] ${
              criticalCount > 0 || highCount > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'
            }`}>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <motion.div
                    className={`p-3 rounded-xl ${criticalCount > 0 || highCount > 0 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}
                    animate={criticalCount > 0 ? { scale: [1, 1.1, 1] } : {}}
                    transition={{ duration: 1, repeat: Infinity }}
                  >
                    {criticalCount > 0 || highCount > 0 ? <ShieldAlert size={24} /> : <ShieldCheck size={24} />}
                  </motion.div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Network Status</p>
                    <p className={`text-xl font-bold ${criticalCount > 0 ? 'text-red-400' : highCount > 0 ? 'text-orange-400' : 'text-emerald-400'}`}>
                      {criticalCount > 0 ? 'Critical Threats' : highCount > 0 ? 'Needs Attention' : 'All Clear'}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.2 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl hover:border-red-500/30 transition-all hover:scale-[1.02]">
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <motion.div
                    className="p-3 bg-red-500/20 rounded-xl text-red-400"
                    animate={criticalCount > 0 ? { rotate: [0, -10, 10, 0] } : {}}
                    transition={{ duration: 0.5, repeat: criticalCount > 0 ? Infinity : 0, repeatDelay: 2 }}
                  >
                    <AlertTriangle size={24} />
                  </motion.div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Critical</p>
                    <p className="text-2xl font-bold text-foreground">{criticalCount}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl hover:border-orange-500/30 transition-all hover:scale-[1.02]">
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <div className="p-3 bg-orange-500/20 rounded-xl text-orange-400">
                    <Zap size={24} />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">High Priority</p>
                    <p className="text-2xl font-bold text-foreground">{highCount}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.4 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl hover:border-primary/30 transition-all hover:scale-[1.02]">
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <motion.div
                    className="p-3 bg-primary/20 rounded-xl text-primary"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
                  >
                    <Radio size={24} />
                  </motion.div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Scanning</p>
                    <p className="text-2xl font-bold text-foreground">Active</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between px-2">
            <h2 className="text-xl font-bold text-foreground flex items-center gap-2">
              <Bell className="text-primary" /> Recent Activity
              {newAlertFlash && (
                <motion.span
                  className="px-2 py-0.5 rounded-full bg-primary text-xs font-bold text-white"
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0 }}
                >NEW</motion.span>
              )}
            </h2>
            <span className="text-sm text-muted-foreground">
              Showing {displayAlerts.length} of {useServerFilter ? serverTotal : baseAlerts.length} alerts
            </span>
          </div>

          <AnimatePresence mode="popLayout">
            {isFiltering ? (
              <motion.div
                className="p-12 text-center"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <motion.div
                  className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4"
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                >
                  <Filter className="text-primary" size={24} />
                </motion.div>
                <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest">Applying filters...</p>
              </motion.div>
            ) : displayAlerts.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-center py-16"
              >
                <motion.div animate={{ scale: [1, 1.05, 1] }} transition={{ duration: 2, repeat: Infinity }}>
                  <ShieldCheck size={64} className="text-emerald-500 mx-auto mb-4" />
                </motion.div>
                <h3 className="text-xl font-bold text-foreground mb-2">All Clear!</h3>
                <p className="text-muted-foreground">No security threats detected. Your network is protected.</p>
              </motion.div>
            ) : (
              displayAlerts.map((alert, index) => {
                const colors = getSeverityColor(alert.severity);
                const isBeingDismissed = dismissingId === alert.id;

                return (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -50, height: 0 }}
                    animate={{
                      opacity: isBeingDismissed ? 0 : 1,
                      x: isBeingDismissed ? 100 : 0,
                      height: 'auto'
                    }}
                    exit={{ opacity: 0, x: 100, height: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    layout
                  >
                    <Card className={`bg-card/40 border-l-4 ${colors.border} rounded-2xl overflow-hidden hover:bg-card/60 transition-all group ${
                      alert.severity === 'critical' ? 'animate-pulse-subtle' : ''
                    }`}>
                      <CardContent className="p-0">
                        <div className="flex flex-col md:flex-row">
                          <div className={`w-full md:w-1 h-1 md:h-auto ${colors.bg}`} />
                          <div className="flex-1 p-6">
                            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                              <div className="flex items-start gap-4">
                                <motion.div
                                  className={`p-3 rounded-xl ${colors.bg}/20 ${colors.text} shrink-0`}
                                  animate={alert.severity === 'critical' ? {
                                    scale: [1, 1.15, 1],
                                    rotate: [0, -5, 5, 0]
                                  } : {}}
                                  transition={{ duration: 1.5, repeat: Infinity }}
                                >
                                  {alert.severity === 'critical' ? (
                                    <AlertTriangle size={24} />
                                  ) : alert.severity === 'high' ? (
                                    <Zap size={24} />
                                  ) : (
                                    <Info size={24} />
                                  )}
                                </motion.div>

                                <div className="space-y-2">
                                  <div className="flex flex-wrap items-center gap-3">
                                    <h3 className="text-lg font-bold text-foreground group-hover:text-primary transition-colors">
                                      {alert.title}
                                    </h3>
                                    <Badge
                                      variant={alert.severity === 'critical' ? 'destructive' : 'secondary'}
                                      className={`rounded-full ${alert.severity === 'critical' ? colors.glow : ''}`}
                                    >
                                      {alert.status}
                                    </Badge>
                                    <Badge variant="outline" className="rounded-full text-xs">
                                      {alert.source}
                                    </Badge>
                                    <Badge variant="outline" className="rounded-full text-xs bg-primary/10 text-primary border-primary/30">
                                      {alert.type?.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()) || 'Security Alert'}
                                    </Badge>
                                  </div>
                                  <p className="text-muted-foreground">{alert.description}</p>
                                  <div className="flex flex-wrap items-center gap-4 pt-2">
                                    <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                                      <Clock size={14} /> {alert.time}
                                    </div>
                                    <div className="flex items-center gap-1.5 text-xs font-medium text-primary">
                                      <Info size={14} /> {alert.recommendation}
                                    </div>
                                  </div>
                                </div>
                              </div>

                              <div className="flex items-center gap-3 self-end lg:self-start shrink-0">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="rounded-full text-muted-foreground hover:text-foreground"
                                  onClick={() => handleDismissAlert(alert.id)}
                                  disabled={isBeingDismissed}
                                >
                                  <XCircle size={18} className="mr-1" /> Dismiss
                                </Button>
                                <AIHelpButton
                                  alert={{
                                    id: alert.id,
                                    type: alert.type,
                                    title: alert.title,
                                    description: alert.description,
                                    severity: alert.severity,
                                    source: alert.source,
                                    evidence: alert.evidence || {}
                                  }}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })
            )}
          </AnimatePresence>
        </div>
      </div>
    </MainLayout>
  );
}
