import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Shield, CheckCircle, Clock, Filter, Info, Trash2, Zap, Radio, ShieldAlert, ShieldCheck, Bell, Activity, Eye, XCircle, Bot, Sparkles } from "lucide-react";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AIHelpButton, AIHealthWidget } from "@/components/AIAssistant";

export default function Alerts() {
  const { alerts, setAlerts } = useMonitorStore();
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [isScanning, setIsScanning] = useState(true);
  const [newAlertFlash, setNewAlertFlash] = useState(false);
  const [dismissingId, setDismissingId] = useState<number | null>(null);
  
  // Simulate real-time scanning indicator
  useEffect(() => {
    const interval = setInterval(() => {
      setIsScanning(prev => !prev);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // Flash effect when new alert arrives
  useEffect(() => {
    if (alerts.length > 0) {
      setNewAlertFlash(true);
      const timer = setTimeout(() => setNewAlertFlash(false), 1000);
      return () => clearTimeout(timer);
    }
  }, [alerts.length]);
  
  const handleDismissAlert = async (alertId: number) => {
    setDismissingId(alertId);
    try {
      await apiService.dismissAlert(alertId);
      setTimeout(() => {
        setAlerts(alerts.filter(a => a.id !== alertId));
        setDismissingId(null);
      }, 300);
    } catch (err) {
      console.error('Failed to dismiss alert:', err);
      setDismissingId(null);
    }
  };

  const handleClearAll = async () => {
    if (confirm('Are you sure you want to clear all alerts?')) {
      try {
        await apiService.clearAlerts();
        setAlerts([]);
      } catch (err) {
        console.error('Failed to clear alerts:', err);
      }
    }
  };
  
  // Use real alerts if available, otherwise show demo data
  const baseAlerts = alerts.length > 0 ? alerts.map(a => ({
    id: a.id,
    type: a.type, // Preserve the actual attack type for AI
    severity: a.severity,
    title: a.title,
    description: a.description,
    source: a.source,
    time: new Date(a.timestamp).toLocaleTimeString(),
    status: a.severity === 'critical' ? 'Action Required' : 'Review',
    recommendation: a.additional_info?.recommendation || 'Review this alert for more details.',
    evidence: a.additional_info?.evidence || {}
  })) : [
    {
      id: 1,
      type: "dos_flood",
      severity: "critical" as const,
      title: "Unusual Traffic Spike",
      description: "A large amount of data is being sent to an unknown address.",
      source: "Desktop PC",
      time: "2 mins ago",
      status: "Action Required",
      recommendation: "Review this device's activity or block the connection.",
      evidence: {}
    },
    {
      id: 2,
      type: "brute_force",
      severity: "high" as const,
      title: "Suspicious Login Attempt",
      description: "Someone tried to access your smart home hub with the wrong password.",
      source: "Unknown Location",
      time: "15 mins ago",
      status: "Blocked",
      recommendation: "Consider changing your admin password.",
      evidence: {}
    },
    {
      id: 3,
      type: "port_scan",
      severity: "medium" as const,
      title: "New Device Discovery",
      description: "A new device named 'Guest-Phone' has joined your Wi-Fi.",
      source: "Wi-Fi Network",
      time: "1 hour ago",
      status: "Review",
      recommendation: "Check if you recognize this device.",
      evidence: {}
    }
  ];

  // Apply filter
  const displayAlerts = filter === 'all' 
    ? baseAlerts 
    : baseAlerts.filter(a => a.severity === filter);

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
        {/* Header with Live Indicator */}
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
              {/* Live Monitoring Indicator */}
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
              variant="outline" 
              size="sm"
              className="rounded-full text-destructive hover:text-destructive border-destructive/30 hover:border-destructive/50"
              onClick={handleClearAll}
            >
              <Trash2 className="mr-2 h-4 w-4" /> Clear All
            </Button>
          </motion.div>
        </motion.div>

        {/* Animated Stats Grid */}
        <div className="grid gap-4 md:grid-cols-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <Card className={`rounded-2xl overflow-hidden transition-all hover:scale-[1.02] ${
              criticalCount > 0 || highCount > 0 
                ? 'bg-red-500/10 border-red-500/30' 
                : 'bg-emerald-500/10 border-emerald-500/30'
            }`}>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <motion.div 
                    className={`p-3 rounded-xl ${
                      criticalCount > 0 || highCount > 0 
                        ? 'bg-red-500/20 text-red-400' 
                        : 'bg-emerald-500/20 text-emerald-400'
                    }`}
                    animate={criticalCount > 0 ? { scale: [1, 1.1, 1] } : {}}
                    transition={{ duration: 1, repeat: Infinity }}
                  >
                    {criticalCount > 0 || highCount > 0 ? <ShieldAlert size={24} /> : <ShieldCheck size={24} />}
                  </motion.div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Network Status</p>
                    <p className={`text-xl font-bold ${
                      criticalCount > 0 || highCount > 0 ? 'text-red-400' : 'text-emerald-400'
                    }`}>
                      {criticalCount > 0 ? 'Critical Threats' : highCount > 0 ? 'Needs Attention' : 'All Clear'}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
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

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
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

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
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

        {/* Real-time Alert List */}
        <div className="space-y-4">
          <div className="flex items-center justify-between px-2">
            <h2 className="text-xl font-bold text-foreground flex items-center gap-2">
              <Bell className="text-primary" />
              Recent Activity
              {newAlertFlash && (
                <motion.span
                  className="px-2 py-0.5 rounded-full bg-primary text-xs font-bold text-white"
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0 }}
                >
                  NEW
                </motion.span>
              )}
            </h2>
            <span className="text-sm text-muted-foreground">
              Showing {displayAlerts.length} of {baseAlerts.length} alerts
            </span>
          </div>
          
          <AnimatePresence mode="popLayout">
            {displayAlerts.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-center py-16"
              >
                <motion.div
                  animate={{ scale: [1, 1.05, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
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
                          {/* Severity Indicator Bar */}
                          <div className={`w-full md:w-1 h-1 md:h-auto ${colors.bg}`} />
                          
                          <div className="flex-1 p-6">
                            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                              <div className="flex items-start gap-4">
                                {/* Animated Icon */}
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
                                    {/* Attack Type Badge */}
                                    <Badge 
                                      variant="outline" 
                                      className="rounded-full text-xs bg-primary/10 text-primary border-primary/30"
                                    >
                                      {alert.type?.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || 'Security Alert'}
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
                                  <XCircle size={18} className="mr-1" />
                                  Dismiss
                                </Button>
                                <AIHelpButton 
                                  alert={{
                                    id: alert.id,
                                    type: alert.type, // Pass actual attack type for specific remediation
                                    title: alert.title,
                                    description: alert.description,
                                    severity: alert.severity,
                                    source: alert.source,
                                    evidence: alert.evidence || {}
                                  }}
                                />
                                {alert.severity === 'critical' && (
                                  <motion.div
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                  >
                                    <Button 
                                      size="sm"
                                      className={`rounded-full px-6 ${colors.bg} hover:opacity-90 ${colors.glow}`}
                                    >
                                      Take Action
                                    </Button>
                                  </motion.div>
                                )}
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
