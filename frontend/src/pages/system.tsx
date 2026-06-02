import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Cpu, Database, HardDrive, Wifi, ShieldCheck, Zap, RefreshCw, Activity, Server, MemoryStick, Gauge, Network, Layers, Clock } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";

interface HealthData {
  cpu: {
    percent: number;
    per_core: number[];
    cores: number;
    physical_cores: number;
    frequency: { current: number; min: number; max: number };
    load_average: number[];
  };
  memory: {
    total: number;
    available: number;
    used: number;
    percent: number;
    swap_total: number;
    swap_used: number;
    swap_percent: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    percent: number;
  };
  network: {
    bytes_sent: number;
    bytes_recv: number;
    packets_sent: number;
    packets_recv: number;
    errin: number;
    errout: number;
    dropin: number;
    dropout: number;
  };
  process: {
    memory_rss: number;
    memory_vms: number;
    cpu_percent: number;
    threads: number;
  };
  processing: {
    queue_size: number;
    packets_captured: number;
    alerts_count: number;
    devices_count: number;
  };
  uptime: number;
  platform: string;
}

export default function SystemStats() {
  const { isConnected, stats } = useMonitorStore();
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const data = await apiService.getSystemHealth();
      setHealth(data);
    } catch (err) {
      console.error('Failed to fetch system health:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number) => {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return val.toFixed(1) + ' ' + units[i];
  };

  const formatUptime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  };

  const getStatusColor = (percent: number) => {
    if (percent < 50) return 'text-emerald-500';
    if (percent < 80) return 'text-amber-500';
    return 'text-red-500';
  };

  const getStatusLabel = (percent: number) => {
    if (percent < 50) return 'Healthy';
    if (percent < 80) return 'Moderate';
    return 'Critical';
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <motion.div 
          className="flex items-center justify-between"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div>
            <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
              <Server className="text-primary" />
              System Health
            </h1>
            <p className="text-muted-foreground text-lg flex items-center gap-2 mt-1">
              <Activity size={16} className="text-primary animate-pulse" />
              Real-time infrastructure monitoring
              {health && (
                <Badge variant="outline" className="ml-2 text-xs">
                  <Clock size={10} className="mr-1" />
                  Uptime: {formatUptime(health.uptime)}
                </Badge>
              )}
            </p>
          </div>
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <Button 
              variant="outline" 
              className="rounded-full gap-2 hover:border-primary/50 transition-all" 
              onClick={fetchHealth}
              disabled={loading}
            >
              <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
              Refresh
            </Button>
          </motion.div>
        </motion.div>

        {/* Primary Metrics */}
        <div className="grid gap-4 md:grid-cols-4">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
            <GaugeCard
              title="CPU Usage"
              value={health?.cpu.percent ?? 0}
              suffix="%"
              icon={Cpu}
              color="text-primary"
              detail={health ? `${health.cpu.cores} cores @ ${Math.round(health.cpu.frequency.current)} MHz` : '...'}
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
            <GaugeCard
              title="Memory"
              value={health?.memory.percent ?? 0}
              suffix="%"
              icon={MemoryStick}
              color="text-emerald-500"
              detail={health ? `${formatBytes(health.memory.used)} / ${formatBytes(health.memory.total)}` : '...'}
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
            <GaugeCard
              title="Disk"
              value={health?.disk.percent ?? 0}
              suffix="%"
              icon={HardDrive}
              color="text-blue-500"
              detail={health ? `${formatBytes(health.disk.used)} / ${formatBytes(health.disk.total)}` : '...'}
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
            <GaugeCard
              title="Process Memory"
              value={health ? Math.round((health.process.memory_rss / (health.memory.total || 1)) * 100) : 0}
              suffix="%"
              icon={Layers}
              color="text-orange-500"
              detail={health ? `RSS: ${formatBytes(health.process.memory_rss)} · ${health.process.threads} threads` : '...'}
            />
          </motion.div>
        </div>

        {/* CPU Per-Core Breakdown */}
        {health && health.cpu.per_core.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.45 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Cpu className="text-primary w-5 h-5" />
                  Per-Core CPU Load
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-2 md:grid-cols-4">
                  {health.cpu.per_core.map((pct, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground w-14 shrink-0 font-mono">Core {i}</span>
                      <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                        <motion.div
                          className={cn("h-full rounded-full", pct < 50 ? 'bg-emerald-500' : pct < 80 ? 'bg-amber-500' : 'bg-red-500')}
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.5 }}
                        />
                      </div>
                      <span className={cn("text-xs font-bold w-10 text-right", getStatusColor(pct))}>{Math.round(pct)}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        <div className="grid gap-6 md:grid-cols-2">
          {/* Network I/O */}
          <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl h-full">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Network className="text-primary w-5 h-5" />
                  Network I/O
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {health ? (
                  <>
                    <div className="grid grid-cols-2 gap-4">
                      <StatItem label="Bytes Sent" value={formatBytes(health.network.bytes_sent)} color="text-orange-400" />
                      <StatItem label="Bytes Received" value={formatBytes(health.network.bytes_recv)} color="text-cyan-400" />
                      <StatItem label="Packets Sent" value={health.network.packets_sent.toLocaleString()} color="text-orange-400" />
                      <StatItem label="Packets Received" value={health.network.packets_recv.toLocaleString()} color="text-cyan-400" />
                    </div>
                    <div className="border-t border-border/30 pt-3 grid grid-cols-2 gap-4">
                      <StatItem label="Errors In" value={health.network.errin.toLocaleString()} color={health.network.errin > 0 ? 'text-red-400' : 'text-muted-foreground'} />
                      <StatItem label="Errors Out" value={health.network.errout.toLocaleString()} color={health.network.errout > 0 ? 'text-red-400' : 'text-muted-foreground'} />
                      <StatItem label="Drops In" value={health.network.dropin.toLocaleString()} color={health.network.dropin > 0 ? 'text-amber-400' : 'text-muted-foreground'} />
                      <StatItem label="Drops Out" value={health.network.dropout.toLocaleString()} color={health.network.dropout > 0 ? 'text-amber-400' : 'text-muted-foreground'} />
                    </div>
                  </>
                ) : (
                  <div className="text-center text-muted-foreground text-sm py-8">Loading network stats...</div>
                )}
              </CardContent>
            </Card>
          </motion.div>

          {/* Processing Stats + Connection Status */}
          <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.6 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl h-full">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Gauge className="text-primary w-5 h-5" />
                  Processing Pipeline
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {health ? (
                  <>
                    <div className="grid grid-cols-2 gap-4">
                      <StatItem label="Packets Captured" value={health.processing.packets_captured.toLocaleString()} color="text-primary" />
                      <StatItem label="Active Alerts" value={health.processing.alerts_count.toLocaleString()} color={health.processing.alerts_count > 0 ? 'text-amber-400' : 'text-emerald-400'} />
                      <StatItem label="Devices Tracked" value={health.processing.devices_count.toLocaleString()} color="text-cyan-400" />
                      <StatItem label="Queue Depth" value={health.processing.queue_size.toLocaleString()} color={health.processing.queue_size > 100 ? 'text-amber-400' : 'text-emerald-400'} />
                    </div>
                    <div className="border-t border-border/30 pt-3 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <motion.div animate={isConnected ? { scale: [1, 1.2, 1] } : {}} transition={{ duration: 1, repeat: Infinity }}>
                            <Wifi className={cn("w-4 h-4", isConnected ? "text-emerald-500" : "text-red-500")} />
                          </motion.div>
                          <span className="text-sm font-medium text-foreground">WebSocket</span>
                        </div>
                        <Badge variant="outline" className={cn("text-xs", isConnected ? 'text-emerald-400 border-emerald-500/40' : 'text-red-400 border-red-500/40')}>
                          {isConnected ? 'Connected' : 'Disconnected'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Zap className="w-4 h-4 text-orange-400" />
                          <span className="text-sm font-medium text-foreground">Total Packets</span>
                        </div>
                        <span className="text-sm font-bold text-foreground">
                          {(stats?.totalPackets || stats?.total_packets || 0).toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-primary" />
                          <span className="text-sm font-medium text-foreground">Platform</span>
                        </div>
                        <span className="text-sm text-muted-foreground">{health.platform}</span>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-center text-muted-foreground text-sm py-8">Loading processing stats...</div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        </div>

        {/* Swap Memory */}
        {health && health.memory.swap_total > 0 && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}>
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Database className="w-5 h-5 text-violet-500" />
                    <div>
                      <p className="text-sm font-medium text-foreground">Swap Memory</p>
                      <p className="text-xs text-muted-foreground">{formatBytes(health.memory.swap_used)} / {formatBytes(health.memory.swap_total)}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-32 h-2 bg-secondary rounded-full overflow-hidden">
                      <motion.div
                        className={cn("h-full rounded-full", health.memory.swap_percent < 50 ? 'bg-violet-500' : 'bg-red-500')}
                        initial={{ width: 0 }}
                        animate={{ width: `${health.memory.swap_percent}%` }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>
                    <span className="text-sm font-bold text-foreground">{Math.round(health.memory.swap_percent)}%</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </div>
    </MainLayout>
  );
}

function GaugeCard({ title, value, suffix, icon: Icon, color, detail }: {
  title: string; value: number; suffix: string; icon: any; color: string; detail: string;
}) {
  const getStatusColor = (v: number) => {
    if (v < 50) return 'text-emerald-500';
    if (v < 80) return 'text-amber-500';
    return 'text-red-500';
  };
  const getStatusLabel = (v: number) => {
    if (v < 50) return 'Healthy';
    if (v < 80) return 'Moderate';
    return 'Critical';
  };

  return (
    <motion.div whileHover={{ scale: 1.02, y: -3 }} transition={{ duration: 0.2 }}>
      <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl group hover:border-primary/30 hover:shadow-2xl transition-all">
        <CardContent className="pt-5 pb-4">
          <div className="flex items-center justify-between mb-3">
            <motion.div className={cn("p-2.5 rounded-xl", color.replace('text', 'bg') + '/10')} whileHover={{ scale: 1.1, rotate: 5 }}>
              <Icon className={cn("w-5 h-5", color)} />
            </motion.div>
            <div className="text-right">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
              <motion.p className="text-2xl font-bold text-foreground" key={value} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }}>
                {Math.round(value)}{suffix}
              </motion.p>
            </div>
          </div>
          <motion.div initial={{ scaleX: 0 }} animate={{ scaleX: 1 }} transition={{ duration: 0.8 }} style={{ originX: 0 }}>
            <Progress value={value} className="h-1.5 mb-2" />
          </motion.div>
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-muted-foreground truncate max-w-[60%]">{detail}</span>
            <div className="flex items-center gap-1">
              <ShieldCheck className={cn("w-3 h-3", getStatusColor(value))} />
              <span className={cn("text-[10px] font-bold uppercase tracking-wider", getStatusColor(value))}>{getStatusLabel(value)}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function StatItem({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="space-y-0.5">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={cn("text-sm font-bold", color)}>{value}</p>
    </div>
  );
}
