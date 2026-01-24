import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MainLayout } from "@/components/layout/MainLayout";
import { Button } from "@/components/ui/button";
import { 
  Activity, 
  ShieldAlert, 
  Wifi, 
  ArrowUpRight, 
  ArrowDownLeft,
  ShieldCheck,
  Cpu,
  Download,
  Play,
  Square,
  Zap,
  Radio,
  TrendingUp
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { useMonitorStore } from "@/store/monitorStore";
import { socketService } from "@/services/socketService";
import { apiService } from "@/services/apiService";

export default function Dashboard() {
  const { stats, alerts, devices, packets, isConnected, isSniffing } = useMonitorStore();
  const setSniffing = useMonitorStore((state) => state.setSniffing);
  const [trafficHistory, setTrafficHistory] = useState<any[]>([]);

  useEffect(() => {
    // Update traffic history when stats change
    if (stats?.currentBandwidth !== undefined) {
      const time = new Date().toLocaleTimeString("en-US", { 
        hour: "2-digit", 
        minute: "2-digit",
        hour12: true 
      });
      
      setTrafficHistory(prev => {
        const newData = [...prev, { 
          time, 
          value: Math.round(stats.currentBandwidth / 1024 / 1024) // Convert to MB
        }];
        // Keep last 24 data points
        return newData.slice(-24);
      });
    }
  }, [stats?.currentBandwidth]);

  useEffect(() => {
    // Request processor stats occasionally
    const interval = setInterval(() => {
      socketService.getProcessorStats();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleMonitoring = async () => {
    try {
      if (isSniffing) {
        socketService.stopSniffing();
        // Optimistically update UI
        setSniffing(false, null);
      } else {
        socketService.startSniffing('Wi-Fi');
        // Optimistically update UI
        setSniffing(true, 'Wi-Fi');
      }
    } catch (err) {
      console.error('Failed to toggle monitoring:', err);
    }
  };

  const handleExportReport = async () => {
    try {
      await apiService.downloadReport('json');
    } catch (err) {
      console.error('Failed to export report:', err);
    }
  };

  const alertsCount = alerts.length;
  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  const devicesCount = devices.length;
  const tcpPackets = stats?.tcpPackets || 0;
  const udpPackets = stats?.udpPackets || 0;
  // Use stats.totalPackets for total count - this reflects actual captured packets
  const totalPackets = stats?.totalPackets || stats?.total_packets || packets.length;

  // Determine most active protocol
  const mostActiveProtocol = tcpPackets > udpPackets ? 'TCP' : 'UDP';
  const protocolPercentage = totalPackets > 0 ? Math.round((Math.max(tcpPackets, udpPackets) / totalPackets) * 100) : 0;

  const chartData = trafficHistory.length > 0 
    ? trafficHistory 
    : Array.from({ length: 12 }, (_, i) => ({ time: `${i}:00`, value: 0 }));

  return (
    <MainLayout>
      {/* Animated Header */}
      <motion.div 
        className="flex flex-col md:flex-row md:items-center justify-between mb-8 gap-4"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div>
          <h1 className="text-4xl font-extrabold tracking-tight text-foreground mb-2 flex items-center gap-3">
            Welcome Back
            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
            >
              <Radio className="text-primary w-8 h-8" />
            </motion.div>
          </h1>
          <p className="text-muted-foreground text-lg flex items-center gap-2">
            <motion.span
              className="inline-flex items-center gap-2"
              animate={{ opacity: [1, 0.5, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <Activity className="w-4 h-4 text-primary" />
            </motion.span>
            {totalPackets ? `${totalPackets.toLocaleString()} packets captured` : "Monitoring network activity..."} • {devicesCount} devices detected
            {!isConnected && <span className="text-destructive ml-2">• Disconnected</span>}
          </p>
        </div>
        <motion.div 
          className="flex gap-3"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <Button 
              variant="outline" 
              className="rounded-full px-6 gap-2 hover:border-primary/50 transition-all"
              onClick={handleExportReport}
            >
              <Download size={18} /> Export Report
            </Button>
          </motion.div>
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <Button 
              className={`rounded-full px-6 gap-2 transition-all ${
                isSniffing 
                  ? 'bg-red-500 hover:bg-red-600 shadow-[0_0_20px_rgba(239,68,68,0.4)]' 
                  : 'bg-primary hover:bg-primary/90 shadow-[0_0_20px_rgba(147,51,234,0.4)]'
              }`}
              onClick={handleToggleMonitoring}
            >
              {isSniffing ? (
                <>
                  <Square size={18} className="animate-pulse" /> Stop Monitoring
                </>
              ) : (
                <>
                  <Play size={18} /> Start Monitoring
                </>
              )}
            </Button>
          </motion.div>
        </motion.div>
      </motion.div>

      {/* Animated Stats Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4 mb-6">
        {[
          { 
            title: "Bandwidth Usage", 
            value: `${((stats?.currentBandwidth || 0) / 1024 / 1024).toFixed(2)} MB/s`,
            change: `Peak: ${((stats?.peakBandwidth || 0) / 1024 / 1024).toFixed(2)} MB/s`,
            icon: Activity,
            trend: "up",
            delay: 0
          },
          { 
            title: "Security Alerts", 
            value: String(alertsCount), 
            change: criticalCount > 0 ? `${criticalCount} Critical` : 'All clear', 
            icon: ShieldAlert,
            trend: criticalCount > 0 ? "up" : "down",
            variant: criticalCount > 0 ? "danger" : "success",
            delay: 0.1
          },
          { 
            title: "Connected Devices", 
            value: String(devicesCount), 
            change: `${totalPackets} packets`,
            icon: Wifi,
            trend: devicesCount > 0 ? "up" : "down",
            delay: 0.2
          },
          { 
            title: "Network Load", 
            value: `${protocolPercentage}%`,
            change: `${mostActiveProtocol} traffic`,
            icon: Cpu,
            trend: "up",
            variant: "success",
            delay: 0.3
          }
        ].map((stat, index) => (
          <motion.div
            key={stat.title}
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: stat.delay }}
          >
            <StatsCard {...stat} />
          </motion.div>
        ))}
      </div>

      <div className="grid gap-6 md:grid-cols-7">
        <Card className="md:col-span-5 bg-card/40 backdrop-blur-xl border-border/50 rounded-2xl overflow-hidden soft-glow">
          <CardHeader className="pb-0">
            <CardTitle className="text-xl font-bold">Network Usage Today</CardTitle>
            <p className="text-sm text-muted-foreground">Real-time bandwidth monitoring</p>
          </CardHeader>
          <CardContent className="h-[350px] pt-6">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#475569" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(value) => `${value} MB`} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  itemStyle={{ color: '#00d4ff' }}
                />
                <Area type="monotone" dataKey="value" stroke="#00d4ff" strokeWidth={2} fillOpacity={1} fill="url(#colorValue)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <div className="md:col-span-2 space-y-4">
          <Card className="h-[calc(50%-8px)] bg-card/50 backdrop-blur border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Most Active Protocol</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-foreground mb-2">{mostActiveProtocol}</div>
              <div className="text-sm text-primary flex items-center gap-1">
                <ArrowUpRight className="w-4 h-4" /> {protocolPercentage}% of traffic
              </div>
              <div className="mt-4 h-2 w-full bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-primary rounded-full shadow-[0_0_10px_#00d4ff]" 
                  style={{width: `${protocolPercentage}%`}} 
                />
              </div>
            </CardContent>
          </Card>
          
          <Card className="h-[calc(50%-8px)] bg-card/50 backdrop-blur border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Packets Captured</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-accent mb-2">{totalPackets.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground flex items-center gap-1">
                TCP: {tcpPackets.toLocaleString()} | UDP: {udpPackets.toLocaleString()}
              </div>
              <div className="mt-4 flex gap-1">
                {[1,2,3,4,5].map(i => (
                  <div key={i} className={`h-8 flex-1 rounded-sm ${i > (5 - Math.ceil(alertsCount / 50)) ? 'bg-secondary' : 'bg-primary/80'}`} />
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Recent Alerts Table */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.6 }}
      >
        <Card className="bg-card/50 backdrop-blur border-border/50 rounded-2xl overflow-hidden">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Zap className="text-primary" />
                Recent Security Events
              </CardTitle>
            </div>
            {alerts.length > 0 && (
              <motion.div
                className="px-3 py-1 rounded-full bg-primary/10 border border-primary/30"
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <span className="text-xs font-bold text-primary">{alerts.length} Events</span>
              </motion.div>
            )}
          </CardHeader>
          <CardContent>
            <AnimatePresence mode="popLayout">
              {alerts.length > 0 ? (
                <div className="space-y-4">
                  {alerts.slice(0, 3).map((alert, index) => (
                    <motion.div 
                      key={alert.id}
                      initial={{ opacity: 0, x: -30 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 30 }}
                      transition={{ duration: 0.3, delay: index * 0.1 }}
                      whileHover={{ scale: 1.02, x: 5 }}
                      className={`flex items-center justify-between p-4 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-all border border-transparent hover:border-primary/20 cursor-pointer ${
                        alert.severity === 'critical' ? 'border-l-4 border-l-red-500' : ''
                      }`}
                    >
                      <div className="flex items-center gap-4">
                        <motion.div 
                          className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                            alert.severity === 'critical' 
                              ? 'bg-red-500/20 text-red-400' 
                              : alert.severity === 'high'
                              ? 'bg-orange-500/20 text-orange-400'
                              : 'bg-primary/20 text-primary'
                          }`}
                          animate={alert.severity === 'critical' ? { 
                            scale: [1, 1.1, 1],
                            rotate: [0, -5, 5, 0]
                          } : {}}
                          transition={{ duration: 1.5, repeat: Infinity }}
                        >
                          <ShieldAlert size={22} />
                        </motion.div>
                        <div>
                          <div className="font-bold text-foreground flex items-center gap-2">
                            {alert.title}
                            {alert.severity === 'critical' && (
                              <span className="px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-[10px] font-bold uppercase">
                                Critical
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-muted-foreground font-mono">{alert.description.substring(0, 60)}...</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-mono text-muted-foreground">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </div>
                        <div className={`text-xs font-bold uppercase ${
                          alert.severity === 'critical' 
                            ? 'text-red-400' 
                            : alert.severity === 'high'
                            ? 'text-orange-400'
                            : 'text-primary'
                        }`}>
                          {alert.severity}
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              ) : (
                <motion.div 
                  className="text-center py-12"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                >
                  <motion.div
                    animate={{ scale: [1, 1.05, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  >
                    <ShieldCheck size={48} className="text-emerald-500 mx-auto mb-4" />
                  </motion.div>
                  <p className="text-muted-foreground">No security events. Your network is protected.</p>
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>
        </Card>
      </motion.div>
    </MainLayout>
  );
}

function StatsCard({ title, value, change, icon: Icon, trend, variant = "default" }: any) {
  const isUp = trend === "up";
  const isDanger = variant === "danger";
  const isSuccess = variant === "success";
  
  let valueColor = "text-foreground";
  let glowClass = "";
  if (isDanger) {
    valueColor = "text-red-400";
    glowClass = "hover:shadow-[0_0_30px_rgba(239,68,68,0.2)]";
  }
  if (isSuccess) {
    valueColor = "text-emerald-400";
    glowClass = "hover:shadow-[0_0_30px_rgba(16,185,129,0.2)]";
  }
  if (!isDanger && !isSuccess) {
    glowClass = "hover:shadow-[0_0_30px_rgba(147,51,234,0.2)]";
  }

  return (
    <motion.div whileHover={{ scale: 1.02, y: -5 }} transition={{ duration: 0.2 }}>
      <Card className={`bg-card/40 backdrop-blur-xl border-border/50 hover:border-primary/30 transition-all rounded-2xl overflow-hidden group ${glowClass}`}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground group-hover:text-primary transition-colors">{title}</CardTitle>
          <motion.div 
            className={`p-2.5 rounded-xl ${isDanger ? 'bg-red-500/10 text-red-400' : isSuccess ? 'bg-emerald-500/10 text-emerald-400' : 'bg-primary/10 text-primary'}`}
            whileHover={{ rotate: 10, scale: 1.1 }}
          >
            <Icon className="h-5 w-5" />
          </motion.div>
        </CardHeader>
        <CardContent>
          <motion.div 
            className={`text-3xl font-black ${valueColor}`}
            key={value}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            {value}
          </motion.div>
          <div className="flex items-center gap-1.5 mt-2">
            <motion.div
              animate={isUp ? { y: [-2, 0, -2] } : {}}
              transition={{ duration: 1, repeat: Infinity }}
            >
              {isUp ? (
                <ArrowUpRight className={`w-4 h-4 ${isDanger ? 'text-red-400' : 'text-emerald-400'}`} />
              ) : (
                <ArrowDownLeft className="w-4 h-4 text-muted-foreground" />
              )}
            </motion.div>
            <span className={`text-xs font-bold ${isUp ? (isDanger ? 'text-red-400' : 'text-emerald-400') : 'text-muted-foreground'}`}>
              {change}
            </span>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
