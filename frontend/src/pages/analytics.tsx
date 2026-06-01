import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Info, ShieldCheck, Users, TrendingUp, BarChart3, Activity } from "lucide-react";
import { useMonitorStore } from "@/store/monitorStore";
import { motion } from "framer-motion";
import { apiService } from "@/services/apiService";
import { useEffect, useMemo, useState } from "react";

export default function Analytics() {
  const { devices, alerts, stats } = useMonitorStore();
  const [topTalkers, setTopTalkers] = useState<any[]>([]);
  const [analyticsData, setAnalyticsData] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const totalPackets = analyticsData?.total_packets || stats?.totalPackets || stats?.total_packets || 0;
  const blockedCount = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;

  const talkerRows = useMemo(() => {
    const source = topTalkers.length > 0 ? topTalkers : devices;
    return source.slice(0, 3).map((device, i) => {
      const packetsIn = Number(device.packets_in ?? device.packetsIn ?? 0);
      const packetsOut = Number(device.packets_out ?? device.packetsOut ?? 0);
      const packetsCaptured = Number(device.packetsCaptured ?? 0);
      const totalPacketsDevice = packetsIn + packetsOut + packetsCaptured;

      return {
        key: `${device.ip_address || device.ipAddress || device.name || i}`,
        label: device.hostname || device.ip_address || device.ipAddress || device.name,
        totalPackets: totalPacketsDevice,
        rank: i,
      };
    });
  }, [devices, topTalkers]);

  useEffect(() => {
    let isMounted = true;
    const loadAnalytics = async () => {
      setIsLoading(true);
      try {
        const [talkersResult, analyticsResult] = await Promise.allSettled([
          apiService.getTopTalkers(3),
          apiService.getAnalytics('24h'),
        ]);

        if (!isMounted) return;

        if (talkersResult.status === 'fulfilled') {
          setTopTalkers(talkersResult.value || []);
        }
        if (analyticsResult.status === 'fulfilled') {
          setAnalyticsData(analyticsResult.value || null);
        }
      } catch (err) {
        console.error('Analytics fetch failed:', err);
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    loadAnalytics();
    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <MainLayout>
      <div className="space-y-6">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <BarChart3 className="text-primary" />
            Security Insights
          </h1>
          <p className="text-muted-foreground text-lg flex items-center gap-2 mt-1">
            <Activity size={16} className="text-primary animate-pulse" />
            Clear reports on your network's safety and usage
          </p>
        </motion.div>

        <div className="grid gap-6 md:grid-cols-2">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all h-full">
              <CardHeader className="bg-muted/30 border-b border-border/50">
                <div className="flex items-center gap-2">
                  <Users className="text-primary w-5 h-5" />
                  <CardTitle>Top Data Users</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="p-6">
                <div className="space-y-6">
                  {talkerRows.length > 0 ? talkerRows.map((device) => (
                    <motion.div 
                      key={device.key} 
                      className="flex items-center justify-between group cursor-pointer p-3 rounded-xl hover:bg-muted/30 transition-all"
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.2 + device.rank * 0.1 }}
                      whileHover={{ x: 5 }}
                    >
                      <div className="flex items-center gap-4">
                        <motion.span 
                          className="text-2xl"
                          whileHover={{ scale: 1.2, rotate: 10 }}
                        >
                          {device.rank === 0 ? '🖥️' : device.rank === 1 ? '💻' : '📱'}
                        </motion.span>
                        <div>
                          <p className="font-bold text-foreground group-hover:text-primary transition-colors">{device.label}</p>
                          <p className="text-xs text-muted-foreground">Total packets this session</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="font-bold text-foreground">{device.totalPackets > 0 ? device.totalPackets.toLocaleString() : 'Active'}</p>
                        <p className="text-[10px] font-bold text-primary">{device.totalPackets > 0 ? 'packets' : 'device'}</p>
                      </div>
                    </motion.div>
                  )) : (
                    <div className="rounded-xl border border-dashed border-border/60 bg-muted/20 p-6 text-center">
                      <p className="text-sm font-semibold text-foreground">
                        {isLoading ? 'Loading devices...' : 'No device traffic yet'}
                      </p>
                      <p className="text-xs text-muted-foreground mt-2">
                        Start packet capture to see top data users in real time.
                      </p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </motion.div>
           
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all h-full">
              <CardHeader className="bg-muted/30 border-b border-border/50">
                <div className="flex items-center gap-2">
                  <motion.div
                    animate={{ rotate: [0, 360] }}
                    transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                  >
                    <ShieldCheck className="text-emerald-500 w-5 h-5" />
                  </motion.div>
                  <CardTitle>Protection Summary</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="p-6">
                <div className="space-y-6">
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm font-medium">
                      <span className="text-foreground">Threats Analyzed</span>
                      <span className="text-emerald-500">{alerts.length > 0 ? '100%' : 'N/A'}</span>
                    </div>
                    <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                      <motion.div 
                        className="h-full bg-linear-to-r from-emerald-500 to-emerald-400"
                        initial={{ width: 0 }}
                        animate={{ width: '100%' }}
                        transition={{ duration: 1, delay: 0.5 }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {alerts.length > 0 
                        ? `We analyzed ${alerts.length} security events. ${blockedCount} required attention.`
                        : 'No security events detected yet.'}
                    </p>
                  </div>
                  
                  <motion.div 
                    className="pt-4 border-t border-border/50"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.8 }}
                  >
                    <div className="flex items-start gap-3 p-3 rounded-xl bg-primary/5 border border-primary/10">
                      <motion.div 
                        className="p-2 rounded-lg bg-primary/10 text-primary"
                        whileHover={{ scale: 1.1 }}
                      >
                        <Info size={18} />
                      </motion.div>
                      <div className="space-y-1">
                        <p className="text-sm font-bold text-foreground">Smart Tip</p>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          {totalPackets > 10000 
                            ? 'High traffic detected. Consider reviewing active connections.'
                            : 'Your network traffic appears normal. Keep monitoring for anomalies.'}
                        </p>
                      </div>
                    </div>
                  </motion.div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    </MainLayout>
  );
}
