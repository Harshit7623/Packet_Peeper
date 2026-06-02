import { MainLayout } from "@/components/layout/MainLayout";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Search, Eye, Pause, Play, Download, ArrowRight, ShieldCheck, ShieldAlert, Radio } from "lucide-react";
import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useMonitorStore } from "@/store/monitorStore";
import { socketService } from "@/services/socketService";
import { apiService } from "@/services/apiService";
import { motion, AnimatePresence } from "framer-motion";

export default function PacketMonitor() {
  const { packets, stats, isSniffing } = useMonitorStore();
  const setSniffing = useMonitorStore((state) => state.setSniffing);
  const [searchTerm, setSearchTerm] = useState("");
  const [localPackets, setLocalPackets] = useState<any[]>([]);

  // Use real packets from store when available
  useEffect(() => {
    if (packets.length === 0) {
      setLocalPackets([]);
      return;
    }

    setLocalPackets(packets.map((p, i) => ({
      id: p.id || i,
      timestamp: p.timestamp,
      source: p.src_ip,
      destination: p.dst_ip,
      protocol: p.protocol,
      src_port: p.src_port,
      dst_port: p.dst_port,
      port: p.dst_port,
      service: p.service || 'Unknown',
      size: p.length,
      status: 'Safe'
    })));
  }, [packets]);

  const filteredPackets = localPackets.filter(p => 
    p.source?.includes(searchTerm) || 
    p.destination?.includes(searchTerm) || 
    p.protocol?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleToggleCapture = async () => {
    try {
      if (isSniffing) {
        socketService.stopSniffing();
        setSniffing(false, null);
      } else {
        socketService.startSniffing('auto');
        setSniffing(true, 'auto');
      }
    } catch (err) {
      console.error('Failed to toggle capture:', err);
    }
  };

  const handleExport = async () => {
    try {
      await apiService.downloadReport('json');
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  // Use stats.totalPackets for consistency with dashboard
  const totalCaptured = stats?.totalPackets || stats?.total_packets || packets.length;

  return (
    <MainLayout>
      <div className="space-y-6">
        <motion.div 
          className="flex flex-col md:flex-row md:items-center justify-between gap-4"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="flex items-center gap-3">
            <motion.div
              className="p-2 bg-primary/10 rounded-xl"
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
            >
              <Radio className="w-6 h-6 text-primary" />
            </motion.div>
            <div>
              <h1 className="text-3xl font-bold text-foreground">Live Intercept</h1>
              <p className="text-muted-foreground text-lg">Monitoring traffic in real-time.</p>
            </div>
          </div>
          <div className="flex gap-2">
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button 
                variant={isSniffing ? "destructive" : "default"} 
                onClick={handleToggleCapture}
                className="rounded-full gap-2 px-6"
              >
                {isSniffing ? <Pause size={16} /> : <Play size={16} />}
                {isSniffing ? "Stop Capture" : "Start Capture"}
              </Button>
            </motion.div>
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button variant="outline" className="rounded-full gap-2 px-6" onClick={handleExport}>
                <Download size={16} /> Export Data
              </Button>
            </motion.div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
        >
          <Card className="p-4 bg-card/40 backdrop-blur-xl border-border/50 rounded-2xl hover:border-primary/30 transition-all">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input 
                  placeholder="Filter packets (IP, protocol, etc.)..." 
                  className="pl-9 font-mono text-xs uppercase tracking-widest bg-black/20 rounded-xl border-none focus:ring-1 focus:ring-primary/50"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <div className="flex gap-4 text-xs font-mono items-center px-4 bg-primary/5 rounded-xl border border-primary/10">
                <div className="flex items-center gap-2">
                  <motion.span 
                    className={isSniffing ? "text-emerald-500 font-bold" : "text-red-500 font-bold"}
                    animate={isSniffing ? { opacity: [1, 0.3, 1] } : {}}
                    transition={{ duration: 1, repeat: Infinity }}
                  >●</motion.span>
                  <span className="text-muted-foreground">{isSniffing ? 'Live' : 'Paused'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Total:</span>
                  <motion.span 
                    className="text-foreground font-bold"
                    key={totalCaptured}
                    initial={{ scale: 1.2 }}
                    animate={{ scale: 1 }}
                  >
                    {totalCaptured.toLocaleString()}
                  </motion.span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Showing:</span>
                  <span className="text-foreground font-bold">{filteredPackets.length}</span>
                </div>
              </div>
            </div>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all">
            <div className="p-0 overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-white/5 text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground border-b border-border/50">
                  <tr>
                    <th className="px-6 py-4">Timestamp</th>
                    <th className="px-6 py-4">Flow (Source → Destination)</th>
                    <th className="px-6 py-4">Protocol</th>
                    <th className="px-6 py-4">Service</th>
                    <th className="px-6 py-4">Size</th>
                    <th className="px-6 py-4 text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30 font-mono text-[11px]">
                  <AnimatePresence mode="popLayout">
                    {filteredPackets.map((packet, index) => (
                      <motion.tr 
                        key={packet.id} 
                        className="hover:bg-white/5 transition-colors group"
                        initial={{ opacity: 0, x: -20, backgroundColor: 'rgba(var(--primary), 0.1)' }}
                        animate={{ opacity: 1, x: 0, backgroundColor: 'transparent' }}
                        exit={{ opacity: 0, x: 20 }}
                        transition={{ duration: 0.3, delay: index * 0.02 }}
                        layout
                      >
                        <td className="px-6 py-3 text-muted-foreground whitespace-nowrap">
                          {packet.timestamp?.split('T')[1]?.slice(0, 12) || packet.timestamp}
                        </td>
                        <td className="px-6 py-3">
                          <div className="flex flex-col gap-1">
                            <span className="text-primary font-bold text-sm tracking-wide">
                              {packet.source}{packet.src_port ? <span className="text-muted-foreground font-normal">:{packet.src_port}</span> : ''}
                            </span>
                            <div className="flex items-center gap-2">
                              <motion.div animate={{ x: [0, 3, 0] }} transition={{ duration: 1, repeat: Infinity }}>
                                <ArrowRight size={12} className="text-muted-foreground" />
                              </motion.div>
                              <span className="text-foreground text-sm tracking-wide">
                                {packet.destination}{packet.dst_port ? <span className="text-muted-foreground font-normal">:{packet.dst_port}</span> : ''}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-3">
                          <Badge variant="outline" className={cn(
                            "rounded px-2 py-0 text-[10px] font-bold border-none",
                            packet.protocol === 'TCP' ? 'bg-blue-500/10 text-blue-400' : 
                            packet.protocol === 'UDP' ? 'bg-orange-500/10 text-orange-400' :
                            packet.protocol === 'HTTPS' ? 'bg-green-500/10 text-green-400' : 'bg-secondary text-foreground'
                          )}>
                            {packet.protocol}
                          </Badge>
                        </td>
                        <td className="px-6 py-3 text-foreground font-bold">{packet.service}</td>
                        <td className="px-6 py-3">
                          <div className="flex items-center gap-2">
                            <span className="w-12 text-right">{packet.size} B</span>
                            <div className="h-1 w-12 bg-secondary rounded-full overflow-hidden hidden sm:block">
                              <motion.div 
                                className="h-full bg-primary/40" 
                                initial={{ width: 0 }}
                                animate={{ width: `${(packet.size / 1500) * 100}%` }}
                                transition={{ duration: 0.5 }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-3 text-center">
                          <motion.div 
                            className={cn(
                              "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-tighter",
                              packet.status === 'Safe' ? 'text-emerald-500 bg-emerald-500/5' : 'text-destructive bg-destructive/10'
                            )}
                            animate={packet.status !== 'Safe' ? { scale: [1, 1.05, 1] } : {}}
                            transition={{ duration: 0.5, repeat: Infinity }}
                          >
                            {packet.status === 'Safe' ? <ShieldCheck size={10} /> : <ShieldAlert size={10} />}
                            {packet.status}
                          </motion.div>
                        </td>
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                </tbody>
              </table>
              <AnimatePresence>
                {filteredPackets.length === 0 && (
                  <motion.div 
                    className="p-20 text-center"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                  >
                    <motion.div 
                      className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4 border border-primary/20"
                      animate={{ scale: [1, 1.1, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    >
                      <Eye className="text-primary" size={32} />
                    </motion.div>
                    <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest">
                      {isSniffing ? "Awaiting Traffic Ingress..." : "Capture Paused"}
                    </p>
                    <p className="text-sm text-muted-foreground mt-3">
                      {isSniffing
                        ? "No packets captured yet. Ensure the correct interface is selected."
                        : "Start packet capture to see live traffic."}
                    </p>
                    {!isSniffing && (
                      <Button className="mt-6 rounded-full px-6" onClick={handleToggleCapture}>
                        <Play size={16} className="mr-2" /> Start Capture
                      </Button>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </Card>
        </motion.div>
      </div>
    </MainLayout>
  );
}
