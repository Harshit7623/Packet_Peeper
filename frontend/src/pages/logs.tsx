import { MainLayout } from "@/components/layout/MainLayout";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Search, History, Shield, Info, RefreshCw, Trash2, Clock, CheckCircle, AlertTriangle, XCircle, X, Terminal, FileText } from "lucide-react";
import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useMonitorStore } from "@/store/monitorStore";
import { socketService } from "@/services/socketService";
import { apiService } from "@/services/apiService";
import { motion, AnimatePresence } from "framer-motion";

interface LogDetail {
  id: number;
  time: string;
  event: string;
  details: string;
  status: string;
  source?: string;
  rawData?: any;
}

export default function Logs() {
  const { logs, setLogs } = useMonitorStore();
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<'all' | 'info' | 'warning' | 'error'>('all');
  const [selectedLog, setSelectedLog] = useState<LogDetail | null>(null);

  useEffect(() => {
    // Request logs from server on mount
    socketService.requestLogs();
  }, []);

  const handleRefresh = () => {
    setLoading(true);
    socketService.requestLogs();
    setTimeout(() => setLoading(false), 1000);
  };

  const handleClearLogs = async () => {
    if (confirm('Are you sure you want to clear all logs?')) {
      try {
        await apiService.clearLogs();
        setLogs([]);
        socketService.clearLogs();
      } catch (err) {
        console.error('Failed to clear logs:', err);
      }
    }
  };

  // Use real logs only
  const displayLogs: LogDetail[] = logs.map((log, i) => ({
    id: i,
    time: new Date(log.timestamp).toLocaleTimeString(),
    event: log.level.toUpperCase(),
    details: log.message,
    status: log.level === 'error' ? 'blocked' : log.level === 'warning' ? 'warning' : 'info',
    source: log.source || 'System',
    rawData: log
  }));

  const filteredLogs = displayLogs
    .filter(log => filter === 'all' || log.status === filter || (filter === 'error' && log.status === 'blocked'))
    .filter(log => 
      log.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase())
    );

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle size={18} />;
      case 'blocked': return <XCircle size={18} />;
      case 'warning': return <AlertTriangle size={18} />;
      default: return <History size={18} />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'bg-emerald-500/10 text-emerald-500';
      case 'blocked': return 'bg-red-500/10 text-red-500';
      case 'warning': return 'bg-amber-500/10 text-amber-500';
      default: return 'bg-primary/10 text-primary';
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <motion.div 
          className="flex flex-col md:flex-row md:items-center justify-between gap-4"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div>
            <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
              <Clock className="text-primary" />
              Activity History
            </h1>
            <p className="text-muted-foreground text-lg">
              A timeline of network events. {logs.length > 0 && `${logs.length} events recorded.`}
            </p>
          </div>
          <motion.div 
            className="flex gap-2"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="relative w-full md:w-80">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input 
                placeholder="Search events..." 
                className="pl-9 rounded-full bg-card border-border/50 focus:border-primary/50"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button 
                variant="outline" 
                size="icon"
                className="rounded-full hover:border-primary/50 transition-all" 
                onClick={handleRefresh} 
                disabled={loading}
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </Button>
            </motion.div>
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button 
                variant="outline" 
                size="icon"
                className="rounded-full text-destructive hover:text-destructive hover:border-destructive/50 transition-all" 
                onClick={handleClearLogs}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </motion.div>
          </motion.div>
        </motion.div>

        {/* Filter Tabs */}
        <motion.div 
          className="flex gap-2"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          {['all', 'info', 'warning', 'error'].map((f) => (
            <Button
              key={f}
              variant={filter === f ? 'default' : 'outline'}
              size="sm"
              className="rounded-full capitalize"
              onClick={() => setFilter(f as any)}
            >
              {f === 'all' ? 'All Events' : f}
            </Button>
          ))}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
        >
          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
            <div className="divide-y divide-border/30">
              <AnimatePresence mode="popLayout">
                {filteredLogs.map((log, index) => (
                    <motion.div 
                      key={log.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 100 }}
                      transition={{ duration: 0.3, delay: index * 0.03 }}
                      layout
                      className="p-6 hover:bg-muted/30 transition-colors group"
                    >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex items-start gap-4">
                        <motion.div 
                          className={`p-2.5 rounded-xl mt-1 ${getStatusColor(log.status)}`}
                          whileHover={{ scale: 1.1, rotate: 5 }}
                        >
                          {getStatusIcon(log.status)}
                        </motion.div>
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <h3 className="font-bold text-foreground group-hover:text-primary transition-colors">{log.event}</h3>
                            <Badge variant="outline" className="text-[10px] uppercase rounded-full border-border/50">{log.time}</Badge>
                          </div>
                          <p className="text-muted-foreground text-sm">{log.details}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                          <Button 
                            variant="ghost" 
                            size="sm" 
                            className="rounded-full text-xs font-bold uppercase tracking-wider gap-2 opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={() => setSelectedLog(log)}
                          >
                            <Info size={14} /> Details
                          </Button>
                        </motion.div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
            {filteredLogs.length === 0 && (
              <motion.div 
                className="p-12 text-center"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
              >
                <History size={48} className="text-muted-foreground mx-auto mb-4 opacity-50" />
                <p className="text-muted-foreground">
                  {logs.length === 0 ? "No logs captured yet." : "No logs matching your search."}
                </p>
              </motion.div>
            )}
            <div className="p-6 bg-muted/20 border-t border-border/50 text-center text-xs text-muted-foreground font-mono uppercase tracking-widest">
              Showing latest {displayLogs.length} events
            </div>
          </Card>
        </motion.div>

        {/* Log Detail Modal */}
        <AnimatePresence>
          {selectedLog && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
              onClick={(e) => e.target === e.currentTarget && setSelectedLog(null)}
            >
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.9, opacity: 0 }}
                className="w-full max-w-lg bg-card border border-border rounded-2xl shadow-2xl overflow-hidden"
              >
                <div className="flex items-center justify-between p-4 border-b border-border bg-muted/30">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-xl ${getStatusColor(selectedLog.status)}`}>
                      {getStatusIcon(selectedLog.status)}
                    </div>
                    <div>
                      <h3 className="font-bold text-foreground">{selectedLog.event}</h3>
                      <p className="text-xs text-muted-foreground">{selectedLog.time}</p>
                    </div>
                  </div>
                  <Button variant="ghost" size="icon" onClick={() => setSelectedLog(null)} className="rounded-full">
                    <X size={18} />
                  </Button>
                </div>
                
                <div className="p-6 space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <FileText size={14} />
                      <span>Description</span>
                    </div>
                    <p className="text-foreground bg-muted/30 p-3 rounded-xl">{selectedLog.details}</p>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground uppercase tracking-wider">Source</p>
                      <p className="text-sm font-medium text-foreground">{selectedLog.source || 'System'}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground uppercase tracking-wider">Status</p>
                      <Badge variant="outline" className={`${getStatusColor(selectedLog.status)} border-0`}>
                        {selectedLog.status}
                      </Badge>
                    </div>
                  </div>
                  
                  {selectedLog.rawData && (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Terminal size={14} />
                        <span>Raw Data</span>
                      </div>
                      <pre className="text-xs bg-slate-900 text-slate-300 p-3 rounded-xl overflow-x-auto">
                        {JSON.stringify(selectedLog.rawData, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
                
                <div className="p-4 border-t border-border bg-muted/20 flex justify-end gap-2">
                  <Button variant="outline" size="sm" onClick={() => setSelectedLog(null)}>
                    Close
                  </Button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </MainLayout>
  );
}
