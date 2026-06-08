import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from "recharts";
import { Brain, AlertTriangle, RefreshCw, Activity, Shield, Cpu, TrendingDown, Clock, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { apiService } from "@/services/apiService";
import { useMonitorStore } from "@/store/monitorStore";
import { motion } from "framer-motion";
import { useState, useEffect, useCallback, useMemo } from "react";
import { cn } from "@/lib/utils";

interface MlStatus {
  model_loaded: boolean;
  last_trained: string | null;
  training_samples: number;
  score_threshold: number;
  training_window_hours: number;
  min_training_samples: number;
  total_scores: number;
  anomaly_count: number;
  last_score_time: string | null;
  model_path: string;
}

interface ScoreEntry {
  timestamp: string;
  score: number;
  is_anomaly: boolean;
  threshold: number;
  window_start: string | null;
}

export default function MlAnomaly() {
  const { alerts } = useMonitorStore();
  const [status, setStatus] = useState<MlStatus | null>(null);
  const [scores, setScores] = useState<ScoreEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRetraining, setIsRetraining] = useState(false);
  const [threshold, setThreshold] = useState(-0.3);
  const [retrainResult, setRetrainResult] = useState<string | null>(null);

  const anomalyAlerts = useMemo(
    () => alerts.filter(a => (a.alert_type || a.type) === 'anomaly'),
    [alerts]
  );

  const loadStatus = useCallback(async () => {
    try {
      const s = await apiService.getMlStatus();
      setStatus(s);
      setThreshold(s.score_threshold);
    } catch {
      setStatus(null);
    }
  }, []);

  const loadScores = useCallback(async () => {
    try {
      const result = await apiService.getMlScores(200);
      setScores(result.scores || []);
    } catch {
      setScores([]);
    }
  }, []);

  const loadAll = useCallback(async () => {
    setIsLoading(true);
    await Promise.allSettled([loadStatus(), loadScores()]);
    setIsLoading(false);
  }, [loadStatus, loadScores]);

  useEffect(() => { loadAll(); }, [loadAll]);

  useEffect(() => {
    const interval = setInterval(loadScores, 30000);
    return () => clearInterval(interval);
  }, [loadScores]);

  useEffect(() => {
    const interval = setInterval(loadStatus, 60000);
    return () => clearInterval(interval);
  }, [loadStatus]);

  const handleRetrain = async () => {
    setIsRetraining(true);
    setRetrainResult(null);
    try {
      const result = await apiService.retrainMl();
      if (result.success) {
        setRetrainResult(`Trained on ${result.samples} samples (contamination: ${result.contamination})`);
      } else {
        setRetrainResult(`Failed: ${result.error}`);
      }
      await loadStatus();
    } catch (e: any) {
      setRetrainResult(`Error: ${e.message}`);
    }
    setIsRetraining(false);
  };

  const handleThresholdChange = async (value: number[]) => {
    const newThreshold = value[0];
    setThreshold(newThreshold);
    try {
      await apiService.updateMlConfig({ score_threshold: newThreshold });
    } catch {}
  };

  const chartData = useMemo(() => {
    return scores.map(s => ({
      time: new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      score: s.score,
      is_anomaly: s.is_anomaly,
      threshold: s.threshold,
    }));
  }, [scores]);

  if (isLoading) {
    return (
      <MainLayout>
        <div className="min-h-screen bg-background flex items-center justify-center">
          <div className="flex items-center gap-3 text-muted-foreground">
            <Loader2 className="h-6 w-6 animate-spin" />
            <span>Loading ML Anomaly Detection...</span>
          </div>
        </div>
      </MainLayout>
    );
  }

  if (!status) {
    return (
      <MainLayout>
        <div className="min-h-screen bg-background flex items-center justify-center">
          <Card className="w-full max-w-md">
            <CardContent className="pt-6 text-center">
              <XCircle className="h-12 w-12 mx-auto mb-4 text-red-500" />
              <h2 className="text-xl font-bold mb-2">ML Service Unavailable</h2>
              <p className="text-muted-foreground text-sm">
                The ML anomaly detection service is not running or is disabled.
                Check your configuration and ensure ml_anomaly_detection is enabled.
              </p>
            </CardContent>
          </Card>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="min-h-screen bg-background">
        <div className="p-6 space-y-6 max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-purple-500/10 flex items-center justify-center border border-purple-500/30">
                <Brain className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">ML Anomaly Detection</h1>
                <p className="text-sm text-muted-foreground font-mono">
                  Isolation Forest on 1-min traffic feature windows
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={loadAll}
                className="gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </Button>
              <Button
                size="sm"
                onClick={handleRetrain}
                disabled={isRetraining}
                className="gap-2 bg-purple-600 hover:bg-purple-700"
              >
                {isRetraining ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cpu className="h-4 w-4" />}
                {isRetraining ? 'Training...' : 'Retrain Model'}
              </Button>
            </div>
          </div>

          {retrainResult && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-sm px-4 py-2 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-300"
            >
              {retrainResult}
            </motion.div>
          )}

          {/* Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
              <Card className="bg-card/80 border-border/40">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Model Status</span>
                    {status.model_loaded
                      ? <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                      : <XCircle className="h-4 w-4 text-red-500" />
                    }
                  </div>
                  <div className="text-2xl font-bold">
                    {status.model_loaded ? 'Trained' : 'Not Trained'}
                  </div>
                  {status.last_trained && (
                    <div className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(status.last_trained).toLocaleString()}
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
              <Card className="bg-card/80 border-border/40">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Training Samples</span>
                    <Activity className="h-4 w-4 text-blue-400" />
                  </div>
                  <div className="text-2xl font-bold">{status.training_samples.toLocaleString()}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {status.training_window_hours}h window
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
              <Card className="bg-card/80 border-border/40">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Anomalies Found</span>
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                  </div>
                  <div className="text-2xl font-bold text-amber-400">{status.anomaly_count}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    of {status.total_scores} total scores
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
              <Card className="bg-card/80 border-border/40">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Anomaly Rate</span>
                    <TrendingDown className="h-4 w-4 text-red-400" />
                  </div>
                  <div className="text-2xl font-bold">
                    {status.total_scores > 0
                      ? ((status.anomaly_count / status.total_scores) * 100).toFixed(1)
                      : '0.0'
                    }%
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    threshold: {status.score_threshold}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Score Timeline Chart */}
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
            <Card className="bg-card/80 border-border/40">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Activity className="h-5 w-5 text-purple-400" />
                    Anomaly Score Timeline
                  </CardTitle>
                  <Badge variant="outline" className="font-mono text-xs">
                    {chartData.length} data points
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                {chartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis
                        dataKey="time"
                        stroke="#64748b"
                        tick={{ fontSize: 11 }}
                        interval="preserveStartEnd"
                      />
                      <YAxis
                        stroke="#64748b"
                        tick={{ fontSize: 11 }}
                        domain={['auto', 'auto']}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                        labelStyle={{ color: '#94a3b8' }}
                        itemStyle={{ color: '#a78bfa' }}
                        formatter={(value: number) => [value.toFixed(4), 'Score']}
                      />
                      <ReferenceLine
                        y={threshold}
                        stroke="#ef4444"
                        strokeDasharray="6 3"
                        label={{
                          value: `Threshold (${threshold})`,
                          position: 'right',
                          fill: '#ef4444',
                          fontSize: 11,
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="score"
                        stroke="#8b5cf6"
                        strokeWidth={2}
                        fill="url(#scoreGradient)"
                        dot={(props: any) => {
                          const { cx, cy, payload } = props;
                          if (payload.is_anomaly) {
                            return (
                              <circle
                                key={`dot-${payload.time}`}
                                cx={cx}
                                cy={cy}
                                r={4}
                                fill="#ef4444"
                                stroke="#ef4444"
                                strokeWidth={2}
                              />
                            );
                          }
                          return <circle key={`dot-${payload.time}`} cx={cx} cy={cy} r={1.5} fill="#8b5cf6" />;
                        }}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                    <div className="text-center">
                      <Brain className="h-10 w-10 mx-auto mb-3 opacity-30" />
                      <p className="text-sm">No score data yet</p>
                      <p className="text-xs opacity-60 mt-1">
                        Scores appear after the model evaluates traffic windows
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>

          {/* Controls + Recent Anomalies */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Threshold Config */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
              <Card className="bg-card/80 border-border/40">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Shield className="h-5 w-5 text-purple-400" />
                    Detection Config
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-sm font-medium">Anomaly Score Threshold</label>
                      <span className="text-sm font-mono text-purple-400">{threshold.toFixed(2)}</span>
                    </div>
                    <Slider
                      value={[threshold]}
                      onValueChange={handleThresholdChange}
                      min={-1.0}
                      max={0.1}
                      step={0.01}
                      className="w-full"
                    />
                    <div className="flex justify-between text-xs text-muted-foreground mt-1">
                      <span>More sensitive (-1.0)</span>
                      <span>Less sensitive (0.1)</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div className="p-3 rounded-md bg-muted/30">
                      <div className="text-xs text-muted-foreground mb-1">Training Window</div>
                      <div className="font-mono font-bold">{status.training_window_hours}h</div>
                    </div>
                    <div className="p-3 rounded-md bg-muted/30">
                      <div className="text-xs text-muted-foreground mb-1">Min Training Samples</div>
                      <div className="font-mono font-bold">{status.min_training_samples}</div>
                    </div>
                    <div className="p-3 rounded-md bg-muted/30">
                      <div className="text-xs text-muted-foreground mb-1">Total Scores Run</div>
                      <div className="font-mono font-bold">{status.total_scores}</div>
                    </div>
                    <div className="p-3 rounded-md bg-muted/30">
                      <div className="text-xs text-muted-foreground mb-1">Last Score Time</div>
                      <div className="font-mono font-bold text-xs">
                        {status.last_score_time
                          ? new Date(status.last_score_time).toLocaleTimeString()
                          : 'N/A'}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            {/* Recent Anomaly Alerts */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}>
              <Card className="bg-card/80 border-border/40">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-amber-400" />
                    Recent Anomaly Alerts
                    {anomalyAlerts.length > 0 && (
                      <Badge variant="destructive" className="ml-1">{anomalyAlerts.length}</Badge>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {anomalyAlerts.length > 0 ? (
                    <div className="space-y-2 max-h-[300px] overflow-y-auto">
                      {anomalyAlerts.slice(0, 10).map((alert, i) => (
                        <motion.div
                          key={alert.id || i}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.05 }}
                          className="p-3 rounded-md bg-red-500/5 border border-red-500/20"
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm font-semibold text-red-400">
                              {alert.title || 'Anomaly Detected'}
                            </span>
                            <Badge variant="destructive" className="text-[10px]">
                              {alert.severity}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground line-clamp-2">
                            {alert.description}
                          </p>
                          <div className="text-[10px] text-muted-foreground mt-1 font-mono">
                            {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : ''}
                          </div>
                        </motion.div>
                      ))}
                    </div>
                  ) : (
                    <div className="h-[200px] flex items-center justify-center text-muted-foreground">
                      <div className="text-center">
                        <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                        <p className="text-sm">No anomaly alerts</p>
                        <p className="text-xs opacity-60 mt-1">
                          The model has not detected any anomalies
                        </p>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Recent Scores Table */}
          {scores.length > 0 && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.8 }}>
              <Card className="bg-card/80 border-border/40">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Clock className="h-5 w-5 text-blue-400" />
                    Recent Scores
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border/40">
                          <th className="text-left py-2 px-3 text-xs font-mono uppercase text-muted-foreground">Time</th>
                          <th className="text-left py-2 px-3 text-xs font-mono uppercase text-muted-foreground">Window</th>
                          <th className="text-left py-2 px-3 text-xs font-mono uppercase text-muted-foreground">Score</th>
                          <th className="text-left py-2 px-3 text-xs font-mono uppercase text-muted-foreground">Threshold</th>
                          <th className="text-left py-2 px-3 text-xs font-mono uppercase text-muted-foreground">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scores.slice(-20).reverse().map((s, i) => (
                          <tr
                            key={i}
                            className={cn(
                              "border-b border-border/20 hover:bg-muted/20 transition-colors",
                              s.is_anomaly && "bg-red-500/5"
                            )}
                          >
                            <td className="py-2 px-3 font-mono text-xs">
                              {new Date(s.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="py-2 px-3 font-mono text-xs text-muted-foreground">
                              {s.window_start ? new Date(s.window_start).toLocaleString() : '—'}
                            </td>
                            <td className="py-2 px-3 font-mono">
                              <span className={cn(s.is_anomaly ? "text-red-400 font-bold" : "text-foreground")}>
                                {s.score.toFixed(4)}
                              </span>
                            </td>
                            <td className="py-2 px-3 font-mono text-muted-foreground">
                              {s.threshold.toFixed(2)}
                            </td>
                            <td className="py-2 px-3">
                              {s.is_anomaly ? (
                                <Badge variant="destructive" className="text-[10px]">Anomaly</Badge>
                              ) : (
                                <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-400/30">Normal</Badge>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </div>
      </div>
    </MainLayout>
  );
}
