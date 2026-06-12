import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  FileText, Download, Trash2, Plus, Calendar, Filter,
  Loader2, FileJson, FileSpreadsheet, FileDown, Clock,
  ChevronLeft, ChevronRight, Search, X, RefreshCw,
  Timer, ToggleLeft, ToggleRight,
} from "lucide-react";
import { apiService } from "@/services/apiService";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { useAuth } from "@/contexts/AuthContext";
import { format } from "date-fns";

interface ReportRecord {
  id: number;
  timestamp: string;
  report_type: string;
  start_date: string | null;
  end_date: string | null;
  file_path: string;
  total_packets: number;
  total_alerts: number;
  file_size: number;
  org_id: number | null;
}

interface ScheduledReport {
  id: number;
  name: string;
  report_type: string;
  frequency: string;
  start_date_offset_days: number;
  end_date_offset_days: number;
  severity: string | null;
  is_active: boolean;
  created_at: string | null;
  last_run_at: string | null;
  org_id: number | null;
}

interface GenerateForm {
  type: 'pdf' | 'csv' | 'json';
  start_date: string;
  end_date: string;
  packet_limit: number;
  alert_limit: number;
  severity: string;
}

interface ScheduleForm {
  name: string;
  report_type: 'pdf' | 'csv' | 'json';
  frequency: 'daily' | 'weekly' | 'monthly';
  start_date_offset_days: number;
  end_date_offset_days: number;
  severity: string;
}

const PAGE_SIZE = 10;

export default function Reports() {
  const { isAdmin, isOperator } = useAuth();
  const canGenerate = isAdmin || isOperator;

  const [tab, setTab] = useState<'history' | 'schedules'>('history');

  // History state
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [showGenerate, setShowGenerate] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [downloadingId, setDownloadingId] = useState<number | null>(null);
  const [form, setForm] = useState<GenerateForm>({
    type: 'json',
    start_date: '',
    end_date: '',
    packet_limit: 10000,
    alert_limit: 1000,
    severity: 'all',
  });

  // Schedules state
  const [schedules, setSchedules] = useState<ScheduledReport[]>([]);
  const [schedulesLoading, setSchedulesLoading] = useState(false);
  const [showScheduleForm, setShowScheduleForm] = useState(false);
  const [scheduleForm, setScheduleForm] = useState<ScheduleForm>({
    name: '',
    report_type: 'json',
    frequency: 'daily',
    start_date_offset_days: 1,
    end_date_offset_days: 0,
    severity: 'all',
  });
  const [creatingSchedule, setCreatingSchedule] = useState(false);
  const [togglingId, setTogglingId] = useState<number | null>(null);
  const [deletingScheduleId, setDeletingScheduleId] = useState<number | null>(null);

  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const result = await apiService.listReports({ limit: PAGE_SIZE, offset });
      setReports(result.reports || []);
      setTotal(result.total || 0);
    } catch (err) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  }, [offset]);

  const fetchSchedules = useCallback(async () => {
    setSchedulesLoading(true);
    try {
      const result = await apiService.listScheduledReports();
      setSchedules(result.schedules || []);
    } catch (err) {
      console.error('Failed to load schedules:', err);
    } finally {
      setSchedulesLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  useEffect(() => {
    if (tab === 'schedules') fetchSchedules();
  }, [tab, fetchSchedules]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const payload: any = { type: form.type };
      if (form.start_date) payload.start_date = form.start_date;
      if (form.end_date) payload.end_date = form.end_date;
      if (form.packet_limit) payload.packet_limit = form.packet_limit;
      if (form.alert_limit) payload.alert_limit = form.alert_limit;
      if (form.severity !== 'all') payload.severity = form.severity;

      await apiService.generateParameterizedReport(payload);
      setShowGenerate(false);
      setOffset(0);
      await fetchReports();
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (report: ReportRecord) => {
    setDownloadingId(report.id);
    try {
      const blob = await apiService.downloadReportById(report.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = report.report_type === 'pdf' ? 'pdf' : report.report_type === 'csv' ? 'csv' : 'json';
      a.download = `report_${report.id}_${report.timestamp?.split('T')[0] || 'unknown'}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download report:', err);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (reportId: number) => {
    if (!confirm('Delete this report?')) return;
    setDeletingId(reportId);
    try {
      await apiService.deleteReport(reportId);
      setReports(prev => prev.filter(r => r.id !== reportId));
      setTotal(prev => prev - 1);
    } catch (err) {
      console.error('Failed to delete report:', err);
    } finally {
      setDeletingId(null);
    }
  };

  const handleCreateSchedule = async () => {
    setCreatingSchedule(true);
    try {
      const payload: any = {
        name: scheduleForm.name || 'Scheduled Report',
        report_type: scheduleForm.report_type,
        frequency: scheduleForm.frequency,
        start_date_offset_days: scheduleForm.start_date_offset_days,
        end_date_offset_days: scheduleForm.end_date_offset_days,
      };
      if (scheduleForm.severity !== 'all') payload.severity = scheduleForm.severity;
      await apiService.createScheduledReport(payload);
      setShowScheduleForm(false);
      setScheduleForm({
        name: '',
        report_type: 'json',
        frequency: 'daily',
        start_date_offset_days: 1,
        end_date_offset_days: 0,
        severity: 'all',
      });
      await fetchSchedules();
    } catch (err) {
      console.error('Failed to create schedule:', err);
    } finally {
      setCreatingSchedule(false);
    }
  };

  const handleToggleSchedule = async (schedule: ScheduledReport) => {
    setTogglingId(schedule.id);
    try {
      await apiService.updateScheduledReport(schedule.id, { is_active: !schedule.is_active });
      setSchedules(prev => prev.map(s => s.id === schedule.id ? { ...s, is_active: !s.is_active } : s));
    } catch (err) {
      console.error('Failed to toggle schedule:', err);
    } finally {
      setTogglingId(null);
    }
  };

  const handleDeleteSchedule = async (scheduleId: number) => {
    if (!confirm('Delete this scheduled report?')) return;
    setDeletingScheduleId(scheduleId);
    try {
      await apiService.deleteScheduledReport(scheduleId);
      setSchedules(prev => prev.filter(s => s.id !== scheduleId));
    } catch (err) {
      console.error('Failed to delete schedule:', err);
    } finally {
      setDeletingScheduleId(null);
    }
  };

  const filteredReports = reports.filter(r => {
    if (typeFilter !== 'all' && r.report_type !== typeFilter) return false;
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      return (
        String(r.id).includes(s) ||
        r.report_type?.toLowerCase().includes(s) ||
        r.timestamp?.toLowerCase().includes(s)
      );
    }
    return true;
  });

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'pdf': return <FileDown size={18} className="text-red-400" />;
      case 'csv': return <FileSpreadsheet size={18} className="text-green-400" />;
      case 'json': return <FileJson size={18} className="text-blue-400" />;
      default: return <FileText size={18} className="text-muted-foreground" />;
    }
  };

  const getTypeBadge = (type: string) => {
    switch (type) {
      case 'pdf': return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'csv': return 'bg-green-500/10 text-green-400 border-green-500/30';
      case 'json': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default: return 'bg-muted text-muted-foreground border-border';
    }
  };

  const getFrequencyBadge = (freq: string) => {
    switch (freq) {
      case 'daily': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'weekly': return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'monthly': return 'bg-violet-500/10 text-violet-400 border-violet-500/30';
      default: return 'bg-muted text-muted-foreground border-border';
    }
  };

  const formatFileSize = (bytes: number) => {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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
              <FileText className="text-primary" />
              Reports
            </h1>
            <p className="text-sm text-muted-foreground mt-1 font-mono">
              Generated report history & scheduled auto-generation
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={tab === 'history' ? fetchReports : fetchSchedules}
              disabled={loading || schedulesLoading}
              className="gap-2"
            >
              <RefreshCw size={16} className={cn((loading || schedulesLoading) && 'animate-spin')} />
              Refresh
            </Button>
            {canGenerate && tab === 'history' && (
              <Button size="sm" onClick={() => setShowGenerate(!showGenerate)} className="gap-2">
                <Plus size={16} />
                Generate Report
              </Button>
            )}
            {canGenerate && tab === 'schedules' && (
              <Button size="sm" onClick={() => setShowScheduleForm(!showScheduleForm)} className="gap-2">
                <Plus size={16} />
                New Schedule
              </Button>
            )}
          </div>
        </motion.div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 p-1 bg-muted/30 rounded-lg w-fit">
          {(['history', 'schedules'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "px-4 py-2 rounded-md text-sm font-medium transition-all",
                tab === t
                  ? "bg-primary/10 text-primary border border-primary/20"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t === 'history' ? 'Report History' : 'Schedules'}
            </button>
          ))}
        </div>

        {/* ===== HISTORY TAB ===== */}
        {tab === 'history' && (
          <>
            <AnimatePresence>
              {showGenerate && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.3 }}
                >
                  <Card className="border-primary/20 bg-card/80 backdrop-blur">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-lg flex items-center gap-2">
                        <Plus size={18} className="text-primary" />
                        Generate New Report
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Format</label>
                          <Select value={form.type} onValueChange={(v) => setForm(f => ({ ...f, type: v as any }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="json">JSON</SelectItem>
                              <SelectItem value="csv">CSV</SelectItem>
                              <SelectItem value="pdf">PDF</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Start Date</label>
                          <Input type="date" value={form.start_date} onChange={(e) => setForm(f => ({ ...f, start_date: e.target.value }))} />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">End Date</label>
                          <Input type="date" value={form.end_date} onChange={(e) => setForm(f => ({ ...f, end_date: e.target.value }))} />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Packet Limit</label>
                          <Input type="number" min={1} max={100000} value={form.packet_limit} onChange={(e) => setForm(f => ({ ...f, packet_limit: parseInt(e.target.value) || 10000 }))} />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Alert Limit</label>
                          <Input type="number" min={1} max={10000} value={form.alert_limit} onChange={(e) => setForm(f => ({ ...f, alert_limit: parseInt(e.target.value) || 1000 }))} />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Severity Filter</label>
                          <Select value={form.severity} onValueChange={(v) => setForm(f => ({ ...f, severity: v }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Severities</SelectItem>
                              <SelectItem value="critical">Critical</SelectItem>
                              <SelectItem value="high">High</SelectItem>
                              <SelectItem value="medium">Medium</SelectItem>
                              <SelectItem value="low">Low</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 mt-6">
                        <Button onClick={handleGenerate} disabled={generating} className="gap-2">
                          {generating ? <Loader2 size={16} className="animate-spin" /> : <FileText size={16} />}
                          {generating ? 'Generating...' : 'Generate'}
                        </Button>
                        <Button variant="ghost" onClick={() => setShowGenerate(false)}>Cancel</Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { label: 'Total Reports', value: total, icon: FileText, color: 'text-primary' },
                { label: 'PDF Reports', value: reports.filter(r => r.report_type === 'pdf').length, icon: FileDown, color: 'text-red-400' },
                { label: 'Total Size', value: formatFileSize(reports.reduce((s, r) => s + (r.file_size || 0), 0)), icon: Download, color: 'text-emerald-400' },
              ].map((stat, i) => (
                <motion.div key={stat.label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1, duration: 0.4 }}>
                  <Card className="bg-card/60 backdrop-blur border-border/40">
                    <CardContent className="p-4 flex items-center gap-4">
                      <div className={cn("p-2 rounded-lg bg-primary/10", stat.color)}><stat.icon size={20} /></div>
                      <div>
                        <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{stat.label}</p>
                        <p className="text-xl font-bold text-foreground">{stat.value}</p>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </div>

            {/* Filters */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative flex-1 max-w-xs">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input placeholder="Search reports..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="pl-9" />
                {searchTerm && (
                  <button onClick={() => setSearchTerm('')} className="absolute right-3 top-1/2 -translate-y-1/2">
                    <X size={14} className="text-muted-foreground hover:text-foreground" />
                  </button>
                )}
              </div>
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-[130px]">
                  <Filter size={14} className="mr-2" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="pdf">PDF</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Reports List */}
            <Card className="bg-card/60 backdrop-blur border-border/40">
              <CardContent className="p-0">
                {loading && reports.length === 0 ? (
                  <div className="flex items-center justify-center py-16">
                    <Loader2 size={32} className="animate-spin text-primary" />
                  </div>
                ) : filteredReports.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                    <FileText size={48} className="mb-4 opacity-30" />
                    <p className="text-lg font-medium">No reports found</p>
                    <p className="text-sm">Generate a report to get started</p>
                  </div>
                ) : (
                  <div className="divide-y divide-border/30">
                    <AnimatePresence>
                      {filteredReports.map((report, i) => (
                        <motion.div
                          key={report.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0, x: 20 }}
                          transition={{ delay: i * 0.03 }}
                          className="flex items-center gap-4 p-4 hover:bg-muted/30 transition-colors group"
                        >
                          <div className="shrink-0">{getTypeIcon(report.report_type)}</div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-foreground text-sm">Report #{report.id}</span>
                              <Badge variant="outline" className={cn("text-[10px] px-2 py-0", getTypeBadge(report.report_type))}>
                                {report.report_type?.toUpperCase()}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground font-mono">
                              <span className="flex items-center gap-1">
                                <Clock size={12} />
                                {report.timestamp ? format(new Date(report.timestamp), 'MMM d, yyyy HH:mm') : 'Unknown'}
                              </span>
                              <span>{report.total_packets?.toLocaleString()} packets</span>
                              <span>{report.total_alerts?.toLocaleString()} alerts</span>
                              <span>{formatFileSize(report.file_size)}</span>
                            </div>
                            {(report.start_date || report.end_date) && (
                              <div className="flex items-center gap-1 mt-1 text-[10px] text-muted-foreground/60 font-mono">
                                <Calendar size={10} />
                                {report.start_date ? format(new Date(report.start_date), 'MMM d, yyyy') : '...'}
                                {' — '}
                                {report.end_date ? format(new Date(report.end_date), 'MMM d, yyyy') : '...'}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-2 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                            <Button variant="ghost" size="sm" onClick={() => handleDownload(report)} disabled={downloadingId === report.id} className="gap-1.5 h-8">
                              {downloadingId === report.id ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
                              Download
                            </Button>
                            {isAdmin && (
                              <Button variant="ghost" size="sm" onClick={() => handleDelete(report.id)} disabled={deletingId === report.id} className="gap-1.5 h-8 text-red-400 hover:text-red-300 hover:bg-red-500/10">
                                {deletingId === report.id ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                              </Button>
                            )}
                          </div>
                        </motion.div>
                      ))}
                    </AnimatePresence>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-2">
                <p className="text-xs text-muted-foreground font-mono">
                  {total} report{total !== 1 ? 's' : ''} — page {currentPage} of {totalPages}
                </p>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} className="gap-1">
                    <ChevronLeft size={14} /> Prev
                  </Button>
                  <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)} className="gap-1">
                    Next <ChevronRight size={14} />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}

        {/* ===== SCHEDULES TAB ===== */}
        {tab === 'schedules' && (
          <>
            <AnimatePresence>
              {showScheduleForm && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.3 }}
                >
                  <Card className="border-primary/20 bg-card/80 backdrop-blur">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-lg flex items-center gap-2">
                        <Timer size={18} className="text-primary" />
                        New Scheduled Report
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Name</label>
                          <Input
                            placeholder="Daily Summary"
                            value={scheduleForm.name}
                            onChange={(e) => setScheduleForm(f => ({ ...f, name: e.target.value }))}
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Format</label>
                          <Select value={scheduleForm.report_type} onValueChange={(v) => setScheduleForm(f => ({ ...f, report_type: v as any }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="json">JSON</SelectItem>
                              <SelectItem value="csv">CSV</SelectItem>
                              <SelectItem value="pdf">PDF</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Frequency</label>
                          <Select value={scheduleForm.frequency} onValueChange={(v) => setScheduleForm(f => ({ ...f, frequency: v as any }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="daily">Daily</SelectItem>
                              <SelectItem value="weekly">Weekly</SelectItem>
                              <SelectItem value="monthly">Monthly</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Lookback (days)</label>
                          <Input
                            type="number"
                            min={1}
                            max={365}
                            value={scheduleForm.start_date_offset_days}
                            onChange={(e) => setScheduleForm(f => ({ ...f, start_date_offset_days: parseInt(e.target.value) || 1 }))}
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">End Offset (days)</label>
                          <Input
                            type="number"
                            min={0}
                            max={365}
                            value={scheduleForm.end_date_offset_days}
                            onChange={(e) => setScheduleForm(f => ({ ...f, end_date_offset_days: parseInt(e.target.value) || 0 }))}
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Severity Filter</label>
                          <Select value={scheduleForm.severity} onValueChange={(v) => setScheduleForm(f => ({ ...f, severity: v }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Severities</SelectItem>
                              <SelectItem value="critical">Critical</SelectItem>
                              <SelectItem value="high">High</SelectItem>
                              <SelectItem value="medium">Medium</SelectItem>
                              <SelectItem value="low">Low</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 mt-6">
                        <Button onClick={handleCreateSchedule} disabled={creatingSchedule} className="gap-2">
                          {creatingSchedule ? <Loader2 size={16} className="animate-spin" /> : <Timer size={16} />}
                          {creatingSchedule ? 'Creating...' : 'Create Schedule'}
                        </Button>
                        <Button variant="ghost" onClick={() => setShowScheduleForm(false)}>Cancel</Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>

            <Card className="bg-card/60 backdrop-blur border-border/40">
              <CardContent className="p-0">
                {schedulesLoading && schedules.length === 0 ? (
                  <div className="flex items-center justify-center py-16">
                    <Loader2 size={32} className="animate-spin text-primary" />
                  </div>
                ) : schedules.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                    <Timer size={48} className="mb-4 opacity-30" />
                    <p className="text-lg font-medium">No scheduled reports</p>
                    <p className="text-sm">Create a schedule to auto-generate reports</p>
                  </div>
                ) : (
                  <div className="divide-y divide-border/30">
                    <AnimatePresence>
                      {schedules.map((schedule, i) => (
                        <motion.div
                          key={schedule.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0, x: 20 }}
                          transition={{ delay: i * 0.03 }}
                          className="flex items-center gap-4 p-4 hover:bg-muted/30 transition-colors group"
                        >
                          <div className="shrink-0">
                            <Timer size={18} className={schedule.is_active ? 'text-emerald-400' : 'text-muted-foreground/50'} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-foreground text-sm">{schedule.name || `Schedule #${schedule.id}`}</span>
                              <Badge variant="outline" className={cn("text-[10px] px-2 py-0", getTypeBadge(schedule.report_type))}>
                                {schedule.report_type?.toUpperCase()}
                              </Badge>
                              <Badge variant="outline" className={cn("text-[10px] px-2 py-0", getFrequencyBadge(schedule.frequency))}>
                                {schedule.frequency?.toUpperCase()}
                              </Badge>
                              {!schedule.is_active && (
                                <Badge variant="outline" className="text-[10px] px-2 py-0 bg-muted/50 text-muted-foreground border-border">
                                  PAUSED
                                </Badge>
                              )}
                            </div>
                            <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground font-mono">
                              <span>{schedule.start_date_offset_days} day lookback</span>
                              {schedule.severity && (
                                <span>Severity: {schedule.severity}</span>
                              )}
                              {schedule.last_run_at && (
                                <span className="flex items-center gap-1">
                                  <Clock size={12} />
                                  Last run: {format(new Date(schedule.last_run_at), 'MMM d, yyyy HH:mm')}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                            {canGenerate && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleToggleSchedule(schedule)}
                                disabled={togglingId === schedule.id}
                                className={cn("gap-1.5 h-8", schedule.is_active ? 'text-amber-400 hover:text-amber-300' : 'text-emerald-400 hover:text-emerald-300')}
                              >
                                {togglingId === schedule.id ? <Loader2 size={14} className="animate-spin" /> : schedule.is_active ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
                                {schedule.is_active ? 'Pause' : 'Enable'}
                              </Button>
                            )}
                            {isAdmin && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDeleteSchedule(schedule.id)}
                                disabled={deletingScheduleId === schedule.id}
                                className="gap-1.5 h-8 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                              >
                                {deletingScheduleId === schedule.id ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                              </Button>
                            )}
                          </div>
                        </motion.div>
                      ))}
                    </AnimatePresence>
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </MainLayout>
  );
}
