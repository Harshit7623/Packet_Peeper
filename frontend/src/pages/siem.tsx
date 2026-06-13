import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Radio, Plus, Trash2, ToggleLeft, ToggleRight, TestTube,
  Loader2, Send, AlertCircle, CheckCircle2, ExternalLink,
} from "lucide-react";
import { apiService } from "@/services/apiService";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

interface SIEMIntegration {
  id: number;
  name: string;
  type: "webhook" | "syslog";
  enabled: boolean;
  url: string;
  host: string;
  port: number;
  protocol: "udp" | "tcp";
  format: "cef" | "json" | "leef";
  severity_filter: string[];
  verify_ssl: boolean;
  sent_count: number;
  error_count: number;
  last_sent: string | null;
  last_error: string | null;
}

const SEVERITY_OPTIONS = ["low", "medium", "high", "critical"];

export default function SIEMPage() {
  const [integrations, setIntegrations] = useState<SIEMIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [testing, setTesting] = useState<number | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; success: boolean; error?: string } | null>(null);

  const [form, setForm] = useState({
    name: "",
    type: "webhook" as "webhook" | "syslog",
    url: "",
    host: "",
    port: 514,
    protocol: "udp" as "udp" | "tcp",
    format: "cef" as "cef" | "json" | "leef",
    severity_filter: ["high", "critical"],
    verify_ssl: true,
  });

  const fetchIntegrations = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiService.getSIEMIntegrations();
      setIntegrations((data as any).integrations || []);
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIntegrations();
  }, [fetchIntegrations]);

  const handleCreate = async () => {
    if (!form.name.trim()) return;
    try {
      await apiService.createSIEMIntegration(form);
      setShowForm(false);
      setForm({
        name: "", type: "webhook", url: "", host: "", port: 514,
        protocol: "udp", format: "cef", severity_filter: ["high", "critical"], verify_ssl: true,
      });
      fetchIntegrations();
    } catch {}
  };

  const handleDelete = async (id: number) => {
    try {
      await apiService.deleteSIEMIntegration(id);
      fetchIntegrations();
    } catch {}
  };

  const handleToggle = async (id: number) => {
    try {
      await apiService.toggleSIEMIntegration(id);
      fetchIntegrations();
    } catch {}
  };

  const handleTest = async (id: number) => {
    setTesting(id);
    setTestResult(null);
    try {
      const result = await apiService.testSIEMIntegration(id);
      setTestResult({ id, success: (result as any).success, error: (result as any).error });
    } catch (e: any) {
      setTestResult({ id, success: false, error: e?.message || "Test failed" });
    } finally {
      setTesting(null);
    }
  };

  const toggleSeverity = (sev: string) => {
    setForm((prev) => ({
      ...prev,
      severity_filter: prev.severity_filter.includes(sev)
        ? prev.severity_filter.filter((s) => s !== sev)
        : [...prev.severity_filter, sev],
    }));
  };

  return (
    <MainLayout>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
                <Radio size={22} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">SIEM Integration</h1>
                <p className="text-sm text-muted-foreground">
                  Forward alerts to Splunk, ELK, QRadar, and more
                </p>
              </div>
            </div>
          </div>
          <Button onClick={() => setShowForm(!showForm)} size="sm">
            <Plus size={14} />
          </Button>
        </div>

        <AnimatePresence>
          {showForm && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
            >
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold">New Integration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-muted-foreground">Name</label>
                      <Input
                        value={form.name}
                        onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                        placeholder="e.g. Splunk Forwarder"
                        className="text-xs"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-muted-foreground">Type</label>
                      <Select
                        value={form.type}
                        onValueChange={(v: any) => setForm((f) => ({ ...f, type: v }))}
                      >
                        <SelectTrigger className="text-xs"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="webhook">Webhook (HTTP POST)</SelectItem>
                          <SelectItem value="syslog">Syslog</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    {form.type === "webhook" ? (
                      <div className="space-y-2">
                        <label className="text-xs font-semibold text-muted-foreground">Webhook URL</label>
                        <Input
                          value={form.url}
                          onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                          placeholder="https://splunk.example.com:8088/services/collector"
                          className="text-xs font-mono"
                        />
                      </div>
                    ) : (
                      <>
                        <div className="space-y-2">
                          <label className="text-xs font-semibold text-muted-foreground">Syslog Host</label>
                          <Input
                            value={form.host}
                            onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))}
                            placeholder="10.0.0.100"
                            className="text-xs font-mono"
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-semibold text-muted-foreground">Port</label>
                          <Input
                            type="number"
                            value={form.port}
                            onChange={(e) => setForm((f) => ({ ...f, port: parseInt(e.target.value) || 514 }))}
                            className="text-xs font-mono w-24"
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-semibold text-muted-foreground">Protocol</label>
                          <Select
                            value={form.protocol}
                            onValueChange={(v: any) => setForm((f) => ({ ...f, protocol: v }))}
                          >
                            <SelectTrigger className="text-xs w-32"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="udp">UDP</SelectItem>
                              <SelectItem value="tcp">TCP</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </>
                    )}

                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-muted-foreground">Format</label>
                      <Select
                        value={form.format}
                        onValueChange={(v: any) => setForm((f) => ({ ...f, format: v }))}
                      >
                        <SelectTrigger className="text-xs w-40"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="cef">CEF (Common Event Format)</SelectItem>
                          <SelectItem value="json">JSON</SelectItem>
                          <SelectItem value="leef">LEEF</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-muted-foreground">Severity Filter</label>
                    <div className="flex gap-2">
                      {SEVERITY_OPTIONS.map((sev) => (
                        <button
                          key={sev}
                          onClick={() => toggleSeverity(sev)}
                          className={cn(
                            "px-3 py-1 rounded text-xs font-semibold border transition-colors",
                            form.severity_filter.includes(sev)
                              ? "border-primary text-primary bg-primary/10"
                              : "border-border/30 text-muted-foreground hover:border-border"
                          )}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Button onClick={handleCreate} size="sm" disabled={!form.name.trim()}>
                      <Plus size={14} /> Create
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => setShowForm(false)}>
                      Cancel
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="space-y-3">
          {loading ? (
            <div className="flex justify-center py-12">
              <Loader2 size={24} className="animate-spin text-muted-foreground" />
            </div>
          ) : integrations.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Radio size={40} className="mx-auto mb-3 opacity-20" />
                <p className="text-sm">No SIEM integrations configured</p>
                <p className="text-xs mt-1">Click + to add a webhook or syslog forwarder</p>
              </CardContent>
            </Card>
          ) : (
            integrations.map((intg) => (
              <Card key={intg.id} className={cn(!intg.enabled && "opacity-60")}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <button onClick={() => handleToggle(intg.id)} className="text-muted-foreground hover:text-foreground">
                        {intg.enabled ? (
                          <ToggleRight size={20} className="text-primary" />
                        ) : (
                          <ToggleLeft size={20} />
                        )}
                      </button>
                      <div>
                        <div className="font-semibold text-sm">{intg.name}</div>
                        <div className="text-xs font-mono text-muted-foreground">
                          {intg.type === "webhook" ? intg.url : `${intg.host}:${intg.port} (${intg.protocol})`}
                        </div>
                      </div>
                      <Badge variant="outline" className="text-[10px] font-mono">{intg.format.toUpperCase()}</Badge>
                      <Badge variant={intg.type === "webhook" ? "default" : "secondary"} className="text-[10px]">
                        {intg.type}
                      </Badge>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right text-xs text-muted-foreground">
                        <div>{intg.sent_count} sent</div>
                        {intg.last_sent && (
                          <div className="text-[10px]">Last: {new Date(intg.last_sent).toLocaleTimeString()}</div>
                        )}
                      </div>

                      {intg.last_error && (
                        <Badge variant="destructive" className="text-[10px] max-w-[200px] truncate">
                          <AlertCircle size={10} className="mr-1" />
                          {intg.last_error}
                        </Badge>
                      )}

                      {testResult && testResult.id === intg.id && (
                        testResult.success ? (
                          <CheckCircle2 size={16} className="text-green-500" />
                        ) : (
                          <AlertCircle size={16} className="text-red-500" />
                        )
                      )}

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTest(intg.id)}
                        disabled={testing === intg.id || !intg.enabled}
                        className="text-xs h-7"
                      >
                        {testing === intg.id ? (
                          <Loader2 size={12} className="animate-spin" />
                        ) : (
                          <TestTube size={12} />
                        )}
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => handleDelete(intg.id)} className="text-destructive h-7">
                        <Trash2 size={12} />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </div>
    </MainLayout>
  );
}
