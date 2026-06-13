import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  FileSearch, RefreshCw, Loader2, ChevronLeft, ChevronRight,
  ArrowRight, Layers, Hash,
} from "lucide-react";
import { apiService } from "@/services/apiService";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

interface PayloadPacket {
  index: number;
  has_raw: boolean;
  raw_size: number;
  timestamp: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  service: string;
}

interface LayerInfo {
  name: string;
  fields: Record<string, unknown>;
}

interface InspectionResult {
  packet_id: number;
  meta: Record<string, unknown>;
  layers: LayerInfo[];
  hex_dump: string[];
  ascii_dump: string[];
  total_bytes: number;
  truncated: boolean;
  raw_size: number;
}

function HexView({ hexDump, asciiDump }: { hexDump: string[]; asciiDump: string[] }) {
  return (
    <div className="font-mono text-[11px] leading-[18px] bg-black/40 rounded p-3 overflow-auto max-h-[400px] space-y-0">
      {hexDump.map((line, i) => (
        <div key={i} className="flex gap-4">
          <span className="text-muted-foreground select-none">{line}</span>
          <span className="text-primary/70">{asciiDump[i]}</span>
        </div>
      ))}
    </div>
  );
}

function LayerAccordion({ layers }: { layers: LayerInfo[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggle = (name: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  if (layers.length === 0) return <p className="text-xs text-muted-foreground">No layer data</p>;

  return (
    <div className="space-y-2">
      {layers.map((layer) => {
        const isOpen = expanded.has(layer.name);
        return (
          <div key={layer.name} className="border border-border/30 rounded overflow-hidden">
            <button
              onClick={() => toggle(layer.name)}
              className="w-full flex items-center justify-between px-3 py-2 bg-muted/30 hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Layers size={14} className="text-primary" />
                <span className="text-xs font-semibold">{layer.name}</span>
                <Badge variant="outline" className="text-[10px]">
                  {Object.keys(layer.fields).length} fields
                </Badge>
              </div>
              <ChevronRight
                size={14}
                className={cn("transition-transform", isOpen && "rotate-90")}
              />
            </button>
            <AnimatePresence>
              {isOpen && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden"
                >
                  <div className="p-3 space-y-1 bg-card/50">
                    {Object.entries(layer.fields).map(([key, value]) => (
                      <div key={key} className="flex items-center gap-2 text-[11px] font-mono">
                        <span className="text-muted-foreground min-w-[120px]">{key}</span>
                        <ArrowRight size={10} className="text-muted-foreground/50" />
                        <span className="text-foreground">{String(value ?? "—")}</span>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </div>
  );
}

export default function PayloadInspectionPage() {
  const [packets, setPackets] = useState<PayloadPacket[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<InspectionResult | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [viewMode, setViewMode] = useState<"hex" | "ascii">("hex");

  const fetchPackets = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiService.getRecentPayloads();
      setPackets((data as any).packets || []);
    } catch {
      setPackets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPackets();
    const interval = setInterval(fetchPackets, 5000);
    return () => clearInterval(interval);
  }, [fetchPackets]);

  const inspectPacket = async (index: number) => {
    setInspecting(true);
    setSelected(null);
    try {
      const data = await apiService.inspectPayload(index);
      setSelected(data as unknown as InspectionResult);
    } catch {
      setSelected(null);
    } finally {
      setInspecting(false);
    }
  };

  return (
    <MainLayout>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
                <FileSearch size={22} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Payload Inspector</h1>
                <p className="text-sm text-muted-foreground">
                  Deep packet inspection with hex dump and protocol layer analysis
                </p>
              </div>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={fetchPackets} disabled={loading}>
            <RefreshCw size={14} className={cn(loading && "animate-spin")} />
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold">Recent Packets</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 max-h-[600px] overflow-y-auto">
                {loading && packets.length === 0 ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 size={20} className="animate-spin text-muted-foreground" />
                  </div>
                ) : packets.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-8">
                    No packets captured yet. Start monitoring first.
                  </p>
                ) : (
                  packets.map((pkt) => (
                    <button
                      key={pkt.index}
                      onClick={() => pkt.has_raw && inspectPacket(pkt.index)}
                      disabled={!pkt.has_raw}
                      className={cn(
                        "w-full text-left p-2 rounded border border-border/20 hover:border-primary/30 transition-colors",
                        selected?.packet_id === pkt.index && "border-primary/50 bg-primary/5",
                        !pkt.has_raw && "opacity-50 cursor-not-allowed"
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px] font-mono",
                              pkt.protocol === "TCP" && "border-blue-500/30 text-blue-400",
                              pkt.protocol === "UDP" && "border-green-500/30 text-green-400",
                              pkt.protocol === "ICMP" && "border-yellow-500/30 text-yellow-400",
                              pkt.protocol === "ARP" && "border-purple-500/30 text-purple-400"
                            )}
                          >
                            {pkt.protocol}
                          </Badge>
                          <span className="text-[11px] font-mono text-foreground truncate">
                            {pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}
                          </span>
                        </div>
                        {pkt.has_raw && (
                          <span className="text-[10px] text-muted-foreground font-mono">
                            {pkt.raw_size}B
                          </span>
                        )}
                      </div>
                      {pkt.service && (
                        <div className="text-[10px] text-muted-foreground mt-1 truncate">
                          {pkt.service}
                        </div>
                      )}
                    </button>
                  ))
                )}
              </CardContent>
            </Card>
          </div>

          <div className="lg:col-span-2 space-y-4">
            {selected ? (
              <>
                <Card>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Hash size={16} className="text-primary" />
                        Packet #{selected.packet_id}
                      </CardTitle>
                      <div className="flex items-center gap-2">
                        <Button
                          variant={viewMode === "hex" ? "default" : "outline"}
                          size="sm"
                          onClick={() => setViewMode("hex")}
                          className="text-xs h-7"
                        >
                          Hex
                        </Button>
                        <Button
                          variant={viewMode === "ascii" ? "default" : "outline"}
                          size="sm"
                          onClick={() => setViewMode("ascii")}
                          className="text-xs h-7"
                        >
                          ASCII
                        </Button>
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {selected.total_bytes} bytes
                        </Badge>
                        {selected.truncated && (
                          <Badge variant="destructive" className="text-[10px]">
                            Truncated
                          </Badge>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <HexView
                      hexDump={selected.hex_dump}
                      asciiDump={selected.ascii_dump}
                    />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Layers size={16} className="text-primary" />
                      Protocol Layers
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <LayerAccordion layers={selected.layers} />
                  </CardContent>
                </Card>
              </>
            ) : inspecting ? (
              <Card className="h-[400px]">
                <CardContent className="h-full flex items-center justify-center">
                  <Loader2 size={24} className="animate-spin text-primary" />
                </CardContent>
              </Card>
            ) : (
              <Card className="h-[400px]">
                <CardContent className="h-full flex items-center justify-center text-muted-foreground">
                  <div className="text-center space-y-3">
                    <FileSearch size={48} className="mx-auto opacity-20" />
                    <p className="text-sm">Select a packet to inspect its payload</p>
                    <p className="text-xs text-muted-foreground/60">
                      Packets with raw data available are clickable
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
