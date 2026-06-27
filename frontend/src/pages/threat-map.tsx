import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Globe, Search, MapPin, AlertTriangle, RefreshCw,
  Loader2, WifiOff, ShieldAlert,
} from "lucide-react";
import { apiService } from "@/services/apiService";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import "leaflet/dist/leaflet.css";

interface ThreatPoint {
  ip: string;
  latitude: number;
  longitude: number;
  city: string | null;
  country: string | null;
  country_code: string | null;
  alert_count: number;
}

interface GeoResult {
  ip: string;
  city: string | null;
  country: string | null;
  country_code: string | null;
  subdivision: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracy_radius: number | null;
  timezone: string | null;
}

function ThreatMapLeaflet({ threats }: { threats: ThreatPoint[] }) {
  const [MapElement, setMapElement] = useState<React.ReactNode>(null);

  useEffect(() => {
    import('react-leaflet').then((mod) => {
      const { MapContainer, TileLayer, CircleMarker, Popup, useMap } = mod;
      const MapController = () => {
        const map = useMap();
        useEffect(() => {
          const timer = setTimeout(() => {
            map.invalidateSize();
          }, 250);
          return () => clearTimeout(timer);
        }, [map]);
        return null;
      };
      const el = (
        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ height: "100%", width: "100%", background: "#0a0f1a" }}
          className="rounded-lg"
        >
          <MapController />
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          {threats.map((t, i) => (
            <CircleMarker
              key={`${t.ip}-${i}`}
              center={[t.latitude, t.longitude]}
              radius={Math.max(6, Math.min(t.alert_count * 3, 25))}
              pathOptions={{
                color: t.alert_count >= 5 ? '#ef4444' : t.alert_count >= 2 ? '#f97316' : '#00d4ff',
                fillColor: t.alert_count >= 5 ? '#ef4444' : t.alert_count >= 2 ? '#f97316' : '#00d4ff',
                fillOpacity: 0.6,
                weight: 2,
              }}
            >
              <Popup>
                <div className="text-xs font-mono space-y-1 min-w-[140px]">
                  <div className="font-bold text-sm">{t.ip}</div>
                  {t.city && <div>{t.city}, {t.country}</div>}
                  {!t.city && t.country && <div>{t.country}</div>}
                  <div className="flex items-center gap-1">
                    <AlertTriangle size={10} className="text-red-500" />
                    <span>{t.alert_count} alert{t.alert_count !== 1 ? 's' : ''}</span>
                  </div>
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      );
      setMapElement(el);
    }).catch(() => {
      setMapElement(
        <div className="h-full flex items-center justify-center text-muted-foreground">
          <div className="text-center space-y-2">
            <Globe size={48} className="mx-auto opacity-30" />
            <p className="text-sm">Map library not available</p>
            <p className="text-xs">Install react-leaflet and leaflet packages</p>
          </div>
        </div>
      );
    });
  }, [threats]);

  if (!MapElement) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <Loader2 size={32} className="animate-spin mx-auto" />
        <p className="text-sm mt-2">Loading map...</p>
      </div>
    );
  }

  return <>{MapElement}</>;
}

export default function ThreatMapPage() {
  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [geoAvailable, setGeoAvailable] = useState(true);
  const [lookupIp, setLookupIp] = useState("");
  const [lookupResult, setLookupResult] = useState<GeoResult | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  const fetchThreats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiService.getGeoipStatus();
      setGeoAvailable(res.available);
      if (!res.available) {
        setThreats([]);
        setLoading(false);
        return;
      }
      const data = await apiService.getThreatMap();
      setThreats((data.threats || []) as unknown as ThreatPoint[]);
    } catch {
      setGeoAvailable(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 30000);
    return () => clearInterval(interval);
  }, [fetchThreats]);

  const handleLookup = async () => {
    if (!lookupIp.trim()) return;
    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);
    try {
      const result = await apiService.lookupGeoip(lookupIp.trim());
      setLookupResult(result as unknown as GeoResult);
    } catch (e: any) {
      setLookupError(e?.message || "Lookup failed");
    } finally {
      setLookupLoading(false);
    }
  };

  const criticalCount = threats.filter((t) => t.alert_count >= 5).length;
  const warningCount = threats.filter((t) => t.alert_count >= 2 && t.alert_count < 5).length;
  const lowCount = threats.filter((t) => t.alert_count < 2).length;

  return (
    <MainLayout>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
                <Globe size={22} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Threat Map</h1>
                <p className="text-sm text-muted-foreground">
                  GeoIP-based threat visualization
                </p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant="outline" className="font-mono text-xs">
              {threats.length} source{threats.length !== 1 ? "s" : ""}
            </Badge>
            <Button variant="outline" size="sm" onClick={fetchThreats} disabled={loading}>
              <RefreshCw size={14} className={cn(loading && "animate-spin")} />
            </Button>
          </div>
        </div>

        {!geoAvailable && !loading && (
          <Card className="border-yellow-500/30 bg-yellow-500/5">
            <CardContent className="p-4 flex items-start gap-3">
              <WifiOff size={20} className="text-yellow-500 mt-0.5" />
              <div className="space-y-1">
                <p className="text-sm font-semibold text-yellow-200">GeoIP Database Not Available</p>
                <p className="text-xs text-muted-foreground">
                  Download the MaxMind GeoLite2-City database (.mmdb) and place it at
                  <code className="mx-1 px-1 py-0.5 rounded bg-muted text-primary text-[10px]">
                    backend/data/GeoLite2-City.mmdb
                  </code>
                  or set the <code className="mx-1 px-1 py-0.5 rounded bg-muted text-primary text-[10px]">GEOLITE2_CITY_DB</code> environment variable.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-3">
            <Card className="h-[600px] overflow-hidden">
              <CardContent className="p-0 h-full">
                {loading ? (
                  <div className="h-full flex items-center justify-center">
                    <div className="text-center space-y-2">
                      <Loader2 size={32} className="animate-spin mx-auto text-primary" />
                      <p className="text-sm text-muted-foreground">Loading threat data...</p>
                    </div>
                  </div>
                ) : geoAvailable ? (
                  <ThreatMapLeaflet threats={threats} />
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground">
                    <div className="text-center space-y-3">
                      <Globe size={64} className="mx-auto opacity-20" />
                      <p className="text-sm">GeoIP database required</p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <AlertTriangle size={16} className="text-red-500" />
                  Threat Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-2.5 w-2.5 rounded-full bg-red-500" />
                    <span className="text-xs text-muted-foreground">Critical</span>
                  </div>
                  <Badge variant="destructive" className="text-[10px]">{criticalCount}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-2.5 w-2.5 rounded-full bg-orange-500" />
                    <span className="text-xs text-muted-foreground">Warning</span>
                  </div>
                  <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-[10px]">
                    {warningCount}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-2.5 w-2.5 rounded-full bg-primary" />
                    <span className="text-xs text-muted-foreground">Low</span>
                  </div>
                  <Badge variant="outline" className="text-[10px]">{lowCount}</Badge>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Search size={16} />
                  IP Lookup
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g. 8.8.8.8"
                    value={lookupIp}
                    onChange={(e) => setLookupIp(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleLookup()}
                    className="text-xs font-mono"
                  />
                  <Button size="sm" onClick={handleLookup} disabled={lookupLoading}>
                    {lookupLoading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
                  </Button>
                </div>

                <AnimatePresence mode="wait">
                  {lookupError && (
                    <motion.div
                      key="error"
                      initial={{ opacity: 0, y: -5 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      className="text-xs text-red-400 p-2 rounded bg-red-500/10"
                    >
                      {lookupError}
                    </motion.div>
                  )}

                  {lookupResult && (
                    <motion.div
                      key="result"
                      initial={{ opacity: 0, y: -5 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      className="space-y-2 p-2 rounded bg-primary/5 border border-primary/10"
                    >
                      <div className="flex items-center gap-2">
                        <MapPin size={12} className="text-primary" />
                        <span className="text-xs font-mono font-semibold">{lookupResult.ip}</span>
                      </div>
                      {lookupResult.city && (
                        <div className="text-xs text-muted-foreground">
                          {lookupResult.city}{lookupResult.subdivision ? `, ${lookupResult.subdivision}` : ""}, {lookupResult.country}
                        </div>
                      )}
                      {!lookupResult.city && lookupResult.country && (
                        <div className="text-xs text-muted-foreground">{lookupResult.country}</div>
                      )}
                      {lookupResult.country_code && (
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {lookupResult.country_code}
                        </Badge>
                      )}
                      {lookupResult.latitude != null && (
                        <div className="text-[10px] font-mono text-muted-foreground">
                          {lookupResult.latitude.toFixed(4)}, {lookupResult.longitude?.toFixed(4)}
                        </div>
                      )}
                      {lookupResult.timezone && (
                        <div className="text-[10px] text-muted-foreground">
                          {lookupResult.timezone}
                        </div>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <ShieldAlert size={16} />
                  Top Sources
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 max-h-[180px] overflow-y-auto">
                {threats.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-4">No threat data</p>
                ) : (
                  [...threats]
                    .sort((a, b) => b.alert_count - a.alert_count)
                    .slice(0, 10)
                    .map((t, i) => (
                      <div key={t.ip} className="flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-muted-foreground w-4 shrink-0">{i + 1}.</span>
                          <span className="font-mono truncate">{t.ip}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {t.country_code && (
                            <span className="text-[10px] font-mono text-muted-foreground">{t.country_code}</span>
                          )}
                          <Badge
                            variant={t.alert_count >= 5 ? "destructive" : "outline"}
                            className="text-[10px] h-5"
                          >
                            {t.alert_count}
                          </Badge>
                        </div>
                      </div>
                    ))
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
