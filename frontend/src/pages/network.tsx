import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Laptop, Smartphone, Router, Wifi, Shield, Tablet, Tv, Loader2, Grid3X3, Circle, Zap, Activity, Eye } from "lucide-react";
import { useMonitorStore } from "@/store/monitorStore";
import { socketService } from "@/services/socketService";
import { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";

const iconMap: Record<string, any> = {
  router: Router,
  pc: Laptop,
  laptop: Laptop,
  tv: Tv,
  mobile: Smartphone,
  phone: Smartphone,
  tablet: Tablet,
  iot: Wifi,
  default: Shield
};

const statusColors = {
  online: { bg: 'bg-emerald-500', glow: 'shadow-[0_0_20px_rgba(16,185,129,0.6)]', text: 'text-emerald-400' },
  offline: { bg: 'bg-gray-500', glow: '', text: 'text-gray-400' },
  warning: { bg: 'bg-amber-500', glow: 'shadow-[0_0_20px_rgba(245,158,11,0.6)]', text: 'text-amber-400' }
};

type ViewMode = 'topology' | 'grid';

interface DeviceNode {
  id: number;
  name: string;
  location: string;
  type: string;
  status: 'online' | 'offline' | 'warning';
  mac: string;
  packets: number;
  angle?: number;
  distance?: number;
}

export default function NetworkMap() {
  const { devices } = useMonitorStore();
  const [isScanning, setIsScanning] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('topology');
  const [selectedDevice, setSelectedDevice] = useState<DeviceNode | null>(null);
  const [hoveredDevice, setHoveredDevice] = useState<number | null>(null);
  const [scanPulse, setScanPulse] = useState(0);
  
  // Continuous scanning animation
  useEffect(() => {
    const interval = setInterval(() => {
      setScanPulse(prev => (prev + 1) % 360);
    }, 50);
    return () => clearInterval(interval);
  }, []);
  
  const handleScanNetwork = () => {
    setIsScanning(true);
    socketService.scanDevices();
    setTimeout(() => setIsScanning(false), 5000);
  };
  
  // Use real devices only - no demo data
  const displayDevices: DeviceNode[] = useMemo(() => {
    if (devices.length === 0) return [];
    
    const baseDevices = devices.map((d, i) => ({
      id: i,
      name: d.hostname || `Device ${i + 1}`,
      location: d.ip_address,
      type: d.device_type?.toLowerCase() || 'default',
      status: 'online' as const,
      mac: d.mac_address,
       packets: (d.packets_in || 0) + (d.packets_out || 0)
    }));
    
    // Calculate positions for star topology (excluding router which is center)
    const nonRouterDevices = baseDevices.filter(d => d.type !== 'router');
    const routerDevice = baseDevices.find(d => d.type === 'router');
    
    const positionedDevices = nonRouterDevices.map((device, index) => ({
      ...device,
      angle: (360 / nonRouterDevices.length) * index,
      distance: 140 + Math.random() * 30 // Slight variation in distance
    }));
    
    if (routerDevice) {
      return [{ ...routerDevice, angle: 0, distance: 0 }, ...positionedDevices];
    }
    return positionedDevices;
  }, [devices]);

  const routerDevice = displayDevices.find(d => d.type === 'router');
  const connectedDevices = displayDevices.filter(d => d.type !== 'router');

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header with View Toggle */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
              <Activity className="text-primary animate-pulse" />
              Network Topology
            </h1>
            <p className="text-muted-foreground text-lg">
              {devices.length > 0 ? (
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  {devices.length} active devices detected
                </span>
              ) : (
                'Visualize your network infrastructure'
              )}
            </p>
          </motion.div>
          
          <motion.div 
            className="flex items-center gap-3"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="bg-card/60 border border-border/50 rounded-xl p-1 flex">
              <Button
                variant={viewMode === 'topology' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('topology')}
                className="gap-2"
              >
                <Circle size={16} />
                Topology
              </Button>
              <Button
                variant={viewMode === 'grid' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('grid')}
                className="gap-2"
              >
                <Grid3X3 size={16} />
                Grid
              </Button>
            </div>
            
            <Button
              onClick={handleScanNetwork}
              disabled={isScanning}
              className="gap-2 bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30"
            >
              {isScanning ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Wifi size={16} />
                  Scan Network
                </>
              )}
            </Button>
          </motion.div>
        </div>

        <AnimatePresence mode="wait">
          {viewMode === 'topology' ? (
            <motion.div
              key="topology"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3 }}
            >
              {/* Star Topology Visualization */}
              <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden">
                <CardContent className="p-0">
                  {displayDevices.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-[600px] text-center">
                      <Wifi size={64} className="text-muted-foreground/30 mb-4" />
                      <h3 className="text-xl font-semibold text-muted-foreground mb-2">No Devices Detected</h3>
                      <p className="text-sm text-muted-foreground/70 max-w-md mb-6">
                        Start packet capture to detect devices on your local network.
                      </p>
                      <Button
                        onClick={handleScanNetwork}
                        disabled={isScanning}
                        className="gap-2"
                      >
                        {isScanning ? (
                          <>
                            <Loader2 size={16} className="animate-spin" />
                            Scanning...
                          </>
                        ) : (
                          <>
                            <Wifi size={16} />
                            Scan Network
                          </>
                        )}
                      </Button>
                    </div>
                  ) : (
                  <div className="relative w-full h-[600px] flex items-center justify-center overflow-hidden">
                    {/* Background Grid */}
                    <div className="absolute inset-0 opacity-10">
                      <svg width="100%" height="100%">
                        <defs>
                          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-primary" />
                          </pattern>
                        </defs>
                        <rect width="100%" height="100%" fill="url(#grid)" />
                      </svg>
                    </div>
                    
                    {/* Radar Sweep Animation */}
                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                      <div 
                        className="w-[400px] h-[400px] rounded-full"
                        style={{
                          background: `conic-gradient(from ${scanPulse}deg, transparent 0deg, rgba(147, 51, 234, 0.3) 30deg, transparent 60deg)`,
                        }}
                      />
                    </div>
                    
                    {/* Radar Circles */}
                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                      {[100, 160, 220, 280].map((radius, i) => (
                        <motion.div
                          key={radius}
                          className="absolute rounded-full border border-primary/20"
                          style={{ width: radius * 2, height: radius * 2 }}
                          initial={{ opacity: 0, scale: 0 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ duration: 0.5, delay: i * 0.1 }}
                        />
                      ))}
                    </div>
                    
                    {/* Scanning Pulse */}
                    {isScanning && (
                      <motion.div
                        className="absolute rounded-full border-2 border-primary"
                        initial={{ width: 0, height: 0, opacity: 1 }}
                        animate={{ width: 600, height: 600, opacity: 0 }}
                        transition={{ duration: 2, repeat: Infinity, ease: "easeOut" }}
                      />
                    )}
                    
                    {/* Connection Lines */}
                    <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 1 }}>
                      {connectedDevices.map((device, index) => {
                        const angle = ((device.angle || 0) * Math.PI) / 180;
                        const distance = device.distance || 150;
                        const x = Math.cos(angle) * distance;
                        const y = Math.sin(angle) * distance;
                        const centerX = 50; // percent
                        const centerY = 50; // percent
                        const isHovered = hoveredDevice === device.id;
                        
                        return (
                          <motion.line
                            key={device.id}
                            x1="50%"
                            y1="50%"
                            x2={`calc(50% + ${x}px)`}
                            y2={`calc(50% + ${y}px)`}
                            stroke={device.status === 'online' ? (isHovered ? '#a855f7' : '#6b21a8') : '#374151'}
                            strokeWidth={isHovered ? 3 : 1.5}
                            strokeDasharray={device.status === 'offline' ? '5,5' : 'none'}
                            initial={{ pathLength: 0, opacity: 0 }}
                            animate={{ pathLength: 1, opacity: device.status === 'online' ? 0.6 : 0.3 }}
                            transition={{ duration: 0.8, delay: index * 0.1 }}
                          >
                            {device.status === 'online' && (
                              <animate
                                attributeName="stroke-opacity"
                                values="0.3;0.8;0.3"
                                dur="2s"
                                repeatCount="indefinite"
                              />
                            )}
                          </motion.line>
                        );
                      })}
                    </svg>
                    
                    {/* Central Router Node */}
                    {routerDevice && (
                      <motion.div
                        className="absolute z-20 cursor-pointer"
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: "spring", stiffness: 200, delay: 0.3 }}
                        onClick={() => setSelectedDevice(routerDevice)}
                        whileHover={{ scale: 1.1 }}
                      >
                        <div className={`relative p-6 rounded-full bg-gradient-to-br from-primary to-purple-700 ${statusColors[routerDevice.status].glow}`}>
                          <Router size={32} className="text-white" />
                          <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-emerald-500 border-2 border-background animate-pulse" />
                        </div>
                        <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 whitespace-nowrap">
                          <p className="text-xs font-bold text-foreground text-center">{routerDevice.name}</p>
                          <p className="text-[10px] text-muted-foreground text-center font-mono">{routerDevice.location}</p>
                        </div>
                      </motion.div>
                    )}
                    
                    {/* Device Nodes */}
                    {connectedDevices.map((device, index) => {
                      const Icon = iconMap[device.type] || iconMap.default;
                      const angle = ((device.angle || 0) * Math.PI) / 180;
                      const distance = device.distance || 150;
                      const x = Math.cos(angle) * distance;
                      const y = Math.sin(angle) * distance;
                      const isHovered = hoveredDevice === device.id;
                      
                      return (
                        <motion.div
                          key={device.id}
                          className="absolute z-10 cursor-pointer"
                          style={{
                            left: `calc(50% + ${x}px - 24px)`,
                            top: `calc(50% + ${y}px - 24px)`,
                          }}
                          initial={{ scale: 0, opacity: 0 }}
                          animate={{ scale: 1, opacity: 1 }}
                          transition={{ type: "spring", stiffness: 200, delay: 0.5 + index * 0.1 }}
                          onMouseEnter={() => setHoveredDevice(device.id)}
                          onMouseLeave={() => setHoveredDevice(null)}
                          onClick={() => setSelectedDevice(device)}
                          whileHover={{ scale: 1.2, zIndex: 30 }}
                        >
                          <div className={`relative p-4 rounded-full transition-all duration-300 ${
                            device.status === 'online' 
                              ? 'bg-card border-2 border-primary/50 hover:border-primary hover:shadow-[0_0_30px_rgba(147,51,234,0.4)]' 
                              : device.status === 'warning'
                              ? 'bg-card border-2 border-amber-500/50 hover:border-amber-500'
                              : 'bg-card/50 border-2 border-gray-600'
                          }`}>
                            <Icon size={20} className={statusColors[device.status].text} />
                            
                            {/* Status Indicator */}
                            <div className={`absolute -top-1 -right-1 w-3 h-3 rounded-full ${statusColors[device.status].bg} ${
                              device.status === 'online' ? 'animate-pulse' : ''
                            }`} />
                            
                            {/* Packet Activity Indicator */}
                            {device.status === 'online' && device.packets > 0 && (
                              <motion.div
                                className="absolute -bottom-1 -left-1"
                                animate={{ scale: [1, 1.3, 1] }}
                                transition={{ duration: 1, repeat: Infinity }}
                              >
                                <Zap size={12} className="text-primary" />
                              </motion.div>
                            )}
                          </div>
                          
                          {/* Hover Tooltip */}
                          <AnimatePresence>
                            {isHovered && (
                              <motion.div
                                className="absolute left-1/2 -translate-x-1/2 bottom-full mb-3 z-50"
                                initial={{ opacity: 0, y: 10, scale: 0.9 }}
                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                exit={{ opacity: 0, y: 10, scale: 0.9 }}
                                transition={{ duration: 0.15 }}
                              >
                                <div className="bg-card border border-border/80 rounded-xl p-3 shadow-xl min-w-[180px]">
                                  <p className="font-bold text-foreground text-sm">{device.name}</p>
                                  <p className="text-xs text-muted-foreground font-mono">{device.location}</p>
                                  <p className="text-[10px] text-muted-foreground font-mono mt-1">{device.mac}</p>
                                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-border/50">
                                    <span className="text-[10px] text-muted-foreground">Packets</span>
                                    <span className="text-xs font-bold text-primary">{device.packets.toLocaleString()}</span>
                                  </div>
                                  <div className="flex items-center justify-between mt-1">
                                    <span className="text-[10px] text-muted-foreground">Status</span>
                                    <span className={`text-xs font-bold ${statusColors[device.status].text}`}>
                                      {device.status.charAt(0).toUpperCase() + device.status.slice(1)}
                                    </span>
                                  </div>
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </motion.div>
                      );
                    })}
                    
                    {/* Legend */}
                    <motion.div 
                      className="absolute bottom-4 left-4 bg-card/80 backdrop-blur border border-border/50 rounded-xl p-4"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 1 }}
                    >
                      <p className="text-xs font-bold text-foreground mb-3">Device Status</p>
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
                          <span className="text-xs text-muted-foreground">Online</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-amber-500" />
                          <span className="text-xs text-muted-foreground">Warning</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-gray-500" />
                          <span className="text-xs text-muted-foreground">Offline</span>
                        </div>
                      </div>
                    </motion.div>
                    
                    {/* Stats */}
                    <motion.div 
                      className="absolute bottom-4 right-4 bg-card/80 backdrop-blur border border-border/50 rounded-xl p-4"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 1.1 }}
                    >
                      <div className="flex items-center gap-6">
                        <div className="text-center">
                          <p className="text-2xl font-bold text-foreground">{displayDevices.length}</p>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-emerald-400">{displayDevices.filter(d => d.status === 'online').length}</p>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Online</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-amber-400">{displayDevices.filter(d => d.status === 'warning').length}</p>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Warning</p>
                        </div>
                      </div>
                    </motion.div>
                  </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          ) : (
            <motion.div
              key="grid"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3 }}
            >
              {/* Grid View */}
              {displayDevices.length === 0 ? (
                <Card className="bg-card/40 border-border/50 rounded-2xl">
                  <CardContent className="flex flex-col items-center justify-center py-20 text-center">
                    <Wifi size={64} className="text-muted-foreground/30 mb-4" />
                    <h3 className="text-xl font-semibold text-muted-foreground mb-2">No Devices Detected</h3>
                    <p className="text-sm text-muted-foreground/70 max-w-md mb-6">
                      Start packet capture to detect devices on your local network.
                    </p>
                    <Button
                      onClick={handleScanNetwork}
                      disabled={isScanning}
                      className="gap-2"
                    >
                      {isScanning ? (
                        <>
                          <Loader2 size={16} className="animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Wifi size={16} />
                          Scan Network
                        </>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              ) : (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {displayDevices.map((device, index) => {
                  const Icon = iconMap[device.type] || iconMap.default;
                  return (
                    <motion.div
                      key={device.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
                    >
                      <Card 
                        className={`bg-card/40 border-border/50 rounded-2xl hover:border-primary/50 transition-all cursor-pointer group hover:shadow-[0_0_30px_rgba(147,51,234,0.2)] ${
                          selectedDevice?.id === device.id ? 'border-primary ring-2 ring-primary/20' : ''
                        }`}
                        onClick={() => setSelectedDevice(device)}
                      >
                        <CardContent className="pt-6">
                          <div className="flex items-start justify-between mb-4">
                            <motion.div 
                              className={`p-3 rounded-2xl ${device.status === 'online' ? 'bg-primary/10 text-primary' : device.status === 'warning' ? 'bg-amber-500/10 text-amber-500' : 'bg-muted text-muted-foreground'}`}
                              whileHover={{ scale: 1.1, rotate: 5 }}
                            >
                              <Icon size={24} />
                            </motion.div>
                            <div className={`h-3 w-3 rounded-full ${statusColors[device.status].bg} ${device.status === 'online' ? 'animate-pulse' : ''}`} />
                          </div>
                          <h3 className="font-bold text-foreground group-hover:text-primary transition-colors">{device.name}</h3>
                          <p className="text-sm text-muted-foreground font-mono">{device.location}</p>
                          <p className="text-xs text-muted-foreground font-mono mt-1 opacity-60">{device.mac}</p>
                          
                          <div className="mt-4 pt-4 border-t border-border/50 space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Status</span>
                              <span className={`text-[10px] font-bold uppercase tracking-widest ${statusColors[device.status].text}`}>
                                {device.status}
                              </span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Packets</span>
                              <span className="text-[10px] font-bold text-primary">{device.packets.toLocaleString()}</span>
                            </div>
                            
                            {/* Activity Bar */}
                            <div className="mt-2">
                              <div className="h-1 bg-muted rounded-full overflow-hidden">
                                <motion.div 
                                  className="h-full bg-gradient-to-r from-primary to-purple-400"
                                  initial={{ width: 0 }}
                                  animate={{ width: `${Math.min((device.packets / 10000) * 100, 100)}%` }}
                                  transition={{ duration: 1, delay: index * 0.1 }}
                                />
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  );
                })}
                
                {/* Scan Button Card */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: displayDevices.length * 0.05 }}
                >
                  <Card 
                    className="bg-primary/5 border-dashed border-primary/30 rounded-2xl flex items-center justify-center p-8 hover:bg-primary/10 transition-all cursor-pointer h-full min-h-[200px]"
                    onClick={handleScanNetwork}
                  >
                    <div className="text-center">
                      <motion.div 
                        className="w-14 h-14 rounded-full bg-primary/20 flex items-center justify-center text-primary mx-auto mb-3"
                        animate={isScanning ? { rotate: 360 } : {}}
                        transition={{ duration: 2, repeat: isScanning ? Infinity : 0, ease: "linear" }}
                      >
                        {isScanning ? <Loader2 size={28} className="animate-spin" /> : <Wifi size={28} />}
                      </motion.div>
                      <p className="font-bold text-foreground">{isScanning ? 'Scanning Network...' : 'Scan for Devices'}</p>
                      <p className="text-xs text-muted-foreground mt-1">{isScanning ? 'Discovering devices' : 'Click to discover new devices'}</p>
                    </div>
                  </Card>
                </motion.div>
              </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Device Details Panel */}
        <AnimatePresence>
          {selectedDevice && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Card className="bg-card/60 border-border/50 rounded-2xl overflow-hidden">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`p-4 rounded-2xl ${
                        selectedDevice.status === 'online' 
                          ? 'bg-primary/10 text-primary' 
                          : selectedDevice.status === 'warning'
                          ? 'bg-amber-500/10 text-amber-500'
                          : 'bg-muted text-muted-foreground'
                      }`}>
                        {(() => {
                          const Icon = iconMap[selectedDevice.type] || iconMap.default;
                          return <Icon size={32} />;
                        })()}
                      </div>
                      <div>
                        <h3 className="text-xl font-bold text-foreground">{selectedDevice.name}</h3>
                        <p className="text-sm text-muted-foreground font-mono">{selectedDevice.location}</p>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setSelectedDevice(null)}
                      className="text-muted-foreground hover:text-foreground"
                    >
                      ✕
                    </Button>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
                    <div className="bg-muted/30 rounded-xl p-4">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">MAC Address</p>
                      <p className="font-mono text-sm text-foreground">{selectedDevice.mac}</p>
                    </div>
                    <div className="bg-muted/30 rounded-xl p-4">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Device Type</p>
                      <p className="text-sm text-foreground capitalize">{selectedDevice.type}</p>
                    </div>
                    <div className="bg-muted/30 rounded-xl p-4">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Status</p>
                      <p className={`text-sm font-bold ${statusColors[selectedDevice.status].text}`}>
                        {selectedDevice.status.charAt(0).toUpperCase() + selectedDevice.status.slice(1)}
                      </p>
                    </div>
                    <div className="bg-muted/30 rounded-xl p-4">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Packets</p>
                      <p className="text-sm font-bold text-primary">{selectedDevice.packets.toLocaleString()}</p>
                    </div>
                  </div>
                  
                  <div className="flex gap-3 mt-6">
                    <Button className="gap-2" variant="outline">
                      <Eye size={16} />
                      Monitor Device
                    </Button>
                    <Button className="gap-2" variant="outline">
                      <Shield size={16} />
                      Security Scan
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </MainLayout>
  );
}
