import { useEffect } from "react";
import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { socketService } from "@/services/socketService";
import { apiService } from "@/services/apiService";
import { useMonitorStore } from "@/store/monitorStore";
import { ThemeProvider } from "@/contexts/ThemeContext";
import NotFound from "@/pages/not-found";

import Dashboard from "@/pages/dashboard";
import PacketMonitor from "@/pages/packet-monitor";
import Alerts from "@/pages/alerts";
import NetworkMap from "@/pages/network";
import TrafficAnalysis from "@/pages/traffic";
import Analytics from "@/pages/analytics";
import SystemStats from "@/pages/system";
import Logs from "@/pages/logs";
import Settings from "@/pages/settings";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/packets" component={PacketMonitor} />
      <Route path="/alerts" component={Alerts} />
      <Route path="/network" component={NetworkMap} />
      <Route path="/traffic" component={TrafficAnalysis} />
      <Route path="/analytics" component={Analytics} />
      <Route path="/system" component={SystemStats} />
      <Route path="/logs" component={Logs} />
      <Route path="/settings" component={Settings} />
      {/* Fallback to 404 */}
      <Route component={NotFound} />
    </Switch>
  );
}

function AppContent() {
  useEffect(() => {
    // Connect to backend on mount
    const initializeConnection = async () => {
      // First try socket connection
      try {
        await socketService.connect();
        useMonitorStore.getState().setConnected(true);
        console.log("✅ Socket connected to Packet Peeper backend");
      } catch (socketError) {
        console.warn("⚠️ Socket connection failed, checking API health...", socketError);
        
        // Fallback: Check if API is reachable
        try {
          await apiService.getHealthStatus();
          useMonitorStore.getState().setConnected(true);
          console.log("✅ API health check passed");
        } catch (apiError) {
          console.error("❌ Backend unreachable:", apiError);
          useMonitorStore.getState().setConnected(false);
        }
      }

      // Load initial data from REST API
      try {
        const [alerts, devices, stats, logs] = await Promise.allSettled([
          apiService.getAlerts(),
          apiService.getDevices(),
          apiService.getStats(),
          apiService.getLogs(),
        ]);

        if (alerts.status === 'fulfilled') {
          useMonitorStore.getState().setAlerts(alerts.value);
        }
        if (devices.status === 'fulfilled') {
          useMonitorStore.getState().setDevices(devices.value);
        }
        if (stats.status === 'fulfilled') {
          useMonitorStore.getState().setStats(stats.value);
        }
        if (logs.status === 'fulfilled') {
          useMonitorStore.getState().setLogs(logs.value);
        }
      } catch (dataError) {
        console.error("Failed to load initial data:", dataError);
      }
    };

    initializeConnection();

    // Periodic health check
    const healthInterval = setInterval(async () => {
      try {
        await apiService.getHealthStatus();
        if (!useMonitorStore.getState().isConnected) {
          useMonitorStore.getState().setConnected(true);
          console.log("✅ Connection restored");
        }
      } catch {
        if (useMonitorStore.getState().isConnected) {
          useMonitorStore.getState().setConnected(false);
          console.log("⛔ Connection lost");
        }
      }
    }, 10000); // Check every 10 seconds

    // Cleanup on unmount
    return () => {
      socketService.disconnect();
      clearInterval(healthInterval);
    };
  }, []);

  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

function App() {
  return <AppContent />;
}

export default App;
