import { useEffect } from "react";
import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { socketService } from "@/services/socketService";
import { apiService, ApiError } from "@/services/apiService";
import { useMonitorStore } from "@/store/monitorStore";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
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
import Login from "@/pages/login";
import Register from "@/pages/register";
import Profile from "@/pages/profile";
import ActionCenter from "@/pages/action-center";

function LoadingScreen() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center space-y-3">
        <div className="text-xs font-mono tracking-[0.3em] text-primary">VERIFYING ACCESS</div>
        <div className="text-2xl font-black text-foreground">Authenticating Session</div>
        <div className="text-sm text-muted-foreground">Connecting to your security console...</div>
      </div>
    </div>
  );
}

function Router() {
  const { authEnabled, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (authEnabled && !isAuthenticated) {
    return (
      <Switch>
        <Route path="/register" component={Register} />
        <Route path="/login" component={Login} />
        <Route component={Login} />
      </Switch>
    );
  }

  return (
    <Switch>
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />
      <Route path="/profile" component={Profile} />
      <Route path="/" component={Dashboard} />
      <Route path="/action-center" component={ActionCenter} />
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
  const { authEnabled, isAuthenticated, isLoading, refreshStatus } = useAuth();

  useEffect(() => {
    if (isLoading) {
      return;
    }

    if (authEnabled && !isAuthenticated) {
      socketService.disconnect();
      useMonitorStore.getState().setConnected(false);
      return;
    }

    let isActive = true;

    // Connect to backend on mount
    const initializeConnection = async () => {
      if (!isActive) {
        return;
      }

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
          if (apiError instanceof ApiError && apiError.status === 401) {
            await refreshStatus();
            return;
          }

          console.error("❌ Backend unreachable:", apiError);
          useMonitorStore.getState().setConnected(false);
        }
      }

      // Load initial data from REST API
      try {
        const results = await Promise.allSettled([
          apiService.getAlerts(),
          apiService.getDevices(),
          apiService.getStats(),
          apiService.getLogs(),
        ]);

        const hasAuthError = results.some(
          (result) => result.status === 'rejected' && result.reason instanceof ApiError && result.reason.status === 401
        );

        if (hasAuthError) {
          await refreshStatus();
          return;
        }

        if (results[0].status === 'fulfilled') {
          useMonitorStore.getState().setAlerts(results[0].value);
        }
        if (results[1].status === 'fulfilled') {
          useMonitorStore.getState().setDevices(results[1].value);
        }
        if (results[2].status === 'fulfilled') {
          useMonitorStore.getState().setStats(results[2].value);
        }
        if (results[3].status === 'fulfilled') {
          useMonitorStore.getState().setLogs(results[3].value);
        }
      } catch (dataError) {
        if (dataError instanceof ApiError && dataError.status === 401) {
          await refreshStatus();
          return;
        }
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
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          await refreshStatus();
          return;
        }
        if (useMonitorStore.getState().isConnected) {
          useMonitorStore.getState().setConnected(false);
          console.log("⛔ Connection lost");
        }
      }
    }, 10000); // Check every 10 seconds

    // Cleanup on unmount
    return () => {
      isActive = false;
      socketService.disconnect();
      clearInterval(healthInterval);
    };
  }, [authEnabled, isAuthenticated, isLoading, refreshStatus]);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
