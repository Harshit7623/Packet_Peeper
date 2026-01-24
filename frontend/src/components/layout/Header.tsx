import { Bell, Search, User, Shield, Activity, Moon, Sun, Settings, LogOut, X, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useState, useEffect } from "react";
import { useMonitorStore } from "@/store/monitorStore";
import { useTheme } from "@/contexts/ThemeContext";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { apiService } from "@/services/apiService";

export function Header() {
  const [currentTime, setCurrentTime] = useState(new Date());
  const { isConnected, stats, alerts } = useMonitorStore();
  const { theme, toggleTheme } = useTheme();
  const [, setLocation] = useLocation();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const unreadAlerts = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').slice(0, 5);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.notification-dropdown') && !target.closest('.notification-btn')) {
        setShowNotifications(false);
      }
      if (!target.closest('.profile-dropdown') && !target.closest('.profile-btn')) {
        setShowProfile(false);
      }
    };
    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      // Navigate to packets page with search
      setLocation(`/packets?search=${encodeURIComponent(searchQuery)}`);
    }
  };

  const handleDismissAlert = async (alertId: number) => {
    try {
      await apiService.dismissAlert(alertId);
      useMonitorStore.getState().setAlerts(alerts.filter(a => a.id !== alertId));
    } catch (err) {
      console.error('Failed to dismiss:', err);
    }
  };

  return (
    <header className="h-16 border-b border-border/30 bg-background/40 backdrop-blur-xl px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center gap-6 flex-1">
        {/* Connection Status */}
        <motion.div 
          className="hidden lg:flex items-center gap-4 px-3 py-1.5 rounded-lg bg-primary/5 border border-primary/10"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.3 }}
        >
          <div className="flex items-center gap-2 text-[10px] font-mono text-primary font-bold uppercase tracking-widest">
            <Shield size={12} />
            <span>{isConnected ? "Live Session" : "Offline"}</span>
          </div>
          <div className="w-px h-3 bg-border/50" />
          <div className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
            <motion.div
              animate={isConnected ? { scale: [1, 1.2, 1] } : {}}
              transition={{ duration: 1, repeat: Infinity }}
            >
              <Activity size={12} className={isConnected ? "text-green-500" : "text-red-500"} />
            </motion.div>
            <span>Packets: <span className="text-foreground font-bold">{stats?.totalPackets?.toLocaleString() || 0}</span></span>
          </div>
        </motion.div>

        {/* Search */}
        <form onSubmit={handleSearch} className="relative max-w-sm w-full hidden md:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground w-4 h-4" />
          <Input 
            placeholder="Search network assets..." 
            className="pl-10 bg-background/60 dark:bg-black/40 border-border/40 focus:border-primary/50 focus:ring-primary/10 h-8 rounded text-[10px] font-mono tracking-widest uppercase"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </form>
      </div>

      <div className="flex items-center gap-4">
        {/* Time Display */}
        <div className="hidden sm:flex flex-col items-end leading-none">
          <div className="text-xs font-mono text-primary font-black tracking-widest">
            {currentTime.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </div>
          <div className="text-[9px] text-muted-foreground font-bold tracking-[0.2em] mt-1 opacity-60">
            {currentTime.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: '2-digit' }).toUpperCase()}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Theme Toggle */}
          <motion.div whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.9 }}>
            <Button 
              variant="ghost" 
              size="icon" 
              className="h-9 w-9 text-muted-foreground hover:text-primary transition-colors"
              onClick={toggleTheme}
            >
              <AnimatePresence mode="wait">
                {theme === 'dark' ? (
                  <motion.div
                    key="moon"
                    initial={{ rotate: -90, opacity: 0 }}
                    animate={{ rotate: 0, opacity: 1 }}
                    exit={{ rotate: 90, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Moon className="w-4 h-4" />
                  </motion.div>
                ) : (
                  <motion.div
                    key="sun"
                    initial={{ rotate: 90, opacity: 0 }}
                    animate={{ rotate: 0, opacity: 1 }}
                    exit={{ rotate: -90, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Sun className="w-4 h-4" />
                  </motion.div>
                )}
              </AnimatePresence>
            </Button>
          </motion.div>

          {/* Notifications Bell */}
          <div className="relative">
            <motion.div whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.9 }}>
              <Button 
                variant="ghost" 
                size="icon" 
                className="notification-btn h-9 w-9 text-muted-foreground hover:text-primary relative"
                onClick={() => setShowNotifications(!showNotifications)}
              >
                <Bell className="w-4 h-4" />
                {unreadAlerts.length > 0 && (
                  <motion.span 
                    className="absolute top-1.5 right-1.5 min-w-[16px] h-4 px-1 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: "spring", stiffness: 500 }}
                  >
                    {unreadAlerts.length}
                  </motion.span>
                )}
              </Button>
            </motion.div>

            {/* Notifications Dropdown */}
            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  className="notification-dropdown absolute right-0 top-12 w-80 bg-card border border-border rounded-xl shadow-2xl overflow-hidden z-50"
                  initial={{ opacity: 0, y: -10, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -10, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="p-4 border-b border-border bg-muted/30">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-foreground">Notifications</h3>
                      <Button variant="ghost" size="sm" onClick={() => setLocation('/alerts')} className="text-xs text-primary">
                        View All
                      </Button>
                    </div>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {unreadAlerts.length > 0 ? (
                      unreadAlerts.map((alert, i) => (
                        <motion.div
                          key={alert.id}
                          className="p-4 border-b border-border/50 hover:bg-muted/30 transition-colors cursor-pointer group"
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.05 }}
                          onClick={() => setLocation('/alerts')}
                        >
                          <div className="flex items-start gap-3">
                            <div className={`w-2 h-2 rounded-full mt-2 ${
                              alert.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'
                            }`} />
                            <div className="flex-1">
                              <p className="text-sm font-medium text-foreground">{alert.title}</p>
                              <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{alert.description}</p>
                              <p className="text-[10px] text-muted-foreground mt-1">
                                {new Date(alert.timestamp).toLocaleTimeString()}
                              </p>
                            </div>
                            <Button 
                              variant="ghost" 
                              size="icon"
                              className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                              onClick={(e) => { e.stopPropagation(); handleDismissAlert(alert.id); }}
                            >
                              <X size={12} />
                            </Button>
                          </div>
                        </motion.div>
                      ))
                    ) : (
                      <div className="p-8 text-center text-muted-foreground">
                        <Check className="w-8 h-8 mx-auto mb-2 text-green-500" />
                        <p className="text-sm">All caught up!</p>
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div className="h-6 w-px bg-border/30 mx-1" />

          {/* Profile Menu */}
          <div className="relative">
            <motion.div 
              className="profile-btn flex items-center gap-3 cursor-pointer group"
              whileHover={{ scale: 1.02 }}
              onClick={() => setShowProfile(!showProfile)}
            >
              <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary group-hover:bg-primary group-hover:text-white transition-all shadow-[0_0_10px_rgba(0,184,217,0.1)]">
                <User className="w-4 h-4" />
              </div>
              <div className="hidden md:block">
                <div className="text-[10px] font-black text-foreground tracking-widest leading-none">OPERATOR</div>
                <div className="text-[8px] text-primary font-bold uppercase tracking-tighter mt-1 opacity-70">
                  {isConnected ? "ONLINE" : "OFFLINE"}
                </div>
              </div>
            </motion.div>

            {/* Profile Dropdown */}
            <AnimatePresence>
              {showProfile && (
                <motion.div
                  className="profile-dropdown absolute right-0 top-12 w-48 bg-card border border-border rounded-xl shadow-2xl overflow-hidden z-50"
                  initial={{ opacity: 0, y: -10, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -10, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="p-2">
                    <Button 
                      variant="ghost" 
                      className="w-full justify-start gap-2 text-sm"
                      onClick={() => { setLocation('/settings'); setShowProfile(false); }}
                    >
                      <Settings size={16} />
                      Settings
                    </Button>
                    <Button 
                      variant="ghost" 
                      className="w-full justify-start gap-2 text-sm text-muted-foreground hover:text-foreground"
                      onClick={toggleTheme}
                    >
                      {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                      {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
                    </Button>
                    <div className="my-1 border-t border-border" />
                    <Button 
                      variant="ghost" 
                      className="w-full justify-start gap-2 text-sm text-red-500 hover:text-red-400 hover:bg-red-500/10"
                    >
                      <LogOut size={16} />
                      Exit
                    </Button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </header>
  );
}
