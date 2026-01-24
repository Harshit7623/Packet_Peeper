import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Bell, Shield, Trash2, Loader2, CheckCircle, Settings } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

export default function SettingsPage() {
  const { reset } = useMonitorStore();
  const [settings, setSettings] = useState({
    auto_blocking: true,
    real_time_alerts: true,
    desktop_notifications: true,
    sound_alerts: false,
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    // Load settings from backend
    apiService.getSettings()
      .then(data => setSettings(prev => ({ ...prev, ...data })))
      .catch(err => console.error('Failed to load settings:', err));
  }, []);

  const handleToggle = async (key: string, value: boolean) => {
    const newSettings = { ...settings, [key]: value };
    setSettings(newSettings);
    setSaving(true);
    
    try {
      await apiService.updateSettings({ [key]: value });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      console.error('Failed to save setting:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (confirm('Are you sure you want to reset all data? This cannot be undone.')) {
      try {
        await apiService.clearAlerts();
        await apiService.clearLogs();
        reset();
      } catch (err) {
        console.error('Failed to reset data:', err);
      }
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6 max-w-4xl">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="flex items-center gap-3 mb-2">
            <motion.div
              className="p-2 bg-primary/10 rounded-xl"
              whileHover={{ scale: 1.1, rotate: 90 }}
              transition={{ duration: 0.3 }}
            >
              <Settings className="w-6 h-6 text-primary" />
            </motion.div>
            <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          </div>
          <p className="text-muted-foreground text-lg">Manage your network preferences and configuration.</p>
        </motion.div>

        <div className="grid gap-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            whileHover={{ scale: 1.01, y: -2 }}
          >
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl hover:border-primary/30 transition-all">
              <CardHeader className="border-b border-border/50 bg-white/5">
                <div className="flex items-center gap-2">
                  <motion.div whileHover={{ scale: 1.1 }}>
                    <Shield className="text-primary w-5 h-5" />
                  </motion.div>
                  <CardTitle className="text-foreground">Security Preferences</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="p-6 space-y-6">
                <motion.div 
                  className="flex items-center justify-between"
                  whileHover={{ x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="space-y-0.5">
                    <Label className="text-base text-foreground">Automatic Blocking</Label>
                    <p className="text-sm text-muted-foreground">Instantly block devices that show suspicious behavior.</p>
                  </div>
                  <Switch 
                    checked={settings.auto_blocking} 
                    onCheckedChange={(checked) => handleToggle('auto_blocking', checked)}
                  />
                </motion.div>
                <motion.div 
                  className="flex items-center justify-between"
                  whileHover={{ x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="space-y-0.5">
                    <Label className="text-base text-foreground">Real-time Alerts</Label>
                    <p className="text-sm text-muted-foreground">Receive instant notifications for security events.</p>
                  </div>
                  <Switch 
                    checked={settings.real_time_alerts}
                    onCheckedChange={(checked) => handleToggle('real_time_alerts', checked)}
                  />
                </motion.div>
                <AnimatePresence>
                  {(saving || saved) && (
                    <motion.div 
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="flex items-center gap-2 text-sm text-muted-foreground"
                    >
                      {saving ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <motion.div
                          initial={{ scale: 0 }}
                          animate={{ scale: 1 }}
                          transition={{ type: "spring", stiffness: 400 }}
                        >
                          <CheckCircle className="w-4 h-4 text-emerald-500" />
                        </motion.div>
                      )}
                      {saving ? 'Saving...' : 'Settings saved'}
                    </motion.div>
                  )}
                </AnimatePresence>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            whileHover={{ scale: 1.01, y: -2 }}
          >
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl hover:border-primary/30 transition-all">
              <CardHeader className="border-b border-border/50 bg-white/5">
                <div className="flex items-center gap-2">
                  <motion.div
                    animate={{ rotate: [0, 15, -15, 0] }}
                    transition={{ duration: 2, repeat: Infinity, repeatDelay: 3 }}
                  >
                    <Bell className="text-primary w-5 h-5" />
                  </motion.div>
                  <CardTitle className="text-foreground">Notification Settings</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="p-6 space-y-6">
                <motion.div 
                  className="flex items-center justify-between"
                  whileHover={{ x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="space-y-0.5">
                    <Label className="text-base text-foreground">Desktop Notifications</Label>
                    <p className="text-sm text-muted-foreground">Get browser notifications for critical issues.</p>
                  </div>
                  <Switch 
                    checked={settings.desktop_notifications}
                    onCheckedChange={(checked) => handleToggle('desktop_notifications', checked)}
                  />
                </motion.div>
                <motion.div 
                  className="flex items-center justify-between"
                  whileHover={{ x: 5 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="space-y-0.5">
                    <Label className="text-base text-foreground">Sound Alerts</Label>
                    <p className="text-sm text-muted-foreground">Play a sound when a new device joins your network.</p>
                  </div>
                  <Switch 
                    checked={settings.sound_alerts}
                    onCheckedChange={(checked) => handleToggle('sound_alerts', checked)}
                  />
                </motion.div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            whileHover={{ scale: 1.01, y: -2 }}
          >
            <Card className="bg-destructive/5 border-destructive/20 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl hover:border-destructive/40 transition-all">
              <CardHeader className="border-b border-destructive/10">
                <div className="flex items-center gap-2">
                  <motion.div whileHover={{ scale: 1.2, rotate: 10 }}>
                    <Trash2 className="text-destructive w-5 h-5" />
                  </motion.div>
                  <CardTitle className="text-destructive">Danger Zone</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label className="text-base text-foreground">Reset All Data</Label>
                    <p className="text-sm text-muted-foreground">Clear all captured packets, alerts, and device data.</p>
                  </div>
                  <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                    <Button variant="destructive" className="rounded-full px-6" onClick={handleReset}>
                      Reset Data
                    </Button>
                  </motion.div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    </MainLayout>
  );
}
