import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Bell, Shield, Trash2, Loader2, CheckCircle, Settings, Gauge } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

const PROFILE_DESCRIPTIONS: Record<string, string> = {
  strict: "Very tight thresholds. Flags suspicious activity early — ideal for high-security networks.",
  balanced: "Default profile. Good balance between catching threats and reducing false positives.",
  sensitive: "Maximum detection sensitivity. May produce more alerts but catches even subtle attacks.",
  test: "Ultra-low thresholds for testing and demo environments.",
};

const PROFILE_COLORS: Record<string, string> = {
  strict: "text-red-400 border-red-500/40 bg-red-500/10",
  balanced: "text-primary border-primary/40 bg-primary/10",
  sensitive: "text-amber-400 border-amber-500/40 bg-amber-500/10",
  test: "text-violet-400 border-violet-500/40 bg-violet-500/10",
};

export default function SettingsPage() {
  const { reset } = useMonitorStore();
  const [settings, setSettings] = useState({
    auto_blocking: true,
    real_time_alerts: true,
    desktop_notifications: true,
    sound_alerts: false,
    data_retention_days: 7,
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [currentProfile, setCurrentProfile] = useState<string>('balanced');
  const [availableProfiles, setAvailableProfiles] = useState<string[]>([]);
  const [profileLoading, setProfileLoading] = useState(false);
  const [profileSaved, setProfileSaved] = useState(false);

  useEffect(() => {
    // Load settings from backend
    apiService.getSettings()
      .then(data => setSettings(prev => ({ ...prev, ...data })))
      .catch(err => console.error('Failed to load settings:', err));

    // Load detection profile
    apiService.getDetectionProfile()
      .then(data => {
        setCurrentProfile(data.current_profile || 'balanced');
        setAvailableProfiles(data.available_profiles || ['strict', 'balanced', 'sensitive']);
      })
      .catch(err => console.error('Failed to load detection profile:', err));
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

  const handleProfileChange = async (profile: string) => {
    if (profile === currentProfile || profileLoading) return;
    setProfileLoading(true);
    try {
      const result = await apiService.setDetectionProfile(profile);
      setCurrentProfile(result.current_profile || profile);
      setProfileSaved(true);
      setTimeout(() => setProfileSaved(false), 2000);
    } catch (err) {
      console.error('Failed to set detection profile:', err);
    } finally {
      setProfileLoading(false);
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

          {/* Detection Sensitivity */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.15 }}
            whileHover={{ scale: 1.01, y: -2 }}
          >
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl hover:border-primary/30 transition-all">
              <CardHeader className="border-b border-border/50 bg-white/5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <motion.div whileHover={{ scale: 1.1 }}>
                      <Gauge className="text-primary w-5 h-5" />
                    </motion.div>
                    <CardTitle className="text-foreground">Detection Sensitivity</CardTitle>
                  </div>
                  <Badge variant="outline" className={cn("capitalize", PROFILE_COLORS[currentProfile] || '')}>
                    {currentProfile}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="p-6 space-y-4">
                <p className="text-sm text-muted-foreground">
                  Choose how aggressively the security engine detects threats. Higher sensitivity catches more attacks but may produce more false positives.
                </p>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  {(availableProfiles.length > 0 ? availableProfiles : ['strict', 'balanced', 'sensitive']).map((profile) => (
                    <motion.button
                      key={profile}
                      onClick={() => handleProfileChange(profile)}
                      disabled={profileLoading}
                      className={cn(
                        "relative p-4 rounded-xl border text-left transition-all cursor-pointer",
                        currentProfile === profile
                          ? `${PROFILE_COLORS[profile] || 'border-primary/40 bg-primary/10'} ring-1 ring-primary/30`
                          : "border-border/50 bg-card/30 hover:border-primary/20 hover:bg-card/50"
                      )}
                      whileHover={{ scale: 1.03, y: -2 }}
                      whileTap={{ scale: 0.97 }}
                    >
                      {currentProfile === profile && (
                        <motion.div
                          className="absolute top-2 right-2"
                          initial={{ scale: 0 }}
                          animate={{ scale: 1 }}
                          transition={{ type: "spring", stiffness: 500 }}
                        >
                          <CheckCircle className="w-4 h-4 text-emerald-500" />
                        </motion.div>
                      )}
                      <p className="text-sm font-bold capitalize text-foreground">{profile}</p>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        {PROFILE_DESCRIPTIONS[profile] || 'Custom detection thresholds.'}
                      </p>
                    </motion.button>
                  ))}
                </div>
                <AnimatePresence>
                  {(profileLoading || profileSaved) && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="flex items-center gap-2 text-sm text-muted-foreground"
                    >
                      {profileLoading ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 400 }}>
                          <CheckCircle className="w-4 h-4 text-emerald-500" />
                        </motion.div>
                      )}
                      {profileLoading ? 'Applying profile...' : 'Detection profile updated'}
                    </motion.div>
                  )}
                </AnimatePresence>
              </CardContent>
            </Card>
          </motion.div>

          {/* Data Retention Limit */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            whileHover={{ scale: 1.01, y: -2 }}
          >
            <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl hover:border-primary/30 transition-all">
              <CardHeader className="border-b border-border/50 bg-background/50">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-primary/10">
                    <Trash2 className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-xl">Data Retention</CardTitle>
                    <p className="text-sm text-muted-foreground mt-1">Manage local storage and auto-deletion.</p>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-6 space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label className="text-base text-foreground">Retain packets for (days)</Label>
                    <p className="text-sm text-muted-foreground">Packet data older than this limit will be automatically deleted to save space.</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <input 
                      type="number"
                      min="1"
                      max="365"
                      className="w-20 px-3 py-1.5 text-sm bg-background border border-border/50 rounded-md focus:outline-none focus:ring-2 focus:ring-primary text-center text-foreground"
                      value={settings.data_retention_days || 7}
                      onChange={(e) => handleToggle('data_retention_days', parseInt(e.target.value) || 7)}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.25 }}
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
