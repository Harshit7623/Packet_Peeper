import { useEffect, useMemo, useState } from "react";
import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { apiService } from "@/services/apiService";
import { User, ShieldCheck, Server, RefreshCcw, Lock, Loader2 } from "lucide-react";
import { motion } from "framer-motion";

interface ProfileData {
  username: string;
  email?: string;
  role?: string;
  created_at?: string;
  last_login?: string | null;
  device_info?: Record<string, unknown>;
  active_sessions?: Array<Record<string, unknown>>;
  active_session_count?: number;
}

interface DeviceInfo {
  mac_address: string;
  ip_address: string;
  hostname: string;
  cpu_count: number;
  total_memory: number;
  os: string;
}

export default function Profile() {
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [profileEmail, setProfileEmail] = useState("");
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordConfirm, setNewPasswordConfirm] = useState("");

  const sessionList = useMemo(() => profile?.active_sessions ?? [], [profile]);

  const loadProfile = async () => {
    setLoading(true);
    setError(null);
    try {
      const [profileData, deviceData] = await Promise.all([
        apiService.getProfile(),
        apiService.getDeviceInfo(),
      ]);
      setProfile(profileData);
      setProfileEmail(profileData.email ?? "");
      setDeviceInfo(deviceData);
    } catch (err) {
      setError("Unable to load profile data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProfile();
  }, []);

  const handleProfileSave = async () => {
    setSavingProfile(true);
    setError(null);
    try {
      await apiService.updateProfile({ email: profileEmail.trim() || undefined });
      await loadProfile();
    } catch (err) {
      setError("Unable to update profile.");
    } finally {
      setSavingProfile(false);
    }
  };

  const handlePasswordChange = async () => {
    if (!oldPassword || !newPassword || !newPasswordConfirm) {
      setError("Fill out all password fields before saving.");
      return;
    }
    setSavingPassword(true);
    setError(null);
    try {
      await apiService.changePassword(oldPassword, newPassword, newPasswordConfirm);
      setOldPassword("");
      setNewPassword("");
      setNewPasswordConfirm("");
    } catch (err) {
      setError("Unable to update password.");
    } finally {
      setSavingPassword(false);
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6 max-w-5xl">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="flex items-center gap-3 mb-2">
            <motion.div className="p-2 bg-primary/10 rounded-xl" whileHover={{ scale: 1.1 }}>
              <User className="w-6 h-6 text-primary" />
            </motion.div>
            <h1 className="text-3xl font-bold text-foreground">Profile & Device</h1>
          </div>
          <p className="text-muted-foreground text-lg">Manage your operator identity and session security.</p>
        </motion.div>

        {error && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="grid gap-6">
          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
            <CardHeader className="border-b border-border/50 bg-white/5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="text-primary w-5 h-5" />
                  <CardTitle className="text-foreground">Account Overview</CardTitle>
                </div>
                <Button variant="ghost" size="sm" onClick={loadProfile} disabled={loading}>
                  <RefreshCcw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              {loading ? (
                <div className="flex items-center gap-2 text-muted-foreground text-sm">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Loading profile...
                </div>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-1">
                    <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Username</p>
                    <div className="text-lg font-semibold text-foreground">{profile?.username}</div>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Role</p>
                    <Badge className="bg-primary/10 text-primary border border-primary/20">
                      {profile?.role ?? "operator"}
                    </Badge>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Last Login</p>
                    <div className="text-sm text-foreground">
                      {profile?.last_login ? new Date(profile.last_login).toLocaleString() : "Not available"}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Active Sessions</p>
                    <div className="text-sm text-foreground">
                      {profile?.active_session_count ?? 0}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
            <CardHeader className="border-b border-border/50 bg-white/5">
              <div className="flex items-center gap-2">
                <Server className="text-primary w-5 h-5" />
                <CardTitle className="text-foreground">Device Identity</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="p-6 grid gap-4 md:grid-cols-2">
              <div>
                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">MAC Address</p>
                <p className="text-sm text-foreground mt-1">{deviceInfo?.mac_address ?? "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Local IP</p>
                <p className="text-sm text-foreground mt-1">{deviceInfo?.ip_address ?? "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Hostname</p>
                <p className="text-sm text-foreground mt-1">{deviceInfo?.hostname ?? "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">System</p>
                <p className="text-sm text-foreground mt-1">
                  {deviceInfo?.os ?? "Unknown"} · {deviceInfo?.cpu_count ?? 0} Cores
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
            <CardHeader className="border-b border-border/50 bg-white/5">
              <div className="flex items-center gap-2">
                <User className="text-primary w-5 h-5" />
                <CardTitle className="text-foreground">Update Profile</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              <div className="space-y-2">
                <Label className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Email</Label>
                <Input
                  value={profileEmail}
                  onChange={(event) => setProfileEmail(event.target.value)}
                  placeholder="operator@company.com"
                  className="bg-background/60"
                />
              </div>
              <Button onClick={handleProfileSave} disabled={savingProfile}>
                {savingProfile ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Saving...
                  </span>
                ) : (
                  "Save Profile"
                )}
              </Button>
            </CardContent>
          </Card>

          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
            <CardHeader className="border-b border-border/50 bg-white/5">
              <div className="flex items-center gap-2">
                <Lock className="text-primary w-5 h-5" />
                <CardTitle className="text-foreground">Change Password</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <Label className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Current</Label>
                  <Input
                    type="password"
                    value={oldPassword}
                    onChange={(event) => setOldPassword(event.target.value)}
                    placeholder="********"
                    className="bg-background/60"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">New</Label>
                  <Input
                    type="password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    placeholder="********"
                    className="bg-background/60"
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Confirm</Label>
                  <Input
                    type="password"
                    value={newPasswordConfirm}
                    onChange={(event) => setNewPasswordConfirm(event.target.value)}
                    placeholder="********"
                    className="bg-background/60"
                  />
                </div>
              </div>
              <Button onClick={handlePasswordChange} disabled={savingPassword}>
                {savingPassword ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Updating...
                  </span>
                ) : (
                  "Update Password"
                )}
              </Button>
            </CardContent>
          </Card>

          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl">
            <CardHeader className="border-b border-border/50 bg-white/5">
              <div className="flex items-center gap-2">
                <ShieldCheck className="text-primary w-5 h-5" />
                <CardTitle className="text-foreground">Active Sessions</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="p-6 space-y-3">
              {sessionList.length === 0 ? (
                <div className="text-sm text-muted-foreground">No active sessions detected.</div>
              ) : (
                sessionList.map((session, index) => (
                  <div key={`${session.id ?? index}`} className="rounded-lg border border-border/40 bg-muted/20 px-4 py-3">
                    <div className="text-xs uppercase tracking-[0.3em] text-muted-foreground font-mono">Session {index + 1}</div>
                    <div className="text-sm text-foreground mt-2">
                      Last seen: {session.last_seen ? new Date(session.last_seen as string).toLocaleString() : "Unknown"}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Device: {(session.device_info as Record<string, unknown>)?.hostname ?? "Unknown"}
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}
