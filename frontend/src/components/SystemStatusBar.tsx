import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Bot, Radio, Settings, AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { apiService } from '@/services/apiService';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

interface AIStatus {
  provider: string;
  model?: string;
  is_fallback?: boolean;
  confidence?: string;
  message?: string;
  providers_available?: Record<string, boolean>;
}

interface DetectionProfile {
  current_profile: string;
  available_profiles: string[];
  description?: Record<string, string>;
}

export function SystemStatusBar() {
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null);
  const [detectionProfile, setDetectionProfile] = useState<DetectionProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [showProfileDropdown, setShowProfileDropdown] = useState(false);
  const [changingProfile, setChangingProfile] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        setLoading(true);
        
        // Fetch both statuses in parallel
        const [aiRes, profileRes] = await Promise.all([
          (async () => {
            try {
              return await apiService.getAIStatus?.();
            } catch {
              return null;
            }
          })(),
          (async () => {
            try {
              return await apiService.getDetectionProfile?.();
            } catch {
              return null;
            }
          })()
        ]);
        
        if (aiRes) setAiStatus(aiRes);
        if (profileRes) setDetectionProfile(profileRes);
      } catch (err) {
        console.error('Failed to fetch system status:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    
    // Poll every 30 seconds
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleProfileChange = async (newProfile: string) => {
    if (changingProfile) return;
    
    setChangingProfile(true);
    try {
      const result = await apiService.setDetectionProfile?.(newProfile);
      
      if (result && result.current_profile) {
        setDetectionProfile(prev => prev ? 
          { ...prev, current_profile: result.current_profile } 
          : null
        );
        
        toast({
          title: 'Detection Profile Updated',
          description: `Switched to ${newProfile} profile`,
        });
      }
    } catch (err) {
      toast({
        title: 'Profile Change Failed',
        description: 'Unable to update detection profile. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setChangingProfile(false);
      setShowProfileDropdown(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-4 h-16 bg-slate-900/50 rounded-lg border border-slate-700/50">
        <Loader2 className="animate-spin text-primary" size={20} />
        <span className="ml-2 text-sm text-muted-foreground">Loading system status...</span>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-3"
    >
      {/* AI Status */}
      <Card className="p-4 bg-slate-900/50 border-slate-700/50">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <motion.div 
              className={`p-2 rounded-lg ${
                aiStatus?.is_fallback 
                  ? 'bg-yellow-500/10' 
                  : 'bg-emerald-500/10'
              }`}
              animate={{ scale: [1, 1.05, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <Bot size={20} className={aiStatus?.is_fallback ? 'text-yellow-400' : 'text-emerald-400'} />
            </motion.div>
            
            <div className="flex-1">
              <p className="text-sm font-semibold text-foreground flex items-center gap-2">
                AI Assistant
                {aiStatus?.is_fallback ? (
                  <Badge variant="outline" className="bg-yellow-500/10 border-yellow-500/30 text-yellow-300 text-xs">
                    Fallback Mode
                  </Badge>
                ) : (
                  <Badge variant="outline" className="bg-emerald-500/10 border-emerald-500/30 text-emerald-300 text-xs">
                    Connected
                  </Badge>
                )}
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {aiStatus?.provider && (
                  <>
                    Provider: <span className="text-foreground font-medium">{aiStatus.provider}</span>
                    {aiStatus.model && <> • Model: {aiStatus.model}</>}
                  </>
                )}
              </p>
            </div>
          </div>
          
          {aiStatus?.message && (
            <p className="text-xs text-muted-foreground italic max-w-xs">
              {aiStatus.message}
            </p>
          )}
        </div>
      </Card>

      {/* Detection Profile */}
      <Card className="p-4 bg-slate-900/50 border-slate-700/50">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3 flex-1">
            <motion.div 
              className="p-2 rounded-lg bg-blue-500/10"
              animate={{ rotate: [0, 10, 0] }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              <Radio size={20} className="text-blue-400" />
            </motion.div>
            
            <div>
              <p className="text-sm font-semibold text-foreground">Detection Profile</p>
              <p className="text-xs text-muted-foreground mt-1">
                Sensitivity: <span className="text-foreground font-medium capitalize">{detectionProfile?.current_profile}</span>
              </p>
              {detectionProfile?.description?.[detectionProfile.current_profile] && (
                <p className="text-xs text-muted-foreground mt-1">
                  {detectionProfile.description[detectionProfile.current_profile]}
                </p>
              )}
            </div>
          </div>
          
          <div className="relative">
            <Button
              size="sm"
              variant="outline"
              className="gap-2"
              onClick={() => setShowProfileDropdown(!showProfileDropdown)}
              disabled={changingProfile}
            >
              {changingProfile ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <Settings size={16} />
              )}
              Change
            </Button>
            
            {showProfileDropdown && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="absolute right-0 mt-2 w-48 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-10"
              >
                <div className="p-2">
                  {detectionProfile?.available_profiles.map(profile => (
                    <button
                      key={profile}
                      onClick={() => handleProfileChange(profile)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors mb-1 last:mb-0 ${
                        detectionProfile?.current_profile === profile
                          ? 'bg-primary/20 text-primary font-medium'
                          : 'text-foreground hover:bg-slate-700'
                      }`}
                      disabled={changingProfile}
                    >
                      <span className="capitalize">{profile}</span>
                      {detectionProfile?.description?.[profile] && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {detectionProfile.description[profile]}
                        </p>
                      )}
                    </button>
                  ))}
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </Card>
    </motion.div>
  );
}
