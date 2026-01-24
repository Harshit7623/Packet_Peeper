import { useState, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Bot, 
  Sparkles, 
  Lightbulb, 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  ChevronDown, 
  ChevronUp,
  Loader2,
  X,
  MessageSquare,
  Zap,
  BookOpen,
  ArrowRight
} from "lucide-react";
import { apiService } from "@/services/apiService";

interface AIRemediationResponse {
  success: boolean;
  explanation: string;
  steps: string[];
  severity_assessment: string;
  estimated_risk: string;
  technical_details?: string;
  prevention_tips?: string[];
  provider: string;
  cached?: boolean;
}

interface AIAssistantPanelProps {
  alert: any;
  onClose: () => void;
  isOpen: boolean;
}

export function AIAssistantPanel({ alert, onClose, isOpen }: AIAssistantPanelProps) {
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<AIRemediationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showTechnical, setShowTechnical] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const panelRef = useRef<HTMLDivElement>(null);
  const hasFetched = useRef(false);
  const alertId = alert?.id;

  useEffect(() => {
    // Reset when modal closes
    if (!isOpen) {
      hasFetched.current = false;
      setResponse(null);
      setError(null);
      return;
    }
    
    // Only fetch once per modal open, using alertId to track
    if (isOpen && alert && !hasFetched.current && !loading) {
      hasFetched.current = true;
      fetchRemediation();
    }
  }, [isOpen, alertId]);

  const fetchRemediation = async () => {
    if (loading) return; // Prevent double-fetch
    
    setLoading(true);
    setError(null);
    setCompletedSteps(new Set());
    
    try {
      // Debug: Log what we're sending
      console.log('🤖 [AI] Sending alert for remediation:', {
        id: alert.id,
        type: alert.type,
        title: alert.title,
        severity: alert.severity
      });
      
      const result = await apiService.getAIRemediation(alert);
      
      // Debug: Log the response
      console.log('🤖 [AI] Received response:', {
        success: result.success,
        provider: result.provider,
        stepsCount: result.steps?.length
      });
      
      setResponse(result);
    } catch (err) {
      setError("Failed to get AI assistance. Please try again.");
      console.error("AI remediation error:", err);
    } finally {
      setLoading(false);
    }
  };

  const toggleStep = (index: number) => {
    setCompletedSteps(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  };

  const getSeverityColor = (assessment: string) => {
    if (assessment.includes("Critical")) return "text-red-400 bg-red-500/10 border-red-500/30";
    if (assessment.includes("Needs Attention")) return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    if (assessment.includes("Moderate")) return "text-amber-400 bg-amber-500/10 border-amber-500/30";
    return "text-blue-400 bg-blue-500/10 border-blue-500/30";
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] flex items-center justify-center p-4"
        onClick={(e) => e.target === e.currentTarget && onClose()}
      >
        <motion.div
          ref={panelRef}
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="w-full max-w-2xl max-h-[90vh] overflow-hidden rounded-2xl bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-700/50 shadow-2xl z-[101]"
        >
          {/* Header */}
          <div className="relative px-6 py-4 border-b border-slate-700/50 bg-gradient-to-r from-primary/10 via-purple-500/10 to-blue-500/10">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <motion.div
                  animate={{ rotate: [0, 10, -10, 0] }}
                  transition={{ duration: 2, repeat: Infinity, repeatDelay: 3 }}
                  className="p-2 rounded-xl bg-gradient-to-br from-primary to-purple-500 shadow-lg"
                >
                  <Bot className="h-6 w-6 text-white" />
                </motion.div>
                <div>
                  <h2 className="text-xl font-bold text-foreground flex items-center gap-2">
                    AI Security Assistant
                    <Sparkles className="h-4 w-4 text-yellow-400" />
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    Analyzing threat and generating recommendations
                  </p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={onClose}
                className="rounded-full hover:bg-white/10"
              >
                <X className="h-5 w-5" />
              </Button>
            </div>
          </div>

          {/* Content */}
          <div className="p-6 overflow-y-auto max-h-[calc(90vh-140px)] space-y-6">
            {/* Alert Summary */}
            <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-orange-400 mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold text-foreground">{alert?.title || "Unknown Alert"}</h3>
                  <p className="text-sm text-muted-foreground mt-1">{alert?.description}</p>
                  <div className="flex gap-2 mt-2">
                    <Badge variant="outline" className="text-xs">
                      {alert?.type || alert?.attack_type || "security"}
                    </Badge>
                    <Badge 
                      variant="outline" 
                      className={`text-xs ${
                        alert?.severity === "critical" ? "border-red-500/50 text-red-400" :
                        alert?.severity === "high" ? "border-orange-500/50 text-orange-400" :
                        "border-amber-500/50 text-amber-400"
                      }`}
                    >
                      {alert?.severity || "medium"}
                    </Badge>
                  </div>
                </div>
              </div>
            </div>

            {/* Loading State */}
            {loading && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center py-12 space-y-4"
              >
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                >
                  <Loader2 className="h-10 w-10 text-primary" />
                </motion.div>
                <p className="text-muted-foreground">Analyzing threat and generating solutions...</p>
                <div className="flex gap-1">
                  {[0, 1, 2].map((i) => (
                    <motion.div
                      key={i}
                      animate={{ opacity: [0.3, 1, 0.3] }}
                      transition={{ duration: 1.5, repeat: Infinity, delay: i * 0.2 }}
                      className="w-2 h-2 rounded-full bg-primary"
                    />
                  ))}
                </div>
              </motion.div>
            )}

            {/* Error State */}
            {error && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-center"
              >
                <p className="text-red-400">{error}</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    hasFetched.current = false;
                    fetchRemediation();
                  }}
                  className="mt-3"
                >
                  Try Again
                </Button>
              </motion.div>
            )}

            {/* AI Response */}
            {response && !loading && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-6"
              >
                {/* Explanation */}
                <Card className="border-slate-700/50 bg-slate-800/30">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Lightbulb className="h-5 w-5 text-yellow-400" />
                      What's Happening?
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-muted-foreground leading-relaxed">
                      {response.explanation}
                    </p>
                  </CardContent>
                </Card>

                {/* Severity Assessment */}
                <div className={`p-4 rounded-xl border ${getSeverityColor(response.severity_assessment)}`}>
                  <div className="flex items-center gap-3">
                    <Shield className="h-5 w-5 flex-shrink-0" />
                    <div>
                      <p className="font-semibold">{response.severity_assessment}</p>
                      <p className="text-sm opacity-80 mt-1">{response.estimated_risk}</p>
                    </div>
                  </div>
                </div>

                {/* Action Steps */}
                <Card className="border-slate-700/50 bg-slate-800/30">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Zap className="h-5 w-5 text-blue-400" />
                      What You Should Do
                      <Badge variant="secondary" className="ml-2 text-xs">
                        {completedSteps.size}/{response.steps.length} completed
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {response.steps.map((step, index) => (
                      <motion.div
                        key={index}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        onClick={() => toggleStep(index)}
                        className={`p-3 rounded-lg border cursor-pointer transition-all ${
                          completedSteps.has(index)
                            ? "bg-emerald-500/10 border-emerald-500/30"
                            : "bg-slate-700/30 border-slate-600/50 hover:border-primary/50"
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 ${
                            completedSteps.has(index)
                              ? "bg-emerald-500 text-white"
                              : "bg-slate-600 text-slate-300"
                          }`}>
                            {completedSteps.has(index) ? (
                              <CheckCircle2 className="h-4 w-4" />
                            ) : (
                              <span className="text-xs font-bold">{index + 1}</span>
                            )}
                          </div>
                          <p className={`text-sm ${
                            completedSteps.has(index) 
                              ? "text-emerald-300 line-through opacity-70" 
                              : "text-foreground"
                          }`}>
                            {step}
                          </p>
                        </div>
                      </motion.div>
                    ))}
                  </CardContent>
                </Card>

                {/* Prevention Tips */}
                {response.prevention_tips && response.prevention_tips.length > 0 && (
                  <Card className="border-slate-700/50 bg-slate-800/30">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <BookOpen className="h-5 w-5 text-purple-400" />
                        Prevent This in the Future
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ul className="space-y-2">
                        {response.prevention_tips.map((tip, index) => (
                          <motion.li
                            key={index}
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.5 + index * 0.1 }}
                            className="flex items-start gap-2 text-sm text-muted-foreground"
                          >
                            <ArrowRight className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                            {tip}
                          </motion.li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                )}

                {/* Technical Details (Collapsible) */}
                {response.technical_details && (
                  <div className="border border-slate-700/50 rounded-xl overflow-hidden">
                    <button
                      onClick={() => setShowTechnical(!showTechnical)}
                      className="w-full px-4 py-3 flex items-center justify-between bg-slate-800/50 hover:bg-slate-800/70 transition-colors"
                    >
                      <span className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                        <MessageSquare className="h-4 w-4" />
                        Technical Details
                      </span>
                      {showTechnical ? (
                        <ChevronUp className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      )}
                    </button>
                    <AnimatePresence>
                      {showTechnical && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="px-4 py-3 bg-slate-900/50 border-t border-slate-700/50"
                        >
                          <p className="text-sm text-muted-foreground font-mono">
                            {response.technical_details}
                          </p>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                )}

                {/* Provider Badge */}
                <div className="flex items-center justify-center gap-2 pt-2">
                  <Badge variant="outline" className="text-xs text-muted-foreground">
                    <Bot className="h-3 w-3 mr-1" />
                    Powered by {response.provider === "fallback" ? "Packet Peeper AI" : response.provider}
                  </Badge>
                  {response.cached && (
                    <Badge variant="outline" className="text-xs text-muted-foreground">
                      <Zap className="h-3 w-3 mr-1" />
                      Cached
                    </Badge>
                  )}
                </div>
              </motion.div>
            )}
          </div>

          {/* Footer */}
          <div className="px-6 py-4 border-t border-slate-700/50 bg-slate-900/50 flex justify-between items-center">
            <p className="text-xs text-muted-foreground">
              AI suggestions are recommendations. Use your judgment.
            </p>
            <Button onClick={onClose}>
              Close
            </Button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

// Floating AI Help Button Component
interface AIHelpButtonProps {
  alert: any;
  size?: "sm" | "default" | "lg";
  variant?: "default" | "outline" | "ghost";
}

export function AIHelpButton({ alert, size = "sm", variant = "outline" }: AIHelpButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Ensure we're mounted before creating portal
  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);

  return (
    <>
      <Button
        variant={variant}
        size={size}
        onClick={(e) => {
          e.stopPropagation(); // Prevent event bubbling
          setIsOpen(true);
        }}
        className="gap-1.5 group"
      >
        <Bot className="h-4 w-4 group-hover:animate-bounce" />
        <span>Get AI Help</span>
        <Sparkles className="h-3 w-3 text-yellow-400" />
      </Button>
      
      {/* Use portal to render modal at document body level */}
      {mounted && isOpen && createPortal(
        <AIAssistantPanel
          alert={alert}
          isOpen={isOpen}
          onClose={() => setIsOpen(false)}
        />,
        document.body
      )}
    </>
  );
}

// Network Health Widget
export function AIHealthWidget() {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const result = await apiService.getNetworkHealthSummary();
        setHealth(result);
      } catch (err) {
        console.error("Failed to fetch health summary:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Card className="border-slate-700/50 bg-gradient-to-br from-slate-800/50 to-slate-900/50">
        <CardContent className="p-4 flex items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  if (!health) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <Card className="border-slate-700/50 bg-gradient-to-br from-slate-800/50 to-slate-900/50 overflow-hidden">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <div className="text-2xl">{health.status.split(' ')[0]}</div>
            <div className="flex-1">
              <h3 className="font-semibold text-foreground">
                {health.status.substring(health.status.indexOf(' ') + 1)}
              </h3>
              <p className="text-sm text-muted-foreground mt-1">
                {health.message}
              </p>
              <p className="text-xs text-primary mt-2">
                {health.action}
              </p>
            </div>
          </div>
          
          {health.stats && (
            <div className="flex gap-4 mt-4 pt-4 border-t border-slate-700/50">
              <div className="text-center">
                <div className="text-lg font-bold text-red-400">{health.stats.critical}</div>
                <div className="text-xs text-muted-foreground">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-orange-400">{health.stats.high}</div>
                <div className="text-xs text-muted-foreground">High</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-amber-400">{health.stats.medium}</div>
                <div className="text-xs text-muted-foreground">Medium</div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

export default AIAssistantPanel;
