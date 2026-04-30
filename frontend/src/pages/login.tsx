import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { ShieldCheck, Lock, User, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/AuthContext";

export default function Login() {
  const { authEnabled, isAuthenticated, isLoading, login, error, clearError } = useAuth();
  const [, setLocation] = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      setLocation("/");
    }
  }, [isAuthenticated, isLoading, setLocation]);

  useEffect(() => {
    if (!authEnabled && !isLoading) {
      setLocation("/");
    }
  }, [authEnabled, isLoading, setLocation]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting) return;

    clearError();
    setSubmitting(true);

    try {
      await login(username.trim(), password);
      setLocation("/");
    } catch {
      // Errors handled by context state.
    } finally {
      setSubmitting(false);
     }
   };
 
   return (
     <div className="min-h-screen bg-background flex items-center justify-center px-6 py-12">
       <div className="w-full max-w-md">
         <div className="mb-8 text-center">
           <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary border border-primary/20">
             <ShieldCheck size={28} />
           </div>
           <div className="text-xs font-mono tracking-[0.4em] text-primary">PACKET PEEPER</div>
           <h1 className="mt-3 text-3xl font-black text-foreground">Operator Access</h1>
           <p className="mt-2 text-sm text-muted-foreground">
             Sign in to reach your network security console.
           </p>
         </div>
 
         <div className="rounded-2xl border border-border/60 bg-card/60 p-6 shadow-xl">
           <form className="space-y-5" onSubmit={handleSubmit}>
             <div className="space-y-2">
               <label className="text-xs font-mono tracking-[0.3em] text-muted-foreground">USERNAME</label>
               <div className="relative">
                 <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                 <Input
                   value={username}
                   onChange={(event) => setUsername(event.target.value)}
                   placeholder="operator"
                   className="pl-10 h-11 bg-background/60"
                   disabled={submitting}
                   autoComplete="username"
                 />
               </div>
             </div>
 
             <div className="space-y-2">
               <label className="text-xs font-mono tracking-[0.3em] text-muted-foreground">PASSWORD</label>
               <div className="relative">
                 <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                 <Input
                   type="password"
                   value={password}
                   onChange={(event) => setPassword(event.target.value)}
                   placeholder="********"
                   className="pl-10 h-11 bg-background/60"
                   disabled={submitting}
                   autoComplete="current-password"
                 />
               </div>
             </div>
 
             {error && (
               <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                 {error}
               </div>
             )}
 
             <Button type="submit" className="w-full h-11 rounded-xl" disabled={submitting || !username || !password}>
               {submitting ? (
                 <span className="flex items-center gap-2">
                   <Loader2 className="h-4 w-4 animate-spin" />
                   Authenticating...
                 </span>
               ) : (
                 "Unlock Console"
               )}
             </Button>
           </form>
 
           <div className="mt-6 text-xs text-muted-foreground text-center">
             Need access? Update credentials in your backend .env settings.
           </div>
         </div>
       </div>
     </div>
   );
 }
