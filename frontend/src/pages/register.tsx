import { useEffect, useState } from "react";
import { Link, useLocation } from "wouter";
import { ShieldCheck, Lock, Mail, User, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/AuthContext";

export default function Register() {
  const { authEnabled, isAuthenticated, isLoading, register, error, clearError } = useAuth();
  const [, setLocation] = useLocation();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

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
    setSuccessMessage(null);
    setSubmitting(true);

    try {
      await register(username.trim(), email.trim(), password, passwordConfirm);
      setSuccessMessage("Account created. Please sign in.");
      setTimeout(() => setLocation("/login"), 900);
    } catch {
      // Errors handled by context state.
    } finally {
      setSubmitting(false);
    }
  };

  const isFormValid = username && email && password && passwordConfirm;

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-6 py-12">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary border border-primary/20">
            <ShieldCheck size={28} />
          </div>
          <div className="text-xs font-mono tracking-[0.4em] text-primary">PACKET PEEPER</div>
          <h1 className="mt-3 text-3xl font-black text-foreground">Create Operator Account</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Provision secure access to the enterprise console.
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
              <label className="text-xs font-mono tracking-[0.3em] text-muted-foreground">EMAIL</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="operator@company.com"
                  className="pl-10 h-11 bg-background/60"
                  disabled={submitting}
                  autoComplete="email"
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
                  autoComplete="new-password"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-mono tracking-[0.3em] text-muted-foreground">CONFIRM PASSWORD</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type="password"
                  value={passwordConfirm}
                  onChange={(event) => setPasswordConfirm(event.target.value)}
                  placeholder="********"
                  className="pl-10 h-11 bg-background/60"
                  disabled={submitting}
                  autoComplete="new-password"
                />
              </div>
            </div>

            <div className="rounded-lg border border-border/40 bg-muted/20 px-4 py-3 text-xs text-muted-foreground">
              Passwords must be 12+ characters with uppercase, lowercase, number, and special symbol.
            </div>

            {error && (
              <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                {error}
              </div>
            )}

            {successMessage && (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-500">
                {successMessage}
              </div>
            )}

            <Button type="submit" className="w-full h-11 rounded-xl" disabled={submitting || !isFormValid}>
              {submitting ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Creating account...
                </span>
              ) : (
                "Create Account"
              )}
            </Button>
          </form>

          <div className="mt-6 text-xs text-muted-foreground text-center">
            Already provisioned?{" "}
            <Link href="/login" className="text-primary hover:text-primary/80">
              Sign in instead
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
