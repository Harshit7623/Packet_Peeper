import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { apiService, ApiError } from "@/services/apiService";
import { socketService } from "@/services/socketService";
import { useMonitorStore } from "@/store/monitorStore";

interface AuthUser {
  username: string;
  email?: string;
  role?: string;
  default_org_id?: number | null;
  organizations?: Array<Record<string, unknown>>;
}

interface AuthContextValue {
  authEnabled: boolean;
  isAuthenticated: boolean;
  isLoading: boolean;
  user: AuthUser | null;
  error: string | null;
  isAdmin: boolean;
  isOperator: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, passwordConfirm: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [authEnabled, setAuthEnabled] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    setIsLoading(true);

    try {
      const status = await apiService.getAuthStatus();
      const enabled = Boolean(status.auth_enabled);
      const authenticated = enabled ? Boolean(status.authenticated) : true;

      setAuthEnabled(enabled);
      setIsAuthenticated(authenticated);
      const authUser: AuthUser | null = status.user ?? (enabled ? null : { username: "operator", role: "operator" });
      setUser(authUser);
      setError(null);

      if (enabled && authenticated && authUser) {
        try {
          const profile = await apiService.getProfile();
          authUser.role = profile.role ?? authUser.role;
          authUser.default_org_id = (profile as any).default_org_id ?? null;
          authUser.organizations = (profile as any).organizations ?? [];
          setUser({ ...authUser });
        } catch {
          // Profile fetch is best-effort; don't block on it
        }
      }

      if (enabled && !authenticated) {
        apiService.setAuthToken(null);
      }
    } catch {
      // If status endpoint is unavailable, do not block app usage.
      setAuthEnabled(false);
      setIsAuthenticated(true);
      setUser({ username: "operator", role: "operator" });
      setError(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const login = useCallback(async (identifier: string, password: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await apiService.login(identifier, password);
      setAuthEnabled(Boolean(result.auth_enabled));
      setIsAuthenticated(true);
      const loginUser: AuthUser = result.user ?? { username: identifier };
      setUser(loginUser);

      if (result.auth_enabled) {
        try {
          const profile = await apiService.getProfile();
          loginUser.role = profile.role ?? loginUser.role;
          loginUser.default_org_id = (profile as any).default_org_id ?? null;
          loginUser.organizations = (profile as any).organizations ?? [];
          setUser({ ...loginUser });
        } catch {
          // best-effort
        }
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Login failed. Please try again.";
      setError(message);
      setIsAuthenticated(false);
      setUser(null);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(async (username: string, email: string, password: string, passwordConfirm: string) => {
    setIsLoading(true);
    setError(null);

    try {
      await apiService.register(username, email, password, passwordConfirm);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Registration failed. Please try again.";
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setIsLoading(true);

    try {
      await apiService.logout();
    } catch {
      // Ignore network failures and clear client state anyway.
    }

    socketService.disconnect();
    useMonitorStore.getState().reset();

    if (authEnabled) {
      setIsAuthenticated(false);
      setUser(null);
    } else {
      setIsAuthenticated(true);
      setUser({ username: "operator" });
    }

    setError(null);
    setIsLoading(false);
  }, [authEnabled]);

  const clearError = useCallback(() => setError(null), []);

  const isAdmin = user?.role === 'admin';
  const isOperator = user?.role === 'operator' || isAdmin;

  const value = useMemo<AuthContextValue>(
    () => ({
      authEnabled,
      isAuthenticated,
      isLoading,
      user,
      error,
      isAdmin,
      isOperator,
      login,
      logout,
      register,
      refreshStatus,
      clearError,
    }),
    [authEnabled, isAuthenticated, isLoading, user, error, isAdmin, isOperator, login, logout, register, refreshStatus, clearError]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
