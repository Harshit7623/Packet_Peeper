/**
 * API Service for REST API calls to Flask backend
 * Handles all HTTP requests to the backend
 */

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
const AUTH_TOKEN_KEY = 'packet_peeper_auth_token';

export class ApiError extends Error {
  status?: number;
  code?: string;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

class ApiService {
  private baseUrl: string;
  private authToken: string | null;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
    this.authToken = this.loadStoredToken();
  }

  private loadStoredToken(): string | null {
    try {
      return localStorage.getItem(AUTH_TOKEN_KEY);
    } catch {
      return null;
    }
  }

  setAuthToken(token: string | null): void {
    this.authToken = token;
    try {
      if (token) {
        localStorage.setItem(AUTH_TOKEN_KEY, token);
      } else {
        localStorage.removeItem(AUTH_TOKEN_KEY);
      }
    } catch {
      // Ignore persistence issues in restricted environments.
    }
  }

  getAuthToken(): string | null {
    return this.authToken;
  }

  private getAuthHeaders(): HeadersInit {
    if (!this.authToken) {
      return {};
    }

    return {
      Authorization: `Bearer ${this.authToken}`,
    };
  }

  private async request<T>(endpoint: string, options: RequestInit = {}, timeout: number = 10000): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const defaultHeaders: HeadersInit = {
      'Content-Type': 'application/json',
      ...this.getAuthHeaders(),
    };

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          ...defaultHeaders,
          ...options.headers,
        },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorMessage = `HTTP error! status: ${response.status}`;
        let errorCode: string | undefined;

        try {
          const payload = await response.json();
          if (payload?.error) {
            errorMessage = payload.error;
          }
          if (payload?.code) {
            errorCode = payload.code;
          }
        } catch {
          const fallbackText = await response.text().catch(() => '');
          if (fallbackText) {
            errorMessage = fallbackText;
          }
        }

        throw new ApiError(errorMessage, response.status, errorCode);
      }

      if (response.status === 204) {
        return undefined as T;
      }

      return response.json();
    } catch (error: any) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        console.error(`API Timeout [${endpoint}]: Request took longer than ${timeout}ms`);
        throw new Error('Request timed out. Please try again.');
      }
      console.error(`API Error [${endpoint}]:`, error);
      throw error;
    }
  }

  private async requestBlob(endpoint: string, options: RequestInit = {}, timeout: number = 20000): Promise<Blob> {
    const url = `${this.baseUrl}${endpoint}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          ...this.getAuthHeaders(),
          ...options.headers,
        },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new ApiError(`Request failed with status ${response.status}`, response.status);
      }

      return response.blob();
    } catch (error: any) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new ApiError('Request timed out', 408);
      }
      throw error;
    }
  }

  // ==================== Authentication ====================

  async login(username: string, password: string) {
    const result = await this.request<{
      message: string;
      token: string;
      expires_in: number;
      user: { username: string };
      auth_enabled: boolean;
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });

    if (result?.token) {
      this.setAuthToken(result.token);
    }

    return result;
  }

  async logout() {
    try {
      await this.request<{ message: string }>('/api/auth/logout', { method: 'POST' });
    } finally {
      this.setAuthToken(null);
    }
  }

  async getAuthStatus() {
    return this.request<{
      auth_enabled: boolean;
      authenticated: boolean;
      user?: { username: string };
      expires_in?: number | null;
      error?: string;
    }>('/api/auth/status');
  }

  // ==================== Packets ====================

  async getPackets(limit: number = 1000) {
    return this.request<any[]>(`/api/packets?limit=${limit}`);
  }

  // ==================== Alerts ====================

  async getAlerts(limit: number = 100) {
    return this.request<any[]>(`/api/alerts?limit=${limit}`);
  }

  async getSecurityAlerts(limit: number = 100) {
    return this.request<any[]>(`/api/security_alerts?limit=${limit}`);
  }

  async dismissAlert(alertId: number) {
    return this.request(`/api/alerts/${alertId}/dismiss`, { method: 'POST' });
  }

  async clearAlerts() {
    return this.request('/api/alerts/clear', { method: 'POST' });
  }

  // ==================== Devices ====================

  async getDevices() {
    return this.request<any[]>('/api/devices');
  }

  async scanNetwork() {
    return this.request<{ message: string; scan_id?: string }>('/api/network/scan', { method: 'POST' });
  }

  // ==================== Statistics ====================

  async getStats() {
    return this.request<any>('/api/stats');
  }

  async getTrafficStats() {
    return this.request<any>('/api/traffic/stats');
  }

  // ==================== Logs ====================

  async getLogs(limit: number = 100) {
    return this.request<any[]>(`/api/logs?limit=${limit}`);
  }

  async clearLogs() {
    return this.request('/api/logs/clear', { method: 'POST' });
  }

  // ==================== Sniffing Control ====================

  async startSniffing(interfaceName?: string) {
    return this.request<{ message: string; interface?: string }>(
      '/api/sniffing/start',
      { 
        method: 'POST',
        body: JSON.stringify({ interface: interfaceName || 'auto' })
      }
    );
  }

  async stopSniffing() {
    return this.request<{ message: string }>('/api/sniffing/stop', { method: 'POST' });
  }

  async getSniffingStatus() {
    return this.request<{ is_running: boolean; interface?: string; start_time?: string }>('/api/sniffing/status');
  }

  async getInterfaces() {
    return this.request<{ interfaces: string[] }>('/api/interfaces');
  }

  // ==================== Reports ====================

  async generateReport(type: 'pdf' | 'csv' | 'json' = 'json') {
    return this.requestBlob('/api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type }),
    });
  }

  async downloadReport(type: 'pdf' | 'csv' | 'json' = 'json') {
    const blob = await this.generateReport(type);
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network_report_${new Date().toISOString().split('T')[0]}.${type}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }

  // ==================== Settings ====================

  async getSettings() {
    return this.request<any>('/api/settings');
  }

  async updateSettings(settings: any) {
    return this.request('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  }

  // ==================== System ====================

  async getSystemInfo() {
    return this.request<any>('/api/system/info');
  }

  async getHealthStatus() {
    return this.request<{ status: string; uptime?: number; version?: string }>('/api/health');
  }

  // ==================== Analytics ====================

  async getAnalytics(timeRange: string = '24h') {
    return this.request<any>(`/api/analytics?range=${timeRange}`);
  }

  async getProtocolDistribution() {
    return this.request<any>('/api/analytics/protocols');
  }

  async getTopTalkers(limit: number = 10) {
    return this.request<any[]>(`/api/analytics/top-talkers?limit=${limit}`);
  }

  async getBandwidthHistory(hours: number = 24) {
    return this.request<any[]>(`/api/analytics/bandwidth?hours=${hours}`);
  }

  // ==================== AI Assistant ====================

  async getAIRemediation(alert: any) {
    // Longer timeout for AI requests (15 seconds)
    return this.request<{
      success: boolean;
      explanation: string;
      steps: string[];
      severity_assessment: string;
      estimated_risk: string;
      technical_details?: string;
      prevention_tips?: string[];
      provider: string;
      cached?: boolean;
    }>('/api/ai/remediate', {
      method: 'POST',
      body: JSON.stringify(alert),
    }, 15000);
  }

  async explainTerm(term: string) {
    return this.request<{
      term: string;
      found: boolean;
      simple: string;
      analogy: string;
      risk: string;
    }>('/api/ai/explain', {
      method: 'POST',
      body: JSON.stringify({ term }),
    });
  }

  async getNetworkHealthSummary() {
    return this.request<{
      status: string;
      message: string;
      action: string;
      stats?: {
        total_alerts: number;
        critical: number;
        high: number;
        medium: number;
      };
    }>('/api/ai/health-summary');
  }

  async getAIStatus() {
    return this.request<{
      provider: string;
      model?: string;
      available: boolean;
      cache_size?: number;
      is_fallback?: boolean;
      confidence?: string;
      message?: string;
      providers_available?: Record<string, boolean>;
    }>('/api/ai/status');
  }

  // ==================== Detection Profile ====================

  async getDetectionProfile() {
    return this.request<{
      current_profile: string;
      available_profiles: string[];
      current_thresholds?: Record<string, any>;
      description?: Record<string, string>;
    }>('/api/detection/profile');
  }

  async setDetectionProfile(profile: string) {
    return this.request<{
      message: string;
      current_profile: string;
      current_thresholds?: Record<string, any>;
    }>('/api/detection/profile', {
      method: 'POST',
      body: JSON.stringify({ profile })
    });
  }
}

// Export singleton instance
export const apiService = new ApiService();

export default ApiService;
