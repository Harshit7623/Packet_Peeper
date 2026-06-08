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

  async login(identifier: string, password: string) {
    const isEmail = identifier.includes('@');
    const payload = isEmail
      ? { email: identifier, password }
      : { username: identifier, password };

    const result = await this.request<{
      message: string;
      token: string;
      expires_in: number;
      user: { username: string; email?: string; role?: string };
      auth_enabled: boolean;
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
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

  async register(username: string, email: string, password: string, passwordConfirm: string) {
    return this.request<{ message: string; user: { username: string; email?: string; role?: string } }>(
      '/api/auth/register',
      {
        method: 'POST',
        body: JSON.stringify({
          username,
          email,
          password,
          password_confirm: passwordConfirm,
        }),
      }
    );
  }

  async getAuthStatus() {
    return this.request<{
      auth_enabled: boolean;
      authenticated: boolean;
      user?: { username: string; email?: string; role?: string };
      expires_in?: number | null;
      error?: string;
    }>('/api/auth/status');
  }

  // ==================== Profile ====================

  async getProfile() {
    return this.request<{
      username: string;
      email?: string;
      role?: string;
      created_at?: string;
      last_login?: string | null;
      device_info?: Record<string, unknown>;
      active_sessions?: Array<Record<string, unknown>>;
      active_session_count?: number;
    }>('/api/profile');
  }

  async updateProfile(updates: { email?: string; device_info?: Record<string, unknown>; preferences?: Record<string, unknown> }) {
    return this.request<{ message: string; user: Record<string, unknown> }>('/api/profile', {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async changePassword(oldPassword: string, newPassword: string, newPasswordConfirm: string) {
    return this.request<{ message: string }>('/api/profile/password', {
      method: 'POST',
      body: JSON.stringify({
        old_password: oldPassword,
        new_password: newPassword,
        new_password_confirm: newPasswordConfirm,
      }),
    });
  }

  async getDeviceInfo() {
    return this.request<{
      mac_address: string;
      ip_address: string;
      hostname: string;
      cpu_count: number;
      total_memory: number;
      os: string;
    }>('/api/profile/device-info');
  }

  // ==================== Packets ====================

  async getPackets(params: {
    limit?: number;
    offset?: number;
    start?: string;
    end?: string;
    protocol?: string;
    src_ip?: string;
    dst_ip?: string;
    src_port?: number;
    dst_port?: number;
    service?: string;
    tcp_flags?: number;
    min_length?: number;
    max_length?: number;
    search?: string;
  } = {}) {
    const { limit = 1000, offset = 0, ...rest } = params;
    const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    Object.entries(rest).forEach(([k, v]) => {
      if (v !== undefined && v !== '') query.set(k, String(v));
    });
    return this.request<{ data: any[]; total: number; limit: number; offset: number }>(`/api/packets?${query}`);
  }

  // ==================== Alerts ====================

  async getAlerts(params: {
    limit?: number;
    offset?: number;
    start?: string;
    end?: string;
    severity?: string;
    alert_type?: string;
    source_ip?: string;
    destination_ip?: string;
    title?: string;
    resolved?: boolean;
    search?: string;
  } = {}) {
    const { limit = 100, offset = 0, ...rest } = params;
    const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    Object.entries(rest).forEach(([k, v]) => {
      if (v !== undefined && v !== '') query.set(k, String(v));
    });
    return this.request<{ data: any[]; total: number; limit: number; offset: number }>(`/api/alerts?${query}`);
  }

  async getSecurityAlerts(limit: number = 100) {
    return this.request<{ data: any[]; total: number }>(`/api/security_alerts?limit=${limit}`);
  }

  async dismissAlert(alertId: number) {
    return this.request(`/api/alerts/${alertId}/dismiss`, { method: 'POST' });
  }

  async clearAlerts() {
    return this.request('/api/alerts/clear', { method: 'POST' });
  }

  // ==================== Devices ====================

  async getDevices(params: {
    ip?: string;
    mac?: string;
    hostname?: string;
    device_type?: string;
    search?: string;
  } = {}) {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '') query.set(k, String(v));
    });
    const qs = query.toString();
    return this.request<{ data: any[]; total: number }>(`/api/devices${qs ? '?' + qs : ''}`);
  }

  async scanNetwork() {
    return this.request<{ message: string; scan_id?: string }>('/api/network/scan', { method: 'POST' });
  }

  // ==================== Search ====================

  async search(query: string, limit: number = 20) {
    return this.request<{ packets: any[]; alerts: any[]; devices: any[]; total: number }>(`/api/search?q=${encodeURIComponent(query)}&limit=${limit}`);
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

  async getSystemHealth() {
    return this.request<{
      cpu: {
        percent: number;
        per_core: number[];
        cores: number;
        physical_cores: number;
        frequency: { current: number; min: number; max: number };
        load_average: number[];
      };
      memory: {
        total: number;
        available: number;
        used: number;
        percent: number;
        swap_total: number;
        swap_used: number;
        swap_percent: number;
      };
      disk: {
        total: number;
        used: number;
        free: number;
        percent: number;
      };
      network: {
        bytes_sent: number;
        bytes_recv: number;
        packets_sent: number;
        packets_recv: number;
        errin: number;
        errout: number;
        dropin: number;
        dropout: number;
      };
      process: {
        memory_rss: number;
        memory_vms: number;
        cpu_percent: number;
        threads: number;
      };
      processing: {
        queue_size: number;
        packets_captured: number;
        alerts_count: number;
        devices_count: number;
      };
      uptime: number;
      platform: string;
    }>('/api/system/health');
  }

  async getTrafficFlow(minutes: number = 30, buckets: number = 30) {
    return this.request<{
      flow: Array<{
        timestamp: string;
        time_label: string;
        tcp: number;
        udp: number;
        icmp: number;
        other: number;
        total: number;
        bytes: number;
      }>;
      minutes: number;
      bucket_count: number;
    }>(`/api/traffic/flow?minutes=${minutes}&buckets=${buckets}`);
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

  // ==================== History / Historical Data ====================

  async getHistoryTimeseries(timeRange: string = '24h', bucket?: number, start?: string, end?: string) {
    const params = new URLSearchParams();
    if (start && end) {
      params.set('start', start);
      params.set('end', end);
    } else {
      params.set('range', timeRange);
    }
    if (bucket !== undefined) {
      params.set('bucket', String(bucket));
    }
    return this.request<{
      data: Array<{
        window_start: string;
        total_packets: number;
        total_bytes: number;
        tcp_packets: number;
        udp_packets: number;
        icmp_packets: number;
        other_packets: number;
        avg_packet_size: number;
        unique_src_ips: number;
        unique_dst_ips: number;
        unique_dst_ports: number;
        syn_count: number;
        syn_ack_ratio: number;
        dns_queries: number;
        arp_packets: number;
        bandwidth_bps: number;
        sample_count: number;
      }>;
      start: string;
      end: string;
      bucket_minutes: number;
      count: number;
    }>(`/api/history/timeseries?${params.toString()}`);
  }

  async getHistorySummary(timeRange: string = '24h', start?: string, end?: string) {
    const params = new URLSearchParams();
    if (start && end) {
      params.set('start', start);
      params.set('end', end);
    } else {
      params.set('range', timeRange);
    }
    return this.request<{
      total_packets: number;
      total_bytes: number;
      avg_bandwidth_bps: number;
      peak_bandwidth_bps: number;
      total_alerts: number;
      unique_src_ips: number;
      start_time: string;
      end_time: string;
    }>(`/api/history/summary?${params.toString()}`);
  }

  async getHistoryProtocols(timeRange: string = '24h', bucket?: number, start?: string, end?: string) {
    const params = new URLSearchParams();
    if (start && end) {
      params.set('start', start);
      params.set('end', end);
    } else {
      params.set('range', timeRange);
    }
    if (bucket !== undefined) {
      params.set('bucket', String(bucket));
    }
    return this.request<{
      data: Array<{
        window_start: string;
        tcp: number;
        udp: number;
        icmp: number;
        other: number;
        total: number;
      }>;
      start: string;
      end: string;
      bucket_minutes: number;
      count: number;
    }>(`/api/history/protocols?${params.toString()}`);
  }

  async getHistoryTopTalkers(timeRange: string = '7d', limit: number = 10, start?: string, end?: string) {
    const params = new URLSearchParams();
    if (start && end) {
      params.set('start', start);
      params.set('end', end);
    } else {
      params.set('range', timeRange);
    }
    params.set('limit', String(limit));
    return this.request<{
      data: Array<{
        ip_address: string;
        hostname: string | null;
        mac_address: string | null;
        device_type: string | null;
        total_packets: number;
        total_bytes: number;
        last_seen: string | null;
      }>;
      start: string;
      end: string;
      count: number;
    }>(`/api/history/top-talkers?${params.toString()}`);
  }

  async getHistoryAlerts(timeRange: string = '7d', severity?: string, limit: number = 100, start?: string, end?: string) {
    const params = new URLSearchParams();
    if (start && end) {
      params.set('start', start);
      params.set('end', end);
    } else {
      params.set('range', timeRange);
    }
    if (severity) {
      params.set('severity', severity);
    }
    params.set('limit', String(limit));
    return this.request<{
      data: any[];
      start: string;
      end: string;
      count: number;
    }>(`/api/history/alerts?${params.toString()}`);
  }

  async getHistoryBandwidth(timeRange: string = '7d', bucket?: number, start?: string, end?: string) {
    const params = new URLSearchParams();
    if (start && end) {
      params.set('start', start);
      params.set('end', end);
    } else {
      params.set('range', timeRange);
    }
    if (bucket !== undefined) {
      params.set('bucket', String(bucket));
    }
    return this.request<{
      data: Array<{
        timestamp: string;
        bandwidth_bps: number;
        total_packets: number;
        total_bytes: number;
      }>;
      start: string;
      end: string;
      bucket_minutes: number;
      count: number;
    }>(`/api/history/bandwidth?${params.toString()}`);
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

  // ==================== ML Anomaly Detection ====================

  async getMlStatus() {
    return this.request<{
      model_loaded: boolean;
      last_trained: string | null;
      training_samples: number;
      score_threshold: number;
      training_window_hours: number;
      min_training_samples: number;
      total_scores: number;
      anomaly_count: number;
      last_score_time: string | null;
      model_path: string;
    }>('/api/ml/status');
  }

  async getMlScores(limit: number = 200) {
    return this.request<{
      scores: Array<{
        timestamp: string;
        score: number;
        is_anomaly: boolean;
        threshold: number;
        window_start: string | null;
      }>;
      count: number;
    }>(`/api/ml/scores?limit=${limit}`);
  }

  async retrainMl(windowHours?: number) {
    return this.request<{
      success: boolean;
      samples?: number;
      contamination?: number;
      start_time?: string;
      end_time?: string;
      trained_at?: string;
      error?: string;
    }>('/api/ml/retrain', {
      method: 'POST',
      body: JSON.stringify({ window_hours: windowHours }),
    }, 30000);
  }

  async getMlConfig() {
    return this.request<{
      score_threshold: number;
      training_window_hours: number;
      min_training_samples: number;
      feature_columns: string[];
    }>('/api/ml/config');
  }

  async updateMlConfig(config: { score_threshold?: number }) {
    return this.request<any>('/api/ml/config', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }
}

// Export singleton instance
export const apiService = new ApiService();

export default ApiService;
