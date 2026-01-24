/**
 * Socket.IO Service for Real-Time Communication
 * Connects to Flask-SocketIO backend and manages WebSocket events
 */

import { io, Socket } from 'socket.io-client';
import { useMonitorStore } from '@/store/monitorStore';

class SocketService {
  private socket: Socket | null = null;
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private backendUrl: string;

  constructor(backendUrl: string = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000') {
    this.backendUrl = backendUrl;
    console.log(`📡 Using backend URL: ${this.backendUrl}`);
  }

  /**
   * Connect to Flask-SocketIO backend
   */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.socket = io(this.backendUrl, {
          reconnection: true,
          reconnectionDelay: 1000,
          reconnectionDelayMax: 5000,
          reconnectionAttempts: this.maxReconnectAttempts,
          transports: ['polling', 'websocket'], // Start with polling, upgrade to websocket
          upgrade: true,
          withCredentials: false,
          forceNew: true,
          timeout: 20000,
        });

        // Connection events
        this.socket.on('connect', () => {
          this.isConnected = true;
          this.reconnectAttempts = 0;
          console.log('✅ Connected to backend');
          useMonitorStore.getState().setConnected(true);
          resolve();
        });

        this.socket.on('disconnect', () => {
          this.isConnected = false;
          useMonitorStore.getState().setConnected(false);
          console.log('⛔ Disconnected from backend');
        });

        this.socket.on('connect_error', (error) => {
          this.reconnectAttempts++;
          console.error('❌ Connection error:', error);
          if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            reject(error);
          }
        });

        // Real-time event listeners
        this.setupEventListeners();
      } catch (error) {
        console.error('Error initializing socket:', error);
        reject(error);
      }
    });
  }

  /**
   * Set up all Socket.IO event listeners
   */
  private setupEventListeners(): void {
    if (!this.socket) return;

    // Packet events
    this.socket.on('new_packet', (packet: any) => {
      useMonitorStore.getState().addPacket(packet);
    });

    // Alert events
    this.socket.on('new_alert', (alert: any) => {
      console.log('🚨 New alert received:', alert);
      useMonitorStore.getState().addAlert(alert);
    });

    // Security-specific alerts
    this.socket.on('security_alert', (alert: any) => {
      console.log('🛡️ Security alert received:', alert);
      useMonitorStore.getState().addAlert(alert);
    });

    // Device events
    this.socket.on('devices_update', (data: any) => {
      useMonitorStore.getState().updateDevices(data.devices || []);
    });

    // Statistics events
    this.socket.on('update_statistics', (stats: any) => {
      useMonitorStore.getState().updateStats(stats);
    });

    // Traffic events
    this.socket.on('traffic_update', (traffic: any) => {
      useMonitorStore.getState().updateTraffic(traffic);
    });

    // Log events
    this.socket.on('new_log', (log: any) => {
      useMonitorStore.getState().addLog(log);
    });

    // Connection status
    this.socket.on('connection_status', (status: any) => {
      console.log('Connection status:', status);
    });

    // Initial alerts sync on connection
    this.socket.on('alerts_sync', (alertsList: any[]) => {
      useMonitorStore.getState().setAlerts(alertsList);
    });

    // Logs list
    this.socket.on('logs_list', (logsList: any[]) => {
      useMonitorStore.getState().setLogs(logsList);
    });

    // Sniffing status events
    this.socket.on('sniffing_status', (data: any) => {
      console.log('Sniffing status:', data);
      if (data.status === 'started' || data.status === 'already_running') {
        useMonitorStore.getState().setSniffing(true, data.interface || 'Wi-Fi');
      } else if (data.status === 'stopped' || data.status === 'not_running') {
        useMonitorStore.getState().setSniffing(false, null);
      }
    });

    // Processor stats
    this.socket.on('processor_stats', (stats: any) => {
      console.log('Processor stats:', stats);
    });
  }

  /**
   * Disconnect from backend
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.isConnected = false;
      console.log('Socket disconnected');
    }
  }

  /**
   * Check if connected
   */
  getIsConnected(): boolean {
    return this.isConnected;
  }

  /**
   * Emit event to server
   */
  emit(event: string, data?: any): void {
    if (this.socket && this.isConnected) {
      this.socket.emit(event, data);
    } else {
      console.warn(`Cannot emit '${event}': Socket not connected`);
    }
  }

  /**
   * Request logs from server
   */
  requestLogs(): void {
    this.emit('get_logs');
  }

  /**
   * Clear logs on server
   */
  clearLogs(): void {
    this.emit('clear_logs');
  }

  /**
   * Get processor statistics
   */
  getProcessorStats(): void {
    this.emit('get_processor_stats');
  }

  /**
   * Start packet sniffing
   */
  startSniffing(interface_name?: string): void {
    this.emit('start_sniffing', { interface: interface_name });
  }

  /**
   * Stop packet sniffing
   */
  stopSniffing(): void {
    this.emit('stop_sniffing');
  }

  /**
   * Request device scan
   */
  scanDevices(): void {
    this.emit('scan_devices');
  }

  /**
   * Reconnect to backend
   */
  reconnect(): Promise<void> {
    if (this.socket) {
      this.socket.connect();
      return new Promise((resolve) => {
        this.socket?.once('connect', () => resolve());
      });
    }
    return this.connect();
  }
}

// Export singleton instance
export const socketService = new SocketService();

// Export for React hooks
export default SocketService;
