/**
 * Zustand Store for Network Monitoring State
 * Manages real-time network data shared across all pages
 */

import { create } from 'zustand';

// Type definitions
export interface Packet {
  id?: number;
  timestamp: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  service?: string;
  payload_hash?: string;
}

export interface Alert {
  id: number;
  type: string;
  title: string;
  description: string;
  timestamp: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  additional_info?: Record<string, any>;
}

export interface Device {
  ip_address: string;
  mac_address: string;
  hostname: string;
  device_type: string;
  first_seen?: string;
  last_seen?: string;
  packets_in: number;
  packets_out: number;
  bytes_in?: number;
  bytes_out?: number;
}

export interface TrafficStats {
  total_packets: number;
  totalPackets?: number;
  tcpPackets?: number;
  udpPackets?: number;
  icmpPackets?: number;
  currentBandwidth: number;
  peakBandwidth: number;
  averageBandwidth: number;
  [key: string]: any;
}

export interface Traffic {
  total_packets: number;
  bandwidth?: {
    current: number;
    peak: number;
    average: number;
  };
  protocols?: {
    TCP: number;
    UDP: number;
    ICMP: number;
  };
}

export interface LogEntry {
  timestamp: string;
  level: string;
  source: string;
  message: string;
}

interface MonitorState {
  // State
  packets: Packet[];
  alerts: Alert[];
  devices: Device[];
  stats: TrafficStats;
  traffic: Traffic | null;
  logs: LogEntry[];
  isConnected: boolean;
  isSniffing: boolean;
  sniffingInterface: string | null;

  // Packet methods
  addPacket: (packet: Packet) => void;
  setPackets: (packets: Packet[]) => void;
  clearPackets: () => void;
  getPacketsCount: () => number;

  // Alert methods
  addAlert: (alert: Alert) => void;
  setAlerts: (alerts: Alert[]) => void;
  clearAlerts: () => void;
  getAlertsCount: () => number;
  getCriticalAlertsCount: () => number;

  // Device methods
  updateDevices: (devices: Device[]) => void;
  setDevices: (devices: Device[]) => void;
  getDeviceCount: () => number;

  // Statistics methods
  updateStats: (stats: TrafficStats) => void;
  setStats: (stats: TrafficStats) => void;

  // Traffic methods
  updateTraffic: (traffic: Traffic) => void;

  // Log methods
  addLog: (log: LogEntry) => void;
  setLogs: (logs: LogEntry[]) => void;
  clearLogs: () => void;
  getLogsCount: () => number;

  // Connection status
  setConnected: (connected: boolean) => void;

  // Sniffing status
  setSniffing: (isSniffing: boolean, interfaceName?: string | null) => void;

  // Reset all
  reset: () => void;
}

export const useMonitorStore = create<MonitorState>((set, get) => ({
  // Initial state
  packets: [],
  alerts: [],
  devices: [],
  stats: {
    total_packets: 0,
    totalPackets: 0,
    tcpPackets: 0,
    udpPackets: 0,
    icmpPackets: 0,
    currentBandwidth: 0,
    peakBandwidth: 0,
    averageBandwidth: 0,
  },
  traffic: null,
  logs: [],
  isConnected: false,
  isSniffing: true, // Default to true since backend auto-starts
  sniffingInterface: 'Wi-Fi',

  // Packet methods
  addPacket: (packet: Packet) =>
    set((state) => {
      const maxPackets = 1000; // Limit in-memory packets
      const newPackets = [packet, ...state.packets].slice(0, maxPackets);
      return { packets: newPackets };
    }),

  setPackets: (packets: Packet[]) => set({ packets }),

  clearPackets: () => set({ packets: [] }),

  getPacketsCount: () => get().packets.length,

  // Alert methods
  addAlert: (alert: Alert) =>
    set((state) => {
      const maxAlerts = 20; // Limit to 20 alerts as per config
      const newAlerts = [alert, ...state.alerts].slice(0, maxAlerts);
      return { alerts: newAlerts };
    }),

  setAlerts: (alerts: Alert[]) => set({ alerts: alerts.slice(0, 20) }),

  clearAlerts: () => set({ alerts: [] }),

  getAlertsCount: () => get().alerts.length,

  getCriticalAlertsCount: () =>
    get().alerts.filter((a) => a.severity === 'critical').length,

  // Device methods
  updateDevices: (devices: any[]) =>
    set((state) => {
      // Merge with existing devices, update last_seen
      const deviceMap = new Map();

      // Add existing devices
      state.devices.forEach((d) => {
        deviceMap.set(d.ip_address, d);
      });

      // Update with new data - transform camelCase from backend to snake_case
      devices.forEach((d) => {
        const ip = d.ip_address || d.ipAddress || '';
        const existing = deviceMap.get(ip);
        const transformed: Device = {
          ip_address: ip,
          mac_address: d.mac_address || d.macAddress || '',
          hostname: d.hostname || '',
          device_type: d.device_type || d.type || 'unknown',
          first_seen: d.first_seen || d.firstSeen,
          last_seen: new Date().toISOString(),
          packets_in: d.packets_in ?? d.packetsIn ?? 0,
          packets_out: d.packets_out ?? d.packetsOut ?? 0,
          bytes_in: d.bytes_in ?? d.bytesIn ?? 0,
          bytes_out: d.bytes_out ?? d.bytesOut ?? 0,
        };
        deviceMap.set(ip, { ...existing, ...transformed });
      });

      return { devices: Array.from(deviceMap.values()) };
    }),

  setDevices: (devices: Device[]) => set({ devices }),

  getDeviceCount: () => get().devices.length,

  // Statistics methods
  updateStats: (stats: TrafficStats) =>
    set((state) => ({
      stats: {
        ...state.stats,
        ...stats,
      },
    })),

  setStats: (stats: TrafficStats) => set({ stats }),

  // Traffic methods
  updateTraffic: (traffic: Traffic) =>
    set((state) => ({
      traffic: {
        ...state.traffic,
        ...traffic,
      },
    })),

  // Log methods
  addLog: (log: LogEntry) =>
    set((state) => {
      const maxLogs = 500; // Limit in-memory logs
      const newLogs = [log, ...state.logs].slice(0, maxLogs);
      return { logs: newLogs };
    }),

  setLogs: (logs: LogEntry[]) => set({ logs }),

  clearLogs: () => set({ logs: [] }),

  getLogsCount: () => get().logs.length,

  // Connection status
  setConnected: (connected: boolean) => set({ isConnected: connected }),

  // Sniffing status
  setSniffing: (isSniffing: boolean, interfaceName: string | null = null) => 
    set({ isSniffing, sniffingInterface: interfaceName }),

  // Reset all
  reset: () =>
    set({
      packets: [],
      alerts: [],
      devices: [],
      stats: {
        total_packets: 0,
        totalPackets: 0,
        tcpPackets: 0,
        udpPackets: 0,
        icmpPackets: 0,
        currentBandwidth: 0,
        peakBandwidth: 0,
        averageBandwidth: 0,
      },
      traffic: null,
      logs: [],
      isConnected: false,
      isSniffing: false,
      sniffingInterface: null,
    }),
}));
