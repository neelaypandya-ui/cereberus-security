import { useEffect, useRef, useState, useCallback } from 'react';

interface VpnStatus {
  connected: boolean;
  protocol: string | null;
  provider: string | null;
  vpn_ip: string | null;
  interface_name: string | null;
}

interface NetworkStats {
  total: number;
  established: number;
  listening: number;
  time_wait: number;
  close_wait: number;
  suspicious: number;
  tcp: number;
  udp: number;
  last_scan: string | null;
}

interface AlertData {
  timestamp: string;
  severity: string;
  module_source: string;
  title: string;
  description: string;
  details: unknown;
  acknowledged: boolean;
}

interface WsMessage {
  type: string;
  data: unknown;
  timestamp: string;
}

export function useWebSocket() {
  const [vpnStatus, setVpnStatus] = useState<VpnStatus | null>(null);
  const [networkStats, setNetworkStats] = useState<NetworkStats | null>(null);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [threatLevel, setThreatLevel] = useState<string>('none');
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number | null>(null);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const ws = new WebSocket(`${protocol}//${host}/ws/events`);

    ws.onopen = () => {
      setConnected(true);
      // Send ping
      ws.send(JSON.stringify({ type: 'ping' }));
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        setLastMessage(msg);

        if (msg.type === 'vpn_status') {
          setVpnStatus(msg.data as VpnStatus);
        } else if (msg.type === 'network_stats') {
          setNetworkStats(msg.data as NetworkStats);
        } else if (msg.type === 'alert') {
          setAlerts((prev) => [msg.data as AlertData, ...prev].slice(0, 100));
        } else if (msg.type === 'threat_level') {
          const data = msg.data as { level: string };
          setThreatLevel(data.level || 'none');
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      setConnected(false);
      // Reconnect after 3 seconds
      reconnectTimer.current = window.setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };

    wsRef.current = ws;
  }, []);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
      }
      wsRef.current?.close();
    };
  }, [connect]);

  return { vpnStatus, networkStats, alerts, threatLevel, connected, lastMessage };
}
