import './VpnStatusPanel.css';

interface VpnStatusPanelProps {
  connected: boolean;
  protocol: string | null;
  vpnIp: string | null;
  provider: string | null;
}

export function VpnStatusPanel({ connected, protocol, vpnIp, provider }: VpnStatusPanelProps) {
  return (
    <div className={`vpn-panel ${connected ? 'vpn-panel--connected' : 'vpn-panel--disconnected'}`}>
      <div className="vpn-panel__indicator" />
      <div className="vpn-panel__info">
        <div className="vpn-panel__status">
          {connected ? 'VPN ACTIVE' : 'VPN INACTIVE'}
        </div>
        {connected && (
          <div className="vpn-panel__details">
            {provider && <span>{provider}</span>}
            {protocol && <span>{protocol}</span>}
            {vpnIp && <span className="vpn-panel__ip">{vpnIp}</span>}
          </div>
        )}
      </div>
    </div>
  );
}
