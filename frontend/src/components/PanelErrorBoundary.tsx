import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  panelName: string;
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class PanelErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error(`[CONTAINMENT BREACH] ${this.props.panelName}:`, error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '24px',
          border: '1px solid var(--severity-critical, #ff1744)',
          borderRadius: '4px',
          background: 'rgba(255, 23, 68, 0.05)',
          fontFamily: 'var(--font-mono, monospace)',
        }}>
          <div style={{
            fontSize: '18px',
            letterSpacing: '2px',
            color: 'var(--severity-critical, #ff1744)',
            marginBottom: '12px',
            fontWeight: 700,
          }}>
            {'// CONTAINMENT BREACH \u2014 '}{this.props.panelName}
          </div>
          <div style={{
            fontSize: '17px',
            color: 'var(--text-secondary, #999)',
            marginBottom: '16px',
            lineHeight: '1.6',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}>
            {this.state.error?.message || 'Unknown error'}
          </div>
          <button
            onClick={this.handleReset}
            style={{
              padding: '6px 16px',
              background: 'transparent',
              border: '1px solid var(--severity-critical, #ff1744)',
              borderRadius: '2px',
              color: 'var(--severity-critical, #ff1744)',
              fontSize: '16px',
              fontFamily: 'var(--font-mono, monospace)',
              letterSpacing: '2px',
              cursor: 'pointer',
              textTransform: 'uppercase',
            }}
          >
            Reinitialize
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export { PanelErrorBoundary };
