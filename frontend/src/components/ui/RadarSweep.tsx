import { useEffect, useRef } from 'react';

interface Blip {
  angle: number;
  distance: number;
  severity: string;
}

interface RadarSweepProps {
  size?: number;
  blips?: Blip[];
  sweepColor?: string;
}

const severityBlipColors: Record<string, string> = {
  critical: '#ff1744',
  high: '#ff5722',
  medium: '#ff9800',
  low: '#ffc107',
  info: '#2196f3',
};

export function RadarSweep({ size = 260, blips = [], sweepColor = '#00e5ff' }: RadarSweepProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sweepAngleRef = useRef(0);
  const frameRef = useRef<number>(0);
  const blipTrailsRef = useRef<Map<number, number>>(new Map());

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const maxR = size / 2 - 16;
    const rings = [0.25, 0.5, 0.75, 1.0];
    const ringLabels = ['LOCAL', 'LAN', 'WAN', 'EXT'];

    const parseColor = (hex: string) => {
      const r = parseInt(hex.slice(1, 3), 16);
      const g = parseInt(hex.slice(3, 5), 16);
      const b = parseInt(hex.slice(5, 7), 16);
      return { r, g, b };
    };

    const sc = parseColor(sweepColor);

    const draw = () => {
      ctx.clearRect(0, 0, size, size);

      // Outer glow border
      const outerGlow = ctx.createRadialGradient(cx, cy, maxR - 4, cx, cy, maxR + 6);
      outerGlow.addColorStop(0, `rgba(${sc.r},${sc.g},${sc.b},0.15)`);
      outerGlow.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = outerGlow;
      ctx.fillRect(0, 0, size, size);

      // Dark background circle
      ctx.beginPath();
      ctx.arc(cx, cy, maxR, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(5, 12, 18, 0.92)';
      ctx.fill();

      // Subtle radial gradient overlay
      const bgGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
      bgGrad.addColorStop(0, `rgba(${sc.r},${sc.g},${sc.b},0.04)`);
      bgGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = bgGrad;
      ctx.fill();

      // Concentric rings
      for (let i = 0; i < rings.length; i++) {
        const r = maxR * rings[i];
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${sc.r},${sc.g},${sc.b},${i === rings.length - 1 ? 0.25 : 0.12})`;
        ctx.lineWidth = i === rings.length - 1 ? 1.2 : 0.6;
        ctx.stroke();

        // Ring labels
        ctx.font = '8px "Cascadia Code", monospace';
        ctx.fillStyle = `rgba(${sc.r},${sc.g},${sc.b},0.3)`;
        ctx.textAlign = 'right';
        ctx.fillText(ringLabels[i], cx + r - 3, cy - 3);
      }

      // Cross hairs (8 lines for compass)
      for (let a = 0; a < 8; a++) {
        const angle = (a * Math.PI) / 4;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + maxR * Math.cos(angle), cy + maxR * Math.sin(angle));
        ctx.strokeStyle = `rgba(${sc.r},${sc.g},${sc.b},${a % 2 === 0 ? 0.10 : 0.05})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }

      // Compass labels
      ctx.font = '9px "Cascadia Code", monospace';
      ctx.fillStyle = `rgba(${sc.r},${sc.g},${sc.b},0.25)`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const compassLabels = [
        { label: 'N', angle: -Math.PI / 2 },
        { label: 'E', angle: 0 },
        { label: 'S', angle: Math.PI / 2 },
        { label: 'W', angle: Math.PI },
      ];
      for (const cl of compassLabels) {
        const lx = cx + (maxR + 10) * Math.cos(cl.angle);
        const ly = cy + (maxR + 10) * Math.sin(cl.angle);
        ctx.fillText(cl.label, lx, ly);
      }

      // Sweep trail (gradient arc behind the sweep line)
      const sweepAngle = sweepAngleRef.current;
      const trailLength = Math.PI * 0.6; // ~108 degree trail

      for (let i = 0; i < 60; i++) {
        const t = i / 60;
        const trailAngle = sweepAngle - t * trailLength;
        const alpha = (1 - t) * 0.12;

        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, maxR, trailAngle - 0.02, trailAngle + 0.02);
        ctx.closePath();
        ctx.fillStyle = `rgba(${sc.r},${sc.g},${sc.b},${alpha})`;
        ctx.fill();
      }

      // Sweep line (bright)
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(
        cx + maxR * Math.cos(sweepAngle),
        cy + maxR * Math.sin(sweepAngle)
      );
      ctx.strokeStyle = `rgba(${sc.r},${sc.g},${sc.b},0.9)`;
      ctx.lineWidth = 1.8;
      ctx.shadowColor = sweepColor;
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Blips
      const now = Date.now();
      for (let i = 0; i < blips.length; i++) {
        const blip = blips[i];
        const bRad = (blip.angle * Math.PI) / 180;
        const dist = maxR * Math.min(blip.distance, 1);
        const bx = cx + dist * Math.cos(bRad);
        const by = cy + dist * Math.sin(bRad);
        const color = severityBlipColors[blip.severity] || sweepColor;
        const bc = parseColor(color);

        // Calculate sweep proximity for "freshly scanned" glow
        let angleDiff = sweepAngle - bRad;
        while (angleDiff < 0) angleDiff += Math.PI * 2;
        while (angleDiff > Math.PI * 2) angleDiff -= Math.PI * 2;
        const freshness = angleDiff < Math.PI * 0.5 ? 1 - angleDiff / (Math.PI * 0.5) : 0;

        // Update trail brightness
        if (freshness > 0.8) {
          blipTrailsRef.current.set(i, now);
        }
        const lastHit = blipTrailsRef.current.get(i) || 0;
        const timeSinceHit = (now - lastHit) / 1000;
        const fadeAlpha = Math.max(0.15, 1 - timeSinceHit * 0.25);

        // Outer pulse ring
        const pulseSize = 10 + Math.sin(now / 300 + i) * 3;
        ctx.beginPath();
        ctx.arc(bx, by, pulseSize, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${bc.r},${bc.g},${bc.b},${0.06 * fadeAlpha})`;
        ctx.fill();

        // Mid glow
        ctx.beginPath();
        ctx.arc(bx, by, 6, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${bc.r},${bc.g},${bc.b},${0.2 * fadeAlpha + freshness * 0.3})`;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(bx, by, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${bc.r},${bc.g},${bc.b},${0.7 * fadeAlpha + freshness * 0.3})`;
        ctx.shadowColor = color;
        ctx.shadowBlur = freshness > 0.3 ? 10 : 4;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Center dot + glow
      const centerGlow = ctx.createRadialGradient(cx, cy, 0, cx, cy, 8);
      centerGlow.addColorStop(0, `rgba(${sc.r},${sc.g},${sc.b},0.6)`);
      centerGlow.addColorStop(1, `rgba(${sc.r},${sc.g},${sc.b},0)`);
      ctx.fillStyle = centerGlow;
      ctx.fillRect(cx - 8, cy - 8, 16, 16);

      ctx.beginPath();
      ctx.arc(cx, cy, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = sweepColor;
      ctx.shadowColor = sweepColor;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Scanline effect (subtle horizontal lines)
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, maxR, 0, Math.PI * 2);
      ctx.clip();
      for (let y = 0; y < size; y += 3) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(size, y);
        ctx.strokeStyle = 'rgba(0,0,0,0.08)';
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }
      ctx.restore();

      // Advance sweep
      sweepAngleRef.current += 0.018; // ~4s per revolution
      if (sweepAngleRef.current > Math.PI * 2) {
        sweepAngleRef.current -= Math.PI * 2;
      }

      frameRef.current = requestAnimationFrame(draw);
    };

    frameRef.current = requestAnimationFrame(draw);

    return () => {
      if (frameRef.current) {
        cancelAnimationFrame(frameRef.current);
      }
    };
  }, [size, blips, sweepColor]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width: size,
        height: size,
        display: 'block',
        margin: '0 auto',
      }}
    />
  );
}
