import './SpinningNumbers.css';
import type { CSSProperties } from 'react';
import type { BgSettings } from '../types/bgSettings';
import { DEFAULT_BG_SETTINGS } from '../types/bgSettings';

type Wheel = {
  time: number;
  numbers: number;
  distance: number;
  color: string;
  scale: number;
};

function lerp(a: number, b: number, t: number) {
  return (b - a) * t + a;
}

function getColor(scheme: string, i: number, total: number): string {
  const t = i / total;
  switch (scheme) {
    case 'cyan':
      return `hsl(195, 85%, ${lerp(45, 75, t)}%)`;
    case 'emerald':
      return `hsl(155, 75%, ${lerp(40, 70, t)}%)`;
    case 'purple':
      return `hsl(270, 80%, ${lerp(50, 80, t)}%)`;
    case 'amber':
      return `hsl(38, 90%, ${lerp(45, 75, t)}%)`;
    case 'white':
    default:
      return `hsl(220, 15%, ${lerp(75, 95, t)}%)`;
  }
}

function createWheel(i: number, total: number, speedMultiplier: number, scheme: string): Wheel {
  const distance = i * 2.0 + 3.8;
  const charWidth = 0.9;
  const baseSpeed = 1.2 / Math.max(0.1, speedMultiplier);
  const circum = distance * 2 * Math.PI;
  const numbers = Math.floor(circum / charWidth);
  const time = baseSpeed * numbers;
  const t = i / total;
  return {
    time,
    numbers,
    distance,
    color: getColor(scheme, i, total),
    scale: lerp(1.25, 0.4, t * t * 0.4),
  };
}

function SpinningWheel({ time, numbers, distance, color, scale }: Wheel) {
  const angleDiff = (Math.PI * 2) / numbers;
  const divs: number[] = [];
  for (let i = 0; i < numbers; i++) {
    divs.push(angleDiff * i);
  }
  return (
    <div
      className="wheel"
      style={
        {
          color,
          '--l': `${distance}em`,
          '--m': numbers,
          '--t': `${time}s`,
          '--r1': Math.random() < 0.5 ? 'reverse' : 'normal',
          '--s': scale,
        } as CSSProperties
      }
    >
      {divs.map((angle, i) =>
        Math.sqrt(Math.random()) < scale ? (
          <div
            key={i}
            className="number"
            style={
              {
                '--a': `${(angle * 180) / Math.PI}deg`,
                '--i': i,
                '--r': Math.random() < 0.5 ? 'reverse' : 'normal',
              } as CSSProperties
            }
          />
        ) : null,
      )}
    </div>
  );
}

export default function SpinningNumbers({ settings = DEFAULT_BG_SETTINGS }: { settings?: BgSettings }) {
  const total = 14;
  const wheels: Wheel[] = Array.from({ length: total }, (_, i) =>
    createWheel(i, total, settings.speed, settings.colorScheme),
  );

  return (
    <div
      className="spinning-number"
      style={{
        position: 'absolute',
        top: `${settings.positionY ?? 53}%`,
        left: `${settings.positionX ?? 53}%`,
        transform: `translate(-50%, -50%) scale(${settings.scale ?? 1.05})`,
        transformOrigin: 'center center',
      }}
    >
      {wheels.map((w, i) => (
        <SpinningWheel {...w} key={`${settings.colorScheme}-${settings.speed.toFixed(1)}-${i}`} />
      ))}
    </div>
  );
}
