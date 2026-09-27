import { X, Sliders, RotateCcw, Palette, Maximize2, Eye, Gauge, Move, MoveHorizontal, MoveVertical } from 'lucide-react';
import type { BgSettings, BgColorScheme, BgAlignment } from '../types/bgSettings';
import { DEFAULT_BG_SETTINGS } from '../types/bgSettings';

interface BgSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  settings: BgSettings;
  onChangeSettings: (newSettings: BgSettings) => void;
}

const COLOR_PRESETS: { id: BgColorScheme; label: string; bgClass: string }[] = [
  { id: 'white', label: 'Grey', bgClass: 'bg-slate-300' },
  { id: 'cyan', label: 'Cyan', bgClass: 'bg-cyan-400' },
  { id: 'emerald', label: 'Emerald', bgClass: 'bg-emerald-400' },
  { id: 'purple', label: 'Purple', bgClass: 'bg-purple-400' },
  { id: 'amber', label: 'Gold', bgClass: 'bg-amber-400' },
];

const ALIGN_PRESETS: { id: BgAlignment; label: string; x: number; y: number }[] = [
  { id: 'top-left', label: '↖ Top L', x: 20, y: 20 },
  { id: 'top-right', label: '↗ Top R', x: 80, y: 20 },
  { id: 'center', label: '🎯 Center', x: 50, y: 50 },
  { id: 'bottom-left', label: '↙ Btm L', x: 20, y: 80 },
  { id: 'bottom-right', label: '↘ Btm R', x: 80, y: 80 },
];

export default function BgSettingsModal({
  isOpen,
  onClose,
  settings,
  onChangeSettings,
}: BgSettingsModalProps) {
  if (!isOpen) return null;

  const update = (key: keyof BgSettings, val: unknown) => {
    onChangeSettings({
      ...settings,
      [key]: val,
    });
  };

  const setAlignPreset = (preset: typeof ALIGN_PRESETS[number]) => {
    onChangeSettings({
      ...settings,
      alignment: preset.id,
      positionX: preset.x,
      positionY: preset.y,
    });
  };

  const reset = () => {
    onChangeSettings(DEFAULT_BG_SETTINGS);
  };

  return (
    <div className="fixed bottom-4 right-4 md:right-8 z-50 w-80 md:w-96 p-5 bg-[var(--color-surface)]/95 border border-[var(--color-border-strong)] shadow-2xl rounded-2xl animate-fade-in transition-all">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border-subtle)] mb-4">
        <div className="flex items-center gap-2 text-sm font-bold">
          <Sliders size={16} className="text-[var(--color-primary)]" />
          <span>Background Customizer</span>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-lg hover:bg-[var(--color-surface-hover)] text-gray-400 hover:text-white transition-colors"
          aria-label="Close background controls"
        >
          <X size={16} />
        </button>
      </div>

      {/* Settings Grid */}
      <div className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
        {/* Alignment Presets */}
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-300">
            <Move size={14} className="text-gray-400" /> Alignment & Position
          </div>
          <div className="grid grid-cols-5 gap-1">
            {ALIGN_PRESETS.map(preset => (
              <button
                key={preset.id}
                onClick={() => setAlignPreset(preset)}
                className={`py-1.5 px-1 rounded text-[11px] font-medium border transition-all text-center ${
                  settings.positionX === preset.x && settings.positionY === preset.y
                    ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/20 text-[var(--color-primary)] font-bold'
                    : 'border-[var(--color-border-subtle)] text-gray-300 hover:bg-[var(--color-surface-hover)]'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* Position X Slider */}
          <div className="pt-1 space-y-1">
            <div className="flex justify-between items-center text-[11px] text-gray-400 font-mono">
              <span className="flex items-center gap-1"><MoveHorizontal size={12} /> Position X</span>
              <span>{settings.positionX ?? 50}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              step="1"
              value={settings.positionX ?? 50}
              onChange={e => update('positionX', parseInt(e.target.value, 10))}
              className="w-full h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
            />
          </div>

          {/* Position Y Slider */}
          <div className="space-y-1">
            <div className="flex justify-between items-center text-[11px] text-gray-400 font-mono">
              <span className="flex items-center gap-1"><MoveVertical size={12} /> Position Y</span>
              <span>{settings.positionY ?? 50}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              step="1"
              value={settings.positionY ?? 50}
              onChange={e => update('positionY', parseInt(e.target.value, 10))}
              className="w-full h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
            />
          </div>
        </div>

        {/* Opacity Control */}
        <div className="space-y-1 pt-1">
          <div className="flex justify-between items-center text-xs font-semibold text-gray-300">
            <span className="flex items-center gap-1.5">
              <Eye size={14} className="text-gray-400" /> Opacity
            </span>
            <span className="font-mono text-xs text-gray-300">
              {Math.round(settings.opacity * 100)}%
            </span>
          </div>
          <input
            type="range"
            min="0.05"
            max="0.70"
            step="0.01"
            value={settings.opacity}
            onChange={e => update('opacity', parseFloat(e.target.value))}
            className="w-full h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
          />
        </div>

        {/* Size / Scale Control */}
        <div className="space-y-1">
          <div className="flex justify-between items-center text-xs font-semibold text-gray-300">
            <span className="flex items-center gap-1.5">
              <Maximize2 size={14} className="text-gray-400" /> Size & Scale
            </span>
            <span className="font-mono text-xs text-gray-300">
              {Math.round(settings.scale * 100)}%
            </span>
          </div>
          <input
            type="range"
            min="0.30"
            max="1.50"
            step="0.05"
            value={settings.scale}
            onChange={e => update('scale', parseFloat(e.target.value))}
            className="w-full h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
          />
        </div>

        {/* Animation Speed Control */}
        <div className="space-y-1">
          <div className="flex justify-between items-center text-xs font-semibold text-gray-300">
            <span className="flex items-center gap-1.5">
              <Gauge size={14} className="text-gray-400" /> Speed
            </span>
            <span className="font-mono text-xs text-gray-300">
              {settings.speed.toFixed(1)}x
            </span>
          </div>
          <input
            type="range"
            min="0.3"
            max="2.5"
            step="0.1"
            value={settings.speed}
            onChange={e => update('speed', parseFloat(e.target.value))}
            className="w-full h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
          />
        </div>

        {/* Color Accent Presets */}
        <div className="space-y-1 pt-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-300 mb-1.5">
            <Palette size={14} className="text-gray-400" /> Color Accent
          </div>
          <div className="grid grid-cols-5 gap-1.5">
            {COLOR_PRESETS.map(preset => {
              const isActive = settings.colorScheme === preset.id;
              return (
                <button
                  key={preset.id}
                  onClick={() => update('colorScheme', preset.id)}
                  className={`flex flex-col items-center justify-center p-1.5 rounded-lg border transition-all ${
                    isActive
                      ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/15 shadow-[0_0_10px_rgba(14,165,233,0.3)] font-bold'
                      : 'border-[var(--color-border-subtle)] hover:bg-[var(--color-surface-hover)]'
                  }`}
                  title={preset.label}
                >
                  <div className={`w-3.5 h-3.5 rounded-full ${preset.bgClass} mb-1`} />
                  <span className="text-[10px] truncate max-w-full font-medium text-gray-300">
                    {preset.label}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between mt-5 pt-3 border-t border-[var(--color-border-subtle)]">
        <button
          onClick={reset}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition-colors"
        >
          <RotateCcw size={13} /> Reset
        </button>
        <button
          onClick={onClose}
          className="btn-primary text-xs px-3.5 py-1"
        >
          Done
        </button>
      </div>
    </div>
  );
}
