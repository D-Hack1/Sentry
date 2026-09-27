export type BgColorScheme = 'white' | 'cyan' | 'emerald' | 'purple' | 'amber';
export type BgAlignment = 'center' | 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right';

export interface BgSettings {
  opacity: number;        // 0.09 (9%)
  scale: number;          // 1.05 (105%)
  colorScheme: BgColorScheme; // 'purple'
  speed: number;          // 0.8x
  alignment: BgAlignment; // 'center'
  positionX: number;      // 53%
  positionY: number;      // 53%
}

export const DEFAULT_BG_SETTINGS: BgSettings = {
  opacity: 0.09,
  scale: 1.05,
  colorScheme: 'purple',
  speed: 0.8,
  alignment: 'center',
  positionX: 53,
  positionY: 53,
};
