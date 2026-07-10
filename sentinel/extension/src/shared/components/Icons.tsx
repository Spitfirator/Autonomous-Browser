// Inline stroke icons (16px grid, 1.5 stroke, round caps) - bundled locally,
// matching the stroke-icon language of the FUZER dashboard.

import type { ReactNode } from 'react';

function Svg({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export function PlayIcon() {
  return (
    <Svg>
      <path d="M5 3.2v9.6c0 .5.55.8.98.53l7.02-4.8a.62.62 0 0 0 0-1.06L5.98 2.67A.62.62 0 0 0 5 3.2Z" />
    </Svg>
  );
}

export function PauseIcon() {
  return (
    <Svg>
      <path d="M5.2 3v10M10.8 3v10" />
    </Svg>
  );
}

export function StopIcon() {
  return (
    <Svg>
      <rect x="3.5" y="3.5" width="9" height="9" rx="1.5" />
    </Svg>
  );
}

export function OverlayIcon() {
  return (
    <Svg>
      <rect x="2" y="2.8" width="12" height="10.4" rx="2" />
      <circle cx="8" cy="8" r="1.6" fill="currentColor" stroke="none" />
    </Svg>
  );
}

export function SettingsIcon() {
  return (
    <Svg>
      <path d="M2.5 5h6.6M12.5 5h1M2.5 11h1.9M7.8 11h5.7" />
      <circle cx="10.7" cy="5" r="1.6" />
      <circle cx="6" cy="11" r="1.6" />
    </Svg>
  );
}

export function SendIcon() {
  return (
    <Svg>
      <path d="M8 13V3M3.8 7.2 8 3l4.2 4.2" />
    </Svg>
  );
}

export function RefreshIcon() {
  return (
    <Svg>
      <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 2.8v3.4h-3.4" />
    </Svg>
  );
}

export function CpuIcon() {
  return (
    <Svg>
      <rect x="4" y="4" width="8" height="8" rx="1.5" />
      <rect x="6.6" y="6.6" width="2.8" height="2.8" rx="0.6" />
      <path d="M6 4V2M10 4V2M6 14v-2M10 14v-2M4 6H2M4 10H2M14 6h-2M14 10h-2" />
    </Svg>
  );
}

export function ShieldIcon() {
  return (
    <Svg>
      <path d="M8 1.8 3 3.6v4.2c0 3 2.1 5.2 5 6.4 2.9-1.2 5-3.4 5-6.4V3.6L8 1.8Z" />
      <path d="m5.9 7.9 1.5 1.5 2.7-2.9" />
    </Svg>
  );
}

export function ChatsIcon() {
  return (
    <Svg>
      <path d="M2.2 3.8h8.2c.7 0 1.2.5 1.2 1.2v4.4c0 .7-.5 1.2-1.2 1.2H6.8l-2.6 2.2v-2.2H3.4c-.7 0-1.2-.5-1.2-1.2V5c0-.7.5-1.2 1.2-1.2Z" />
      <path d="M13.8 6.2v4.6c0 .9-.5 1.4-1.4 1.4h-.3" />
    </Svg>
  );
}

export function PlusIcon() {
  return (
    <Svg>
      <path d="M8 3v10M3 8h10" />
    </Svg>
  );
}

export function ActivityIcon() {
  return (
    <Svg>
      <path d="M1.8 8h2.7l1.9-4.6L9.6 12l1.9-4h2.7" />
    </Svg>
  );
}
