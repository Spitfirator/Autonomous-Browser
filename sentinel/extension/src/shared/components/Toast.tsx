import { useEffect, useState } from 'react';

export interface ToastMsg {
  text: string;
  kind: 'ok' | 'err';
}

export function useToast(): [ToastMsg | null, (t: ToastMsg) => void] {
  const [toast, setToast] = useState<ToastMsg | null>(null);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(timer);
  }, [toast]);
  return [toast, setToast];
}

export function Toast({ toast }: { toast: ToastMsg | null }) {
  if (!toast) return null;
  return <div className={`toast ${toast.kind}`}>{toast.text}</div>;
}
