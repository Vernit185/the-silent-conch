import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { discoverApi, describeError } from '@/services/api';
import type { ApiCatalog } from '@/types/api';
interface ApiState { catalog?: ApiCatalog | undefined; loading: boolean; error?: string | undefined; token: string; setToken: (token: string) => void; refresh: () => void; }
const Context = createContext<ApiState | undefined>(undefined);
export function ApiProvider({ children }: { children: ReactNode }) {
  const [catalog, setCatalog] = useState<ApiCatalog>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [token, setToken] = useState('');
  const controller = useRef<AbortController | undefined>(undefined);
  const refresh = useCallback(() => {
    controller.current?.abort();
    const next = new AbortController(); controller.current = next;
    setLoading(true); setError(undefined); setCatalog(undefined);
    discoverApi(next.signal).then(setCatalog).catch(e => { if (!next.signal.aborted) setError(describeError(e)); }).finally(() => { if (!next.signal.aborted) setLoading(false); });
  }, []);
  useEffect(() => { refresh(); return () => controller.current?.abort(); }, [refresh]);
  return <Context.Provider value={{ catalog, loading, error, token, setToken, refresh }}>{children}</Context.Provider>;
}
export function useApi() { const value = useContext(Context); if (!value) throw new Error('API provider is required.'); return value; }
