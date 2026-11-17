import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import type { FlashbarProps } from '@cloudscape-design/components/flashbar';
import { kms, type User } from './api';

// --------------------------------------------------------------------------- safe storage
export const store = {
  get(key: string, kind: 'session' | 'local' = 'session'): string | null {
    try {
      return (kind === 'session' ? sessionStorage : localStorage).getItem(key);
    } catch {
      return null;
    }
  },
  set(key: string, value: string | null, kind: 'session' | 'local' = 'session') {
    try {
      const s = kind === 'session' ? sessionStorage : localStorage;
      if (value === null) s.removeItem(key);
      else s.setItem(key, value);
    } catch {
      /* storage unavailable: fall back to in-memory only */
    }
  },
};

// --------------------------------------------------------------------------- theme
export type ThemeMode = 'light' | 'dark';

export function initialTheme(): ThemeMode {
  const saved = store.get('stratus.theme', 'local');
  if (saved === 'light' || saved === 'dark') return saved;
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

export function setTheme(mode: ThemeMode) {
  applyMode(mode === 'dark' ? Mode.Dark : Mode.Light);
  store.set('stratus.theme', mode, 'local');
}

// --------------------------------------------------------------------------- session
interface SessionValue {
  token: string | null;
  user: User | null;
  signInAs: (username: string) => Promise<void>;
  signInWithPassword: (username: string, password: string) => Promise<void>;
  signOut: () => void;
  notify: (item: Omit<FlashbarProps.MessageDefinition, 'id' | 'onDismiss' | 'dismissible'>) => void;
  flash: FlashbarProps.MessageDefinition[];
}

const SessionContext = createContext<SessionValue | null>(null);

function loadUser(): User | null {
  const raw = store.get('stratus.user');
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => store.get('stratus.token'));
  const [user, setUser] = useState<User | null>(loadUser);
  const [flash, setFlash] = useState<FlashbarProps.MessageDefinition[]>([]);

  const accept = useCallback((t: string, u: User) => {
    store.set('stratus.token', t);
    store.set('stratus.user', JSON.stringify(u));
    setToken(t);
    setUser(u);
    setFlash([]);
  }, []);

  const signInAs = useCallback(async (username: string) => {
    const r = await kms.demoLogin(username);
    accept(r.token, r.user);
  }, [accept]);

  const signInWithPassword = useCallback(async (username: string, password: string) => {
    const r = await kms.login(username, password);
    accept(r.token, r.user);
  }, [accept]);

  const signOut = useCallback(() => {
    store.set('stratus.token', null);
    store.set('stratus.user', null);
    setToken(null);
    setUser(null);
  }, []);

  const notify = useCallback<SessionValue['notify']>((item) => {
    const id = `${Date.now()}-${Math.random()}`;
    const dismiss = () => setFlash((f) => f.filter((x) => x.id !== id));
    setFlash((f) => [{ ...item, id, dismissible: true, onDismiss: dismiss }, ...f].slice(0, 3));
    if (item.type === 'success' || item.type === 'info') setTimeout(dismiss, 6000);
  }, []);

  const value = useMemo(
    () => ({ token, user, signInAs, signInWithPassword, signOut, notify, flash }),
    [token, user, signInAs, signInWithPassword, signOut, notify, flash],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession outside provider');
  return ctx;
}

/** Session that is guaranteed to be signed in (used inside the console shell). */
export function useAuthed() {
  const s = useSession();
  return { ...s, token: s.token as string, user: s.user as User };
}

export function errorText(e: unknown): string {
  if (e && typeof e === 'object' && 'code' in e && 'message' in e) {
    const err = e as { code: string; message: string };
    return `${err.code}: ${err.message}`;
  }
  return e instanceof Error ? e.message : String(e);
}
