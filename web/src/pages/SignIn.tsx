import { useEffect, useState } from 'react';
import { Link as RouterLink, useLocation, useNavigate } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import { kms, type Persona } from '../lib/api';
import { errorText, initialTheme, setTheme, useSession } from '../lib/session';
import './signin.css';

const BLURB: Record<string, string> = {
  alice: 'Key admin. Creates, rotates and revokes keys; uploads patient files.',
  bob: 'Developer. Can encrypt and decrypt with keys he is granted, nothing more.',
  mallory: 'Another tenant entirely. Use her to try breaking in.',
};

export default function SignIn() {
  const { signInAs, signInWithPassword, token } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? '/console';

  const [personas, setPersonas] = useState<Persona[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => setTheme(initialTheme()), []);
  useEffect(() => {
    if (token) navigate(from, { replace: true });
  }, [token, from, navigate]);
  useEffect(() => {
    let cancelled = false;
    const load = (attempt: number) =>
      kms
        .personas()
        .then((p) => !cancelled && setPersonas(p))
        .catch((e) => {
          if (cancelled) return;
          if (attempt < 6) setTimeout(() => load(attempt + 1), 4000);
          else setError(errorText(e));
        });
    load(0);
    return () => {
      cancelled = true;
    };
  }, []);

  const go = async (fn: () => Promise<void>, id: string) => {
    setBusy(id);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="si-page">
      <aside className="si-brand">
        <RouterLink to="/" className="si-logo">
          <img src="/favicon.svg" alt="" width={28} height={28} />
          <span>Stratus</span>
        </RouterLink>
        <div className="si-brand-copy">
          <h1>
            Sign in to the <em>console</em>
          </h1>
          <p>Every file is sealed in your browser before it reaches our servers.</p>
        </div>
        <ol className="si-layers" aria-label="Key hierarchy">
          <li>
            <span>Root KEK</span>
            <small>KMS only</small>
          </li>
          <li>
            <span>Customer managed key</span>
            <small>per tenant</small>
          </li>
          <li>
            <span>Data key</span>
            <small>per file, then wiped</small>
          </li>
        </ol>
      </aside>

      <main className="si-main">
        <div className="si-card">
          <SpaceBetween size="l">
            <Box variant="h2" padding="n">
              Choose a demo identity
            </Box>
            {error && (
              <Alert type="error" header="Sign-in problem">
                {error}
              </Alert>
            )}
            {!personas && !error && (
              <Box color="text-body-secondary">
                <Spinner /> Waking the KMS. Free hosting can take up to a minute.
              </Box>
            )}
            <div className="si-personas">
              {personas?.map((p) => (
                <button
                  key={p.username}
                  className={`si-persona ${p.username === 'mallory' ? 'attacker' : ''}`}
                  disabled={!!busy}
                  onClick={() => go(() => signInAs(p.username), p.username)}
                >
                  <span className="si-avatar" aria-hidden>
                    {p.display_name[0]}
                  </span>
                  <span className="si-who">
                    <strong>{p.display_name}</strong>
                    <span>
                      {p.tenant_name} · {p.role}
                    </span>
                    <small>{BLURB[p.username] ?? ''}</small>
                  </span>
                  {busy === p.username ? <Spinner /> : <span className="si-arrow">→</span>}
                </button>
              ))}
            </div>
            <ExpandableSection headerText="Sign in with a password">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  go(() => signInWithPassword(username, password), 'password');
                }}
              >
                <Form
                  actions={
                    <Button variant="primary" loading={busy === 'password'} formAction="submit">
                      Sign in
                    </Button>
                  }
                >
                  <SpaceBetween size="m">
                    <FormField label="Username">
                      <Input value={username} onChange={(e) => setUsername(e.detail.value)} autoComplete="username" />
                    </FormField>
                    <FormField label="Password" description="Demo password: stratus-demo. Five wrong attempts lock the account for a minute.">
                      <Input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.detail.value)}
                        autoComplete="current-password"
                      />
                    </FormField>
                  </SpaceBetween>
                </Form>
              </form>
            </ExpandableSection>
          </SpaceBetween>
        </div>
      </main>
    </div>
  );
}
