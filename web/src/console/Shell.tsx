import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom';
import AnnotationContext from '@cloudscape-design/components/annotation-context';
import AppLayout from '@cloudscape-design/components/app-layout';
import BreadcrumbGroup, { type BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';
import Flashbar from '@cloudscape-design/components/flashbar';
import Hotspot from '@cloudscape-design/components/hotspot';
import Link from '@cloudscape-design/components/link';
import SideNavigation from '@cloudscape-design/components/side-navigation';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import TutorialPanel, { type TutorialPanelProps } from '@cloudscape-design/components/tutorial-panel';
import { kms, type Persona } from '../lib/api';
import { initialTheme, setTheme, store, useSession, type ThemeMode } from '../lib/session';
import { ANNOTATION_I18N, helpPanel, TUTORIAL, TUTORIAL_I18N, type HelpTopic } from './help';

export interface PageMeta {
  help: HelpTopic;
  crumbs: BreadcrumbGroupProps.Item[];
}

interface ShellApi {
  setPage: (meta: PageMeta) => void;
  openHelp: (topic?: HelpTopic) => void;
  openTutorial: () => void;
}

const ShellContext = createContext<ShellApi | null>(null);

export function useShell() {
  const ctx = useContext(ShellContext);
  if (!ctx) throw new Error('useShell outside Shell');
  return ctx;
}

/** Register the current page's breadcrumbs and help topic. */
export function usePage(meta: PageMeta) {
  const { setPage } = useShell();
  const key = JSON.stringify(meta);
  useEffect(() => {
    setPage(meta);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, setPage]);
}

export function InfoLink({ topic }: { topic: HelpTopic }) {
  const { openHelp } = useShell();
  return (
    <Link variant="info" onFollow={() => openHelp(topic)}>
      Info
    </Link>
  );
}

function useNavLink() {
  const navigate = useNavigate();
  return (e: CustomEvent<{ href: string; external?: boolean }>) => {
    if (e.detail.external) return;
    e.preventDefault();
    navigate(e.detail.href);
  };
}

export default function Shell() {
  const { token, user, signOut, signInAs, flash, notify } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const follow = useNavLink();

  const [page, setPageState] = useState<PageMeta>({ help: 'home', crumbs: [] });
  const [toolsOpen, setToolsOpen] = useState(false);
  const [toolsMode, setToolsMode] = useState<'help' | 'tutorial'>('help');
  const [helpTopic, setHelpTopic] = useState<HelpTopic>('home');
  const [navOpen, setNavOpen] = useState(true);
  const [theme, setThemeState] = useState<ThemeMode>(initialTheme);
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [tutorial, setTutorial] = useState<TutorialPanelProps.Tutorial | null>(null);
  const [tutorialDone, setTutorialDone] = useState(() => store.get('stratus.tutorialDone', 'local') === '1');

  useEffect(() => setTheme(theme), [theme]);
  useEffect(() => {
    kms.personas().then(setPersonas).catch(() => setPersonas([]));
  }, []);
  useEffect(() => {
    const onUnauthorized = () => signOut();
    window.addEventListener('stratus:unauthorized', onUnauthorized);
    return () => window.removeEventListener('stratus:unauthorized', onUnauthorized);
  }, [signOut]);

  const setPage = useCallback((meta: PageMeta) => {
    setPageState(meta);
    setHelpTopic(meta.help);
  }, []);
  const openHelp = useCallback((topic?: HelpTopic) => {
    if (topic) setHelpTopic(topic);
    setToolsMode('help');
    setToolsOpen(true);
  }, []);
  const openTutorial = useCallback(() => {
    setToolsMode('tutorial');
    setToolsOpen(true);
  }, []);
  const api = useMemo(() => ({ setPage, openHelp, openTutorial }), [setPage, openHelp, openTutorial]);

  if (!token || !user) return <Navigate to="/console/signin" replace state={{ from: location.pathname }} />;

  const tutorials = [{ ...TUTORIAL, completed: tutorialDone }];
  const activeHref = '/' + location.pathname.split('/').slice(1, 4).join('/');

  return (
    <ShellContext.Provider value={api}>
      <AnnotationContext
        currentTutorial={tutorial}
        onStartTutorial={(e) => {
          setTutorial(e.detail.tutorial);
          setToolsOpen(true);
        }}
        onExitTutorial={() => setTutorial(null)}
        onFinish={() => {
          setTutorial(null);
          setTutorialDone(true);
          store.set('stratus.tutorialDone', '1', 'local');
          notify({ type: 'success', content: 'Tutorial complete. You have seen the whole envelope.' });
        }}
        i18nStrings={ANNOTATION_I18N}
      >
        <div id="stratus-top-nav" style={{ position: 'sticky', top: 0, zIndex: 1002 }}>
          <TopNavigation
            identity={{
              href: '/console',
              logo: { src: '/wordmark.svg', alt: 'Stratus Cloud console' },
              onFollow: (e) => {
                e.preventDefault();
                navigate('/console');
              },
            }}
            utilities={[
              {
                type: 'button',
                text: 'Walkthrough',
                iconName: 'suggestions',
                onClick: openTutorial,
              },
              {
                type: 'menu-dropdown',
                text: 'pk-north-1',
                description: 'Region',
                items: [
                  { id: 'pk', text: 'Asia Pacific (Islamabad)', secondaryText: 'pk-north-1 · current' },
                  { id: 'eu', text: 'Europe (Frankfurt)', secondaryText: 'eu-central-1 · coming soon', disabled: true },
                ],
              },
              {
                type: 'button',
                text: theme === 'dark' ? 'Light mode' : 'Dark mode',
                onClick: () => setThemeState(theme === 'dark' ? 'light' : 'dark'),
              },
              {
                type: 'menu-dropdown',
                text: user.display_name,
                description: `${user.tenant_name} · ${user.role}`,
                iconName: 'user-profile',
                items: [
                  {
                    id: 'switch',
                    text: 'Switch demo persona',
                    items: personas
                      .filter((p) => p.username !== user.username)
                      .map((p) => ({ id: `as:${p.username}`, text: `${p.display_name} · ${p.tenant_name}` })),
                  },
                  { id: 'home', text: 'Stratus home page', href: '/' },
                  { id: 'signout', text: 'Sign out' },
                ],
                onItemClick: async (e) => {
                  const id = e.detail.id;
                  if (id === 'signout') {
                    signOut();
                    navigate('/console/signin');
                  } else if (id === 'home') {
                    e.preventDefault();
                    navigate('/');
                  } else if (id.startsWith('as:')) {
                    await signInAs(id.slice(3));
                    navigate('/console');
                  }
                },
              },
            ]}
          />
        </div>
        <AppLayout
          headerSelector="#stratus-top-nav"
          navigationOpen={navOpen}
          onNavigationChange={(e) => setNavOpen(e.detail.open)}
          navigation={
            <SideNavigation
              header={{ text: user.tenant_name, href: '/console' }}
              activeHref={activeHref}
              onFollow={follow}
              items={[
                { type: 'link', text: 'Dashboard', href: '/console' },
                {
                  type: 'section',
                  text: 'Stratus KMS',
                  items: [
                    {
                      type: 'link',
                      text: 'Customer managed keys',
                      href: '/console/kms/keys',
                      info: <Hotspot hotspotId="nav-keys" />,
                    },
                  ],
                },
                {
                  type: 'section',
                  text: 'Stratus Vault',
                  items: [
                    { type: 'link', text: 'Buckets', href: '/console/vault/buckets', info: <Hotspot hotspotId="nav-buckets" /> },
                  ],
                },
                {
                  type: 'section',
                  text: 'Security',
                  items: [
                    { type: 'link', text: 'Activity', href: '/console/activity' },
                    { type: 'link', text: 'Security lab', href: '/console/lab' },
                    { type: 'link', text: 'Trade-offs', href: '/console/tradeoffs' },
                  ],
                },
                { type: 'divider' },
                { type: 'link', text: 'Stratus home', href: '/' },
              ]}
            />
          }
          breadcrumbs={
            <BreadcrumbGroup
              items={[{ text: 'Stratus', href: '/console' }, ...page.crumbs]}
              onFollow={follow}
              ariaLabel="Breadcrumbs"
            />
          }
          notifications={<Flashbar items={flash} stackItems={flash.length > 2} />}
          toolsOpen={toolsOpen}
          onToolsChange={(e) => setToolsOpen(e.detail.open)}
          tools={
            toolsMode === 'tutorial' ? (
              <TutorialPanel tutorials={tutorials} i18nStrings={TUTORIAL_I18N} />
            ) : (
              helpPanel(helpTopic)
            )
          }
          content={<Outlet />}
          ariaLabels={{
            navigation: 'Side navigation',
            navigationClose: 'Close side navigation',
            navigationToggle: 'Open side navigation',
            tools: 'Help panel',
            toolsClose: 'Close help panel',
            toolsToggle: 'Open help panel',
            notifications: 'Notifications',
          }}
        />
      </AnnotationContext>
    </ShellContext.Provider>
  );
}

export function Hot({ id, children, side = 'right' }: { id: string; children: ReactNode; side?: 'left' | 'right' }) {
  return (
    <Hotspot hotspotId={id} side={side}>
      {children}
    </Hotspot>
  );
}
