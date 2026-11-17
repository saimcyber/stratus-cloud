import { StrictMode, lazy, Suspense } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import '@cloudscape-design/global-styles/index.css';
import './console/console.css';
import Landing from './landing/Landing';
import { SessionProvider } from './lib/session';

const Shell = lazy(() => import('./console/Shell'));
const SignIn = lazy(() => import('./pages/SignIn'));
const Home = lazy(() => import('./pages/Home'));
const Keys = lazy(() => import('./pages/Keys'));
const KeyDetail = lazy(() => import('./pages/KeyDetail'));
const Buckets = lazy(() => import('./pages/Buckets'));
const BucketDetail = lazy(() => import('./pages/BucketDetail'));
const Activity = lazy(() => import('./pages/Activity'));
const Lab = lazy(() => import('./pages/Lab'));
const Tradeoffs = lazy(() => import('./pages/Tradeoffs'));

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SessionProvider>
      <BrowserRouter>
        <Suspense fallback={null}>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/console/signin" element={<SignIn />} />
            <Route path="/console" element={<Shell />}>
              <Route index element={<Home />} />
              <Route path="kms/keys" element={<Keys />} />
              <Route path="kms/keys/:keyId" element={<KeyDetail />} />
              <Route path="vault/buckets" element={<Buckets />} />
              <Route path="vault/buckets/:bucket" element={<BucketDetail />} />
              <Route path="activity" element={<Activity />} />
              <Route path="lab" element={<Lab />} />
              <Route path="tradeoffs" element={<Tradeoffs />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </SessionProvider>
  </StrictMode>,
);
