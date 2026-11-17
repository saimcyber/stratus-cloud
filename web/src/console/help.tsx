import Box from '@cloudscape-design/components/box';
import Header from '@cloudscape-design/components/header';
import HelpPanel from '@cloudscape-design/components/help-panel';
import type { TutorialPanelProps } from '@cloudscape-design/components/tutorial-panel';
import type { ReactNode } from 'react';

export type HelpTopic = 'home' | 'keys' | 'key' | 'buckets' | 'bucket' | 'activity' | 'lab' | 'tradeoffs';

const TOPICS: Record<HelpTopic, { title: string; body: ReactNode }> = {
  home: {
    title: 'Stratus Cloud',
    body: (
      <>
        <p>Stratus is a working model of envelope encryption, the way cloud key management services protect stored objects.</p>
        <h3>Three parties</h3>
        <ul>
          <li><strong>Your browser</strong> encrypts and decrypts files.</li>
          <li><strong>Stratus KMS</strong> holds the key hierarchy and hands out data keys.</li>
          <li><strong>Stratus Vault</strong> stores ciphertext and wrapped keys, nothing else.</li>
        </ul>
        <p>Start the guided tutorial from the top bar to encrypt your first file.</p>
      </>
    ),
  },
  keys: {
    title: 'Customer managed keys',
    body: (
      <>
        <p>A CMK is a key that never leaves the KMS. It wraps the per-object data keys your browser uses.</p>
        <h3>Wrapping algorithms</h3>
        <ul>
          <li><strong>AES-KW</strong>: AES Key Wrap (RFC 3394) with a 256-bit key. Fast, symmetric.</li>
          <li><strong>RSA-2048-OAEP</strong>: asymmetric wrapping with SHA-256. Slower, but the public half can be shared.</li>
        </ul>
        <h3>Access</h3>
        <p>Each key has its own access list. <em>Users</em> can encrypt and decrypt; <em>admins</em> can also rotate, disable, delete and change access. Keys from another tenant are never visible.</p>
      </>
    ),
  },
  key: {
    title: 'Key lifecycle',
    body: (
      <>
        <h3>Rotation</h3>
        <p>Rotating creates a new key version and makes it primary. New data keys are wrapped under it. Older versions stay available for decryption only, so nothing breaks.</p>
        <h3>Re-wrap</h3>
        <p>After rotating, the Vault can re-wrap existing objects: the KMS unwraps each data key with the old version and wraps it with the new one. The file itself is never re-encrypted.</p>
        <h3>Revocation</h3>
        <ul>
          <li><strong>Remove access</strong>: that user's requests are denied immediately.</li>
          <li><strong>Disable</strong>: all use is blocked, reversibly.</li>
          <li><strong>Schedule deletion</strong>: after the waiting period the key material is destroyed and every object under it is crypto-shredded.</li>
        </ul>
      </>
    ),
  },
  buckets: {
    title: 'Vault buckets',
    body: (
      <>
        <p>Buckets belong to your tenant. Every object is encrypted in your browser before upload using a data key from the KMS.</p>
        <p>The Vault is treated as <strong>untrusted</strong>: it has no KMS credentials and could be fully compromised without exposing a single file.</p>
      </>
    ),
  },
  bucket: {
    title: 'Objects',
    body: (
      <>
        <h3>Upload</h3>
        <p>Your browser requests a fresh data key, encrypts the file with AES-256-GCM, wipes the key, and sends only ciphertext plus the wrapped key.</p>
        <h3>Raw view</h3>
        <p>Shows exactly what the storage server holds for an object. Try it after an upload.</p>
        <h3>Needs re-wrap</h3>
        <p>Objects whose data key is wrapped under an older CMK version. They still decrypt; re-wrapping moves them to the current version without touching the payload.</p>
      </>
    ),
  },
  activity: {
    title: 'Activity',
    body: (
      <>
        <p>Every KMS and Vault call is recorded with who made it and whether it succeeded, including denied attempts.</p>
        <p>Events never contain keys, plaintext or ciphertext.</p>
      </>
    ),
  },
  lab: {
    title: 'Security lab',
    body: (
      <>
        <p>Each card runs a real attack against the live services and shows the defence that stops it.</p>
        <p>The lab signs in as other demo personas behind the scenes; your own session is not changed.</p>
      </>
    ),
  },
  tradeoffs: {
    title: 'Security vs. usability',
    body: (
      <>
        <p>Benchmarks run in your browser against the live services.</p>
        <p>They show what each security choice costs in latency and storage, and why envelope encryption keeps the KMS fast no matter how large a file is.</p>
      </>
    ),
  },
};

export function helpPanel(topic: HelpTopic) {
  const t = TOPICS[topic];
  return (
    <HelpPanel header={<Header variant="h2">{t.title}</Header>}>
      <Box variant="div">{t.body}</Box>
    </HelpPanel>
  );
}

// --------------------------------------------------------------------------- guided walkthrough
export const TUTORIAL: TutorialPanelProps.Tutorial = {
  title: 'Encrypt your first file',
  description: (
    <>
      <Box variant="p">A five-minute walk through the whole envelope: find your key, encrypt a file in the browser, inspect what the server stored, then rotate the key.</Box>
    </>
  ),
  completed: false,
  completedScreenDescription: 'You encrypted a file without the cloud ever seeing it, then rotated the key without re-encrypting anything.',
  tasks: [
    {
      title: 'Meet your key',
      steps: [
        {
          title: 'Open the key list',
          content: 'Choose Customer managed keys in the side navigation. These are the keys your tenant owns in Stratus KMS.',
          hotspotId: 'nav-keys',
        },
        {
          title: 'Your CMK',
          content: 'alias/patient-records is an AES-256 key. Its material is wrapped under the Root KEK and never leaves the KMS. Open it to see its versions and access list.',
          hotspotId: 'keys-table',
        },
      ],
    },
    {
      title: 'Encrypt a file',
      steps: [
        {
          title: 'Open the Vault',
          content: 'Choose Buckets under Stratus Vault in the side navigation.',
          hotspotId: 'nav-buckets',
        },
        {
          title: 'Open a bucket',
          content: 'Open acme-patient-records.',
          hotspotId: 'bucket-link',
        },
        {
          title: 'Upload',
          content: 'Choose Upload and pick any small file (or use the sample text). Keep the Envelope Inspector on to watch each step: data key, zeroization, AES-GCM, upload.',
          hotspotId: 'upload-button',
        },
        {
          title: 'See what the server sees',
          content: 'Select your object and choose Raw view. That is everything the storage server holds: random-looking bytes and a wrapped key.',
          hotspotId: 'raw-view',
        },
      ],
    },
    {
      title: 'Rotate without re-encrypting',
      steps: [
        {
          title: 'Rotate the key',
          content: 'Open alias/patient-records and choose Actions → Rotate now. A new primary version is created.',
          hotspotId: 'key-actions',
        },
        {
          title: 'Re-wrap',
          content: 'Back in the bucket, objects show "Needs re-wrap". Choose Re-wrap: the KMS swaps each wrapped key to the new version. The ciphertext hash stays identical.',
          hotspotId: 'rewrap-button',
        },
      ],
    },
  ],
};

export const TUTORIAL_I18N: TutorialPanelProps.I18nStrings = {
  tutorialListTitle: 'Guided walkthrough',
  tutorialListDescription: 'Step-by-step tours of the console. Hotspots point at the controls you need.',
  tutorialListDownloadLinkText: 'Download',
  tutorialCompletedText: 'Completed',
  labelExitTutorial: 'Exit tutorial',
  learnMoreLinkText: 'Learn more',
  startTutorialButtonText: 'Start tutorial',
  restartTutorialButtonText: 'Restart tutorial',
  completionScreenTitle: 'Nicely done',
  feedbackLinkText: 'Feedback',
  dismissTutorialButtonText: 'Dismiss tutorial',
  taskTitle: (i, title) => `Task ${i + 1}: ${title}`,
  stepTitle: (i, title) => `Step ${i + 1}: ${title}`,
  labelTotalSteps: (n) => `Total steps: ${n}`,
  labelLearnMoreExternalIcon: 'Opens in a new tab',
  labelTutorialListDownloadLink: 'Download PDF version of this tutorial',
  labelLearnMoreLink: 'Learn more about this tutorial (opens new tab)',
};

export const ANNOTATION_I18N = {
  stepCounterText: (i: number, n: number) => `Step ${i + 1}/${n}`,
  taskTitle: (i: number, title: string) => `Task ${i + 1}: ${title}`,
  labelHotspot: (open: boolean, i: number, n: number) =>
    open ? `close annotation for step ${i + 1} of ${n}` : `open annotation for step ${i + 1} of ${n}`,
  nextButtonText: 'Next',
  previousButtonText: 'Previous',
  finishButtonText: 'Finish',
  labelDismissAnnotation: 'dismiss annotation',
};
