import Popover from '@cloudscape-design/components/popover';
import Box from '@cloudscape-design/components/box';

export const GLOSSARY = {
  KEK: {
    title: 'Root key-encryption key (Root KEK)',
    body: 'The 256-bit key at the top of the hierarchy. It lives only in the KMS process (loaded from a sealed secret) and is used for one thing: wrapping CMK key material. It never touches your data or your data keys.',
  },
  CMK: {
    title: 'Customer managed key (CMK)',
    body: 'Your tenant\'s key in the KMS. Its material is stored wrapped under the Root KEK. It wraps data keys with AES Key Wrap (RFC 3394) or RSA-2048-OAEP. Rotating it creates a new version; old versions stay available for decryption.',
  },
  DEK: {
    title: 'Data encryption key (DEK)',
    body: 'A fresh 256-bit AES key generated for every object. Your browser uses it once to encrypt the file with AES-256-GCM, then wipes it. Only its wrapped form is stored next to the ciphertext.',
  },
  WRAPPED: {
    title: 'Wrapped data key (ciphertext blob)',
    body: 'The DEK encrypted under a CMK version, plus an HMAC that binds it to the encryption context. It is useless without the KMS, so it can be stored safely next to the data.',
  },
  CONTEXT: {
    title: 'Encryption context',
    body: 'Non-secret {tenant, bucket, object} labels. They are authenticated as AES-GCM additional data and bound into the wrapped key, so ciphertext or keys moved to another object fail to decrypt.',
  },
  GCM: {
    title: 'AES-256-GCM',
    body: 'Authenticated encryption: it hides the data and produces a 16-byte tag. Changing a single bit of the ciphertext, IV or context makes decryption fail instead of returning garbage.',
  },
  ZEROIZE: {
    title: 'Zeroization',
    body: 'Overwriting key bytes with zeros as soon as they are no longer needed. In the browser the DEK is imported as a non-extractable CryptoKey and the raw bytes are filled with 0x00. Garbage-collected runtimes make this best-effort.',
  },
  SHRED: {
    title: 'Crypto-shredding',
    body: 'Deleting a CMK destroys its key material. Every object encrypted under it becomes permanently unreadable, even though the ciphertext still exists.',
  },
} as const;

export type GlossaryKey = keyof typeof GLOSSARY;

export default function Term({ k, children }: { k: GlossaryKey; children?: React.ReactNode }) {
  const g = GLOSSARY[k];
  return (
    <Popover header={g.title} content={<Box variant="p">{g.body}</Box>} size="medium" triggerType="text" dismissButton={false}>
      {children ?? k}
    </Popover>
  );
}
