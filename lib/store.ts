import { kv } from "@vercel/kv";

export type RepoInstallation = {
  repoOwner: string;
  installationId: number;
  publicRepos: string[];
  privateRepos: string[];
};

const memoryStore = new Map<string, RepoInstallation>();
const hasKvConfig = Boolean(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);

function key(owner: string): string {
  return `installation:${owner.toLowerCase()}`;
}

export async function readInstallation(repoOwner: string): Promise<RepoInstallation | null> {
  const normalized = key(repoOwner);
  if (memoryStore.has(normalized)) {
    return memoryStore.get(normalized) ?? null;
  }

  if (!hasKvConfig) {
    return null;
  }

  try {
    const value = await kv.get<RepoInstallation>(normalized);
    if (value) {
      memoryStore.set(normalized, value);
    }
    return value ?? null;
  } catch {
    return null;
  }
}

export async function writeInstallation(record: RepoInstallation): Promise<void> {
  const normalized = key(record.repoOwner);
  memoryStore.set(normalized, record);

  if (!hasKvConfig) {
    return;
  }

  try {
    await kv.set(normalized, record);
  } catch {
    // Fall back to in-memory cache when KV is unavailable.
  }
}

export async function deleteInstallation(repoOwner: string): Promise<void> {
  const normalized = key(repoOwner);
  memoryStore.delete(normalized);

  if (!hasKvConfig) {
    return;
  }

  try {
    await kv.del(normalized);
  } catch {
    // Ignore external store errors in deletion paths.
  }
}
