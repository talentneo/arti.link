import { createHash, createPrivateKey, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";

import { SignJWT } from "jose";

import { type RepoInstallation, readInstallation, writeInstallation } from "./store";

type Installation = {
  id: number;
  account: {
    login: string;
  };
  updated_at: string;
};

type Repository = {
  full_name: string;
  private?: boolean;
  fork?: boolean;
};

type WorkflowRun = {
  id: number;
  event: string;
  workflow_id: number;
  check_suite_url: string;
  updated_at: string;
  repository: Repository;
};

type Artifact = {
  id: number;
  name: string;
  url: string;
  expired?: boolean;
};

type ArtifactListLink = {
  title: string;
  url: string;
  zipUrl: string;
};

type Link = {
  title: string;
  url: string;
  ext?: boolean;
};

const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_WEB_BASE = "https://github.com";

const WORKFLOW_EXAMPLES = [
  {
    workflowUrl: "https://github.com/oprypin/nightly.link/blob/master/.github/workflows/upload-test.yml",
    repoOwner: "oprypin",
    repoName: "nightly.link",
    workflow: "upload-test",
    branch: "master",
    artifact: "some-artifact"
  },
  {
    workflowUrl: "https://github.com/crystal-lang/crystal/blob/master/.github/workflows/win.yml",
    repoOwner: "crystal-lang",
    repoName: "crystal",
    workflow: "win",
    branch: "master",
    artifact: "crystal"
  },
  {
    workflowUrl: "https://github.com/quassel/quassel/blob/master/.github/workflows/main.yml",
    repoOwner: "quassel",
    repoName: "quassel",
    workflow: "main",
    branch: "master",
    artifact: "Windows"
  }
] as const;

class HttpError extends Error {
  status: number;
  headers: HeadersInit;

  constructor(status: number, message = "", headers: HeadersInit = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

class GitHubRequestError extends Error {
  status: number;
  body: string;

  constructor(status: number, body: string) {
    super(`GitHub API request failed with status ${status}`);
    this.status = status;
    this.body = body;
  }
}

class GitHubArtifactDownloadError extends Error {}

class GitHubLogsDownloadError extends Error {}

let appJwtCache: { token: string; expiresAt: number } | null = null;
let appSigningKey: KeyObject | null = null;
const installationTokenCache = new Map<number, { token: string; expiresAt: number }>();
let exampleCache:
  | {
      expiresAt: number;
      workflowUrl: string;
      runId: number;
      artifactId: number;
      checkSuiteId: number;
      repoOwner: string;
      repoName: string;
      workflow: string;
      branch: string;
      artifactName: string;
    }
  | null = null;

function getBaseUrl(): string {
  return process.env.URL ?? "https://arti-link/";
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new HttpError(500, `Missing required environment variable: ${name}`);
  }
  return value;
}

function getFallbackInstallationId(): number {
  const value = requiredEnv("FALLBACK_INSTALLATION_ID");
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(500, "FALLBACK_INSTALLATION_ID must be a number");
  }
  return parsed;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function absUrl(pathname: string): string {
  return new URL(pathname, getBaseUrl()).toString();
}

function encodePathSegment(value: string): string {
  return encodeURIComponent(value);
}

function appendQuery(url: string, key: string, value: string | null | undefined): string {
  if (!value) {
    return url;
  }
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
}

function appendHashToken(url: string, h: string | null | undefined): string {
  return appendQuery(url, "h", h);
}

function jsonContentType(headers: Headers): boolean {
  const value = headers.get("content-type") ?? "";
  return value.includes("application/json");
}

function isNotFoundStatus(status: number): boolean {
  return status === 401 || status === 404 || status === 451;
}

function statusText(status: number): string {
  const map = new Map<number, string>([
    [400, "Bad Request"],
    [401, "Unauthorized"],
    [403, "Forbidden"],
    [404, "Not Found"],
    [410, "Gone"],
    [500, "Internal Server Error"],
    [502, "Bad Gateway"],
    [503, "Service Unavailable"]
  ]);
  return map.get(status) ?? "Unknown Error";
}

function renderLayout({
  title,
  canonical,
  popup,
  body
}: {
  title?: string;
  canonical?: string;
  popup?: boolean;
  body: string;
}): string {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/style.css">
<link rel="icon" href="/logo.svg" type="image/svg+xml">
${canonical ? `<link rel="canonical" href="${escapeHtml(canonical)}">` : ""}
<title>arti-link${title ? ` | ${escapeHtml(title)}` : ""}</title>
</head>
<body>
${popup ? `<aside><p>arti-link is open source and free to use.</p></aside>` : ""}
<article>
${body}
</article>
</body>
</html>`;
}

function renderArtifactListPage({
  title,
  subtitle,
  messages,
  links
}: {
  title: string;
  subtitle: string;
  messages: string[];
  links: ArtifactListLink[];
}): string {
  const rows = links
    .map(
      (link) =>
        `<tr><th><a rel="nofollow" href="${escapeHtml(link.url)}">${escapeHtml(link.title)}</a></th><td><a rel="nofollow" href="${escapeHtml(link.zipUrl)}">${escapeHtml(link.zipUrl)}</a></td></tr>`
    )
    .join("\n");
  const notices = messages
    .map((message) => `<p class="absent">${escapeHtml(message)}</p>`)
    .join("\n");
  const artifactCount = links.length;
  const countLabel = `${artifactCount} artifact${artifactCount === 1 ? "" : "s"} available`;

  return `<h1><a href="/">arti-link</a></h1>
<h2>${escapeHtml(title)}</h2>
<h3>${escapeHtml(subtitle)}</h3>
<p class="lead">${escapeHtml(countLabel)}. Pick a named entry for the guided page, or use the direct <code>.zip</code> URL in the right column.</p>
${notices}
<p class="muted-note">These links always resolve from the latest matching run context, not a fixed historical file.</p>
<table>${rows}</table>`;
}

function renderLinkGroup({
  heading,
  links,
  ext
}: {
  heading: string;
  links: Link[];
  ext: boolean;
}): string {
  const rows = links
    .filter((link) => Boolean(link.ext) === ext)
    .map((link, index) => {
      const open = !ext && index === 0 ? "<b>" : "";
      const close = !ext && index === 0 ? "</b>" : "";
      const target = ext ? " target=\"_blank\"" : "";
      return `<li>${open}<a rel="nofollow" href="${escapeHtml(link.url)}"${target}>${escapeHtml(link.title)}</a>${close}</li>`;
    })
    .join("\n");
  return `<p>${escapeHtml(heading)}</p><ul>${rows}</ul>`;
}

function renderArtifactPage({
  title,
  subtitle,
  links
}: {
  title: string;
  subtitle: string;
  links: Link[];
}): string {
  return `<h1><a href="/">arti-link</a></h1>
<h2>${escapeHtml(title)}</h2>
<h3>${escapeHtml(subtitle)}</h3>
<p class="lead">Use these links in order: the first entries are stable and shareable, while lower entries are progressively more direct and short-lived.</p>
${renderLinkGroup({
  heading: "Artifact access links (from stable to direct):",
  links,
  ext: false
})}
${renderLinkGroup({ heading: "Related GitHub pages:", links, ext: true })}
<p class="muted-note">Tip: if you publish links externally, prefer the first stable URL rather than ephemeral links.</p>`;
}

function renderJobPage({
  title,
  subtitle,
  links
}: {
  title: string;
  subtitle: string;
  links: Link[];
}): string {
  return `<h1><a href="/">arti-link</a></h1>
<h2>${escapeHtml(title)}</h2>
<h3>${escapeHtml(subtitle)}</h3>
<p class="lead">This page provides portable access to raw job logs.</p>
${renderLinkGroup({ heading: "Job log access links:", links, ext: false })}
${renderLinkGroup({ heading: "Related GitHub pages:", links, ext: true })}
<p class="muted-note">Artifacts are attached to the parent run, so artifact downloads should use run/workflow routes.</p>`;
}

function renderErrorPage(status: number, message: string): string {
  const text = message.trim().length > 0 ? message : statusText(status);
  const content = escapeHtml(text)
    .replace(/&lt;(https?:\/\/[^&]+)&gt;/g, '<a rel="nofollow" href="$1">$1</a>')
    .split(/\n+/)
    .map((line) => `<p>${line}</p>`)
    .join("\n");

  return `<h1>Error ${status} - ${escapeHtml(statusText(status))}</h1>
<p class="lead">The request could not be completed with the current input or GitHub state.</p>
${content}
<p class="muted-note">If this is an expired artifact/log, trigger a new workflow run and use the latest generated links.</p>
<p><a href="/">Return to the home page</a></p>`;
}

function parseFullName(fullName: string): { owner: string; repo: string } {
  const [owner = "", repo = ""] = fullName.split("/");
  return { owner, repo };
}

function checkSuiteIdFromRun(run: WorkflowRun): number | null {
  const match = run.check_suite_url.match(/\/(\d+)$/);
  if (!match) {
    return null;
  }
  const parsed = Number.parseInt(match[1], 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function repoPassword(installation: RepoInstallation, repoName: string): string {
  const secret = requiredEnv("APP_SECRET");
  const digest = createHash("sha256")
    .update(`${installation.installationId}\n${installation.repoOwner}\n${repoName}\n${secret}`)
    .digest("hex");
  return digest.slice(0, 40);
}

function normalizeWorkflow(workflow: string): string {
  if (/^\d+$/.test(workflow)) {
    return workflow;
  }
  if (workflow.endsWith(".yml") || workflow.endsWith(".yaml")) {
    return workflow;
  }
  return `${workflow}.yml`;
}

function stripYml(workflow: string): string {
  return workflow.endsWith(".yml") ? workflow.slice(0, -4) : workflow;
}

function workflowPattern(repoOwner: string, repoName: string): string {
  return `^https://github.com/${escapeRegex(repoOwner)}/${escapeRegex(repoName)}/(blob|tree|raw|blame|commits)/.+/.github/workflows/[^/]+\\.ya?ml(#.*)?$`;
}

function workflowPlaceholder(repoOwner: string, repoName: string): string {
  return `https://github.com/${repoOwner}/${repoName}/blob/$branch/.github/workflows/$workflow.yml`;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function encodePossiblyEncodedSegment(value: string): string {
  try {
    return encodeURIComponent(decodeURIComponent(value));
  } catch {
    return encodeURIComponent(value);
  }
}

function githubRunLink(repoOwner: string, repoName: string, runId: number): string {
  return `${GITHUB_WEB_BASE}/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/actions/runs/${runId}#artifacts`;
}

function githubJobLink(repoOwner: string, repoName: string, jobId: number): string {
  return `${GITHUB_WEB_BASE}/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/runs/${jobId}`;
}

function githubActionsLink({
  repoOwner,
  repoName,
  event,
  branch,
  status
}: {
  repoOwner: string;
  repoName: string;
  event: string;
  branch: string;
  status: string;
}): string {
  const query = new URLSearchParams({ query: `event:${event} is:${status} branch:${branch}` });
  return `${GITHUB_WEB_BASE}/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/actions?${query.toString()}`;
}

function artifactGhDownloadLink({
  repoOwner,
  repoName,
  checkSuiteId,
  artifactId
}: {
  repoOwner: string;
  repoName: string;
  checkSuiteId: number;
  artifactId: number;
}): string {
  return `${GITHUB_WEB_BASE}/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/suites/${checkSuiteId}/artifacts/${artifactId}`;
}

function artifactApiLink(repoOwner: string, repoName: string, artifactId: number): string {
  return `${GITHUB_API_BASE}/repos/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/actions/artifacts/${artifactId}`;
}

function parseNextLink(linkHeader: string | null): string | null {
  if (!linkHeader) {
    return null;
  }

  for (const part of linkHeader.split(",")) {
    const match = part.match(/<([^>]+)>;\s*rel="next"/);
    if (match) {
      return match[1];
    }
  }
  return null;
}

async function githubFetch(
  pathOrUrl: string,
  {
    method,
    body,
    headers,
    redirect
  }: {
    method?: string;
    body?: BodyInit;
    headers?: HeadersInit;
    redirect?: RequestRedirect;
  } = {}
): Promise<Response> {
  const url = pathOrUrl.startsWith("http")
    ? pathOrUrl
    : `${GITHUB_API_BASE}/${pathOrUrl.replace(/^\//, "")}`;
  const mergedHeaders = new Headers(headers);
  mergedHeaders.set("User-Agent", "arti-link");
  if (!mergedHeaders.has("Accept")) {
    mergedHeaders.set("Accept", "application/vnd.github+json");
  }

  return fetch(url, {
    method: method ?? "GET",
    body,
    headers: mergedHeaders,
    cache: "no-store",
    redirect: redirect ?? "follow"
  });
}

async function throwIfGitHubError(response: Response): Promise<void> {
  if (response.ok) {
    return;
  }
  const body = await response.text();
  throw new GitHubRequestError(response.status, body);
}

function normalizePemInput(raw: string): string {
  let value = raw.trim();
  if (
    (value.startsWith("\"") && value.endsWith("\"")) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }

  value = value.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\r\n/g, "\n");

  if (!value.includes("BEGIN")) {
    try {
      const decoded = Buffer.from(value.replace(/\s+/g, ""), "base64").toString("utf8");
      if (decoded.includes("BEGIN") && decoded.includes("PRIVATE KEY")) {
        return decoded.trim();
      }
    } catch {
      // Keep original value and let parser fail with explicit error.
    }
  }

  return value.trim();
}

async function loadPrivateKeyPem(): Promise<string> {
  const inline = process.env.GITHUB_PEM;
  if (inline) {
    return normalizePemInput(inline);
  }

  const b64 = process.env.GITHUB_PEM_BASE64;
  if (b64) {
    return normalizePemInput(Buffer.from(b64, "base64").toString("utf8"));
  }

  const filename = process.env.GITHUB_PEM_FILENAME;
  if (filename) {
    return normalizePemInput(await readFile(filename, "utf8"));
  }

  throw new HttpError(
    500,
    "Missing GitHub app private key. Set GITHUB_PEM, GITHUB_PEM_BASE64, or GITHUB_PEM_FILENAME."
  );
}

async function getAppJwt(): Promise<string> {
  const now = Date.now();
  if (appJwtCache && now < appJwtCache.expiresAt) {
    return appJwtCache.token;
  }

  const appId = requiredEnv("GITHUB_APP_ID");
  if (!appSigningKey) {
    const pem = await loadPrivateKeyPem();
    try {
      // GitHub may emit either PKCS#1 (RSA PRIVATE KEY) or PKCS#8 (PRIVATE KEY).
      appSigningKey = createPrivateKey({ key: pem, format: "pem" });
    } catch {
      throw new HttpError(
        500,
        "Invalid GITHUB_PEM private key. Regenerate your GitHub App private key and verify PEM format."
      );
    }
  }

  const token = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt(Math.floor(now / 1000))
    .setExpirationTime("10m")
    .setIssuer(appId)
    .sign(appSigningKey);

  appJwtCache = {
    token,
    expiresAt: now + 9 * 60 * 1000
  };
  return token;
}

async function getInstallationToken(installationId: number): Promise<string | null> {
  const now = Date.now();
  const cached = installationTokenCache.get(installationId);
  if (cached && now < cached.expiresAt) {
    return cached.token;
  }

  const appJwt = await getAppJwt();
  const response = await githubFetch(`/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    body: JSON.stringify({ permissions: { actions: "read" } }),
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${appJwt}`
    }
  });

  if (response.status === 404) {
    return null;
  }

  if (response.status === 422) {
    const body = await response.text();
    if (body.includes("permissions requested are not granted to this installation")) {
      throw new HttpError(
        500,
        "GitHub App installation is missing repository permission 'Actions: Read-only'.\nUpdate GitHub App settings -> Repository permissions -> Actions = Read-only, reinstall the app, and update FALLBACK_INSTALLATION_ID."
      );
    }
    throw new GitHubRequestError(response.status, body);
  }

  await throwIfGitHubError(response);
  const payload = (await response.json()) as { token: string };
  installationTokenCache.set(installationId, {
    token: payload.token,
    expiresAt: now + 55 * 60 * 1000
  });
  return payload.token;
}

async function oauthExchangeCode(code: string): Promise<string> {
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: requiredEnv("GITHUB_CLIENT_ID"),
      client_secret: requiredEnv("GITHUB_CLIENT_SECRET"),
      code
    }),
    cache: "no-store"
  });

  await throwIfGitHubError(response);

  if (jsonContentType(response.headers)) {
    const body = (await response.json()) as
      | {
          access_token?: string;
          error?: string;
        }
      | undefined;

    if (body?.error === "bad_verification_code") {
      throw new HttpError(302, "", { Location: "/dashboard" });
    }

    if (!body?.access_token) {
      throw new HttpError(500, "OAuth response did not include an access token.");
    }

    return body.access_token;
  }

  const raw = await response.text();
  const params = new URLSearchParams(raw);
  if (params.get("error") === "bad_verification_code") {
    throw new HttpError(302, "", { Location: "/dashboard" });
  }
  const token = params.get("access_token");
  if (!token) {
    throw new HttpError(500, "OAuth response did not include an access token.");
  }
  return token;
}

async function getJsonList<T>({
  url,
  authorization,
  extract,
  maxItems
}: {
  url: string;
  authorization: string;
  extract: (payload: unknown) => T[];
  maxItems: number;
}): Promise<T[]> {
  const items: T[] = [];
  let nextUrl: string | null = url;

  while (nextUrl) {
    const response = await githubFetch(nextUrl, {
      headers: {
        Authorization: authorization
      }
    });

    await throwIfGitHubError(response);
    const payload = (await response.json()) as unknown;
    for (const item of extract(payload)) {
      items.push(item);
      if (items.length >= maxItems) {
        return items;
      }
    }

    nextUrl = parseNextLink(response.headers.get("link"));
  }

  return items;
}

async function userInstallations(userToken: string): Promise<Installation[]> {
  return getJsonList<Installation>({
    url: `${GITHUB_API_BASE}/user/installations?per_page=100`,
    authorization: `token ${userToken}`,
    maxItems: 500,
    extract: (payload) => {
      const data = payload as { installations?: Installation[] };
      return data.installations ?? [];
    }
  });
}

async function userInstallationRepos(installationId: number, userToken: string): Promise<Repository[]> {
  return getJsonList<Repository>({
    url: `${GITHUB_API_BASE}/user/installations/${installationId}/repositories?per_page=300`,
    authorization: `token ${userToken}`,
    maxItems: 300,
    extract: (payload) => {
      const data = payload as { repositories?: Repository[] };
      return data.repositories ?? [];
    }
  });
}

async function installationRepos(installationToken: string): Promise<Repository[]> {
  return getJsonList<Repository>({
    url: `${GITHUB_API_BASE}/installation/repositories?per_page=300`,
    authorization: `token ${installationToken}`,
    maxItems: 300,
    extract: (payload) => {
      const data = payload as { repositories?: Repository[] };
      return data.repositories ?? [];
    }
  });
}

async function installationById(installationId: number): Promise<Installation> {
  const appJwt = await getAppJwt();
  const response = await githubFetch(`/app/installations/${installationId}`, {
    headers: {
      Authorization: `Bearer ${appJwt}`
    }
  });
  await throwIfGitHubError(response);
  return (await response.json()) as Installation;
}

async function workflowRuns({
  repoOwner,
  repoName,
  workflow,
  branch,
  event,
  status,
  token
}: {
  repoOwner: string;
  repoName: string;
  workflow: string;
  branch: string;
  event: string;
  status: string;
  token: string;
}): Promise<WorkflowRun[]> {
  const params = new URLSearchParams({
    per_page: "1",
    branch,
    event,
    status
  });
  const response = await githubFetch(
    `/repos/${encodePathSegment(repoOwner.toLowerCase())}/${encodePathSegment(repoName.toLowerCase())}/actions/workflows/${encodePathSegment(workflow)}/runs?${params.toString()}`,
    {
      headers: {
        Authorization: `token ${token}`
      }
    }
  );

  if (!response.ok) {
    const body = await response.text();
    throw new GitHubRequestError(response.status, body);
  }

  const payload = (await response.json()) as { workflow_runs?: WorkflowRun[] };
  return payload.workflow_runs ?? [];
}

async function runArtifacts({
  repoOwner,
  repoName,
  runId,
  token
}: {
  repoOwner: string;
  repoName: string;
  runId: number;
  token: string;
}): Promise<Artifact[]> {
  const response = await githubFetch(
    `/repos/${encodePathSegment(repoOwner.toLowerCase())}/${encodePathSegment(repoName.toLowerCase())}/actions/runs/${runId}/artifacts?per_page=100`,
    {
      headers: {
        Authorization: `token ${token}`
      }
    }
  );

  if (!response.ok) {
    const body = await response.text();
    throw new GitHubRequestError(response.status, body);
  }

  const payload = (await response.json()) as { artifacts?: Artifact[] };
  return payload.artifacts ?? [];
}

async function artifactZipLocation({
  repoOwner,
  repoName,
  artifactId,
  token
}: {
  repoOwner: string;
  repoName: string;
  artifactId: number;
  token: string;
}): Promise<string> {
  const response = await githubFetch(
    `/repos/${encodePathSegment(repoOwner.toLowerCase())}/${encodePathSegment(repoName.toLowerCase())}/actions/artifacts/${artifactId}/zip`,
    {
      headers: {
        Authorization: `token ${token}`
      },
      redirect: "manual"
    }
  );

  if (
    response.status === 410 ||
    (response.status === 500 && (await response.clone().text()).includes("Failed to generate URL to download artifact"))
  ) {
    throw new GitHubArtifactDownloadError();
  }

  if (!response.ok && response.status !== 302) {
    const body = await response.text();
    throw new GitHubRequestError(response.status, body);
  }

  const location = response.headers.get("location");
  if (!location) {
    throw new HttpError(502, "GitHub did not return a temporary download URL.");
  }

  return location;
}

async function jobLogsLocation({
  repoOwner,
  repoName,
  jobId,
  token
}: {
  repoOwner: string;
  repoName: string;
  jobId: number;
  token: string;
}): Promise<string> {
  const response = await githubFetch(
    `/repos/${encodePathSegment(repoOwner.toLowerCase())}/${encodePathSegment(repoName.toLowerCase())}/actions/jobs/${jobId}/logs`,
    {
      headers: {
        Authorization: `token ${token}`
      },
      redirect: "manual"
    }
  );

  if (response.status === 410) {
    throw new GitHubLogsDownloadError();
  }

  if (!response.ok && response.status !== 302) {
    const body = await response.text();
    throw new GitHubRequestError(response.status, body);
  }

  const location = response.headers.get("location");
  if (!location) {
    throw new HttpError(502, "GitHub did not return a temporary logs URL.");
  }

  return location;
}

async function refreshInstallationForUser(
  installation: Installation,
  userToken: string
): Promise<RepoInstallation> {
  const repos = await userInstallationRepos(installation.id, userToken);
  const publicRepos: string[] = [];
  const privateRepos: string[] = [];

  for (const repo of repos) {
    const { owner, repo: name } = parseFullName(repo.full_name);
    if (owner !== installation.account.login) {
      continue;
    }

    if (repo.private) {
      privateRepos.push(name);
    } else {
      publicRepos.push(name);
    }
  }

  const result: RepoInstallation = {
    repoOwner: installation.account.login,
    installationId: installation.id,
    publicRepos,
    privateRepos
  };

  await writeInstallation(result);
  return result;
}

async function refreshInstallationByApp(installationId: number): Promise<RepoInstallation> {
  const installation = await installationById(installationId);
  const token = await getInstallationToken(installation.id);
  if (!token) {
    throw new HttpError(404, `Installation #${installationId} was not found.`);
  }

  const repos = await installationRepos(token);
  const publicRepos: string[] = [];
  const privateRepos: string[] = [];

  for (const repo of repos) {
    const { owner, repo: name } = parseFullName(repo.full_name);
    if (owner !== installation.account.login) {
      continue;
    }

    if (repo.private) {
      privateRepos.push(name);
    } else {
      publicRepos.push(name);
    }
  }

  const result: RepoInstallation = {
    repoOwner: installation.account.login,
    installationId,
    publicRepos,
    privateRepos
  };

  await writeInstallation(result);
  return result;
}

async function verifiedToken(
  repoOwner: string,
  repoName: string,
  h: string | null
): Promise<{ token: string; h: string | null }> {
  const installation = await readInstallation(repoOwner);
  if (installation) {
    const isPublic = installation.publicRepos.some((name) => name.toLowerCase() === repoName.toLowerCase());

    let verifiedHash: string | null = null;
    if (!isPublic) {
      const privateMatch = installation.privateRepos.includes(repoName);
      if (privateMatch && h) {
        const expected = repoPassword(installation, repoName);
        if (h === expected) {
          verifiedHash = h;
        }
      }

      if (!verifiedHash) {
        throw new HttpError(
          404,
          `Repository not found: <https://github.com/${repoOwner}/${repoName}>\nIf this is your private repository, access it by authorizing from the home page.`
        );
      }
    }

    const token = await getInstallationToken(installation.installationId);
    if (token) {
      return { token, h: verifiedHash };
    }
  }

  const fallbackToken = await getInstallationToken(getFallbackInstallationId());
  if (!fallbackToken) {
    throw new HttpError(500, "Fallback installation token is not available.");
  }
  return { token: fallbackToken, h: null };
}

async function latestRun({
  repoOwner,
  repoName,
  workflow,
  branch,
  status,
  token
}: {
  repoOwner: string;
  repoName: string;
  workflow: string;
  branch: string;
  status: string;
  token: string;
}): Promise<WorkflowRun> {
  const events = ["push", "schedule"] as const;
  const promises = events.map((event) =>
    workflowRuns({
      repoOwner,
      repoName,
      workflow,
      branch,
      event,
      status,
      token
    }).catch((error: unknown) => {
      if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
        throw new HttpError(
          404,
          `Repository '${repoOwner}/${repoName}' or workflow '${workflow}' not found.\nCheck on GitHub: <https://github.com/${repoOwner}/${repoName}/tree/${branch}/.github/workflows>`
        );
      }
      throw error;
    })
  );

  const runs = (await Promise.all(promises)).flatMap((value) => value.slice(0, 1));
  if (runs.length === 0) {
    throw new HttpError(
      404,
      `No successful runs found for workflow '${workflow}' and branch '${branch}'.\nCheck on GitHub: <${githubActionsLink({
        repoOwner,
        repoName,
        event: "push",
        branch,
        status
      })}>`
    );
  }

  return runs.reduce((latest, current) => {
    if (new Date(current.updated_at).getTime() > new Date(latest.updated_at).getTime()) {
      return current;
    }
    return latest;
  });
}

function mapGitHubPath(pathname: string, direct: boolean): string | null {
  let match = pathname.match(
    /^\/([^/]+)\/([^/]+)\/(blob|tree|raw|blame|commits)\/(.+)\/\.github\/workflows\/([^/]+\.ya?ml)$/
  );
  if (match) {
    const [, repoOwner, repoName, , branch, workflowFile] = match;
    const workflow = workflowFile.replace(/\.ya?ml$/, "");
    return `/${encodePossiblyEncodedSegment(repoOwner)}/${encodePossiblyEncodedSegment(repoName)}/workflows/${encodePossiblyEncodedSegment(
      workflow
    )}/${encodePossiblyEncodedSegment(branch)}?preview`;
  }

  match = pathname.match(/^\/([^/]+)\/([^/]+)\/actions\/runs\/(\d+)$/);
  if (match) {
    const [, repoOwner, repoName, runId] = match;
    return `/${encodePossiblyEncodedSegment(repoOwner)}/${encodePossiblyEncodedSegment(repoName)}/actions/runs/${runId}`;
  }

  match = pathname.match(/^\/([^/]+)\/([^/]+)\/runs\/(\d+)$/);
  if (match) {
    const [, repoOwner, repoName, jobId] = match;
    return `/${encodePossiblyEncodedSegment(repoOwner)}/${encodePossiblyEncodedSegment(repoName)}/runs/${jobId}`;
  }

  match = pathname.match(/^\/([^/]+)\/([^/]+)\/suites\/(\d+)\/artifacts\/(\d+)$/);
  if (match) {
    const [, repoOwner, repoName, , artifactId] = match;
    return `/${encodePossiblyEncodedSegment(repoOwner)}/${encodePossiblyEncodedSegment(repoName)}/actions/artifacts/${artifactId}${
      direct ? ".zip" : ""
    }`;
  }

  match = pathname.match(/^\/([^/]+)\/([^/]+)\/commit\/[0-9a-fA-F]{40}\/checks\/(\d+)\/logs$/);
  if (match) {
    const [, repoOwner, repoName, jobId] = match;
    return `/${encodePossiblyEncodedSegment(repoOwner)}/${encodePossiblyEncodedSegment(repoName)}/runs/${jobId}${
      direct ? ".txt" : ""
    }`;
  }

  return null;
}

function parseStatus(searchParams: URLSearchParams): string {
  const status = searchParams.get("status") ?? "success";
  if (status !== "success" && status !== "completed") {
    throw new HttpError(400, "?status must be 'success' (default) or 'completed'");
  }
  return status;
}

async function handleIndex(url: URL): Promise<Response> {
  const inputUrl = url.searchParams.get("url");
  const h = url.searchParams.get("h");
  const messages: string[] = [];

  if (inputUrl) {
    let path = "";
    try {
      const parsed = new URL(inputUrl);
      path = parsed.pathname;
    } catch {
      path = inputUrl;
    }

    const mapped = mapGitHubPath(path, false);
    if (mapped) {
      const redirectTarget = appendHashToken(mapped, h);
      throw new HttpError(302, "", { Location: redirectTarget });
    }

    messages.push("Did not detect a link to a GitHub workflow file, actions run, or artifact.");
    messages.push(path);
  }

  let exampleWorkflow: string = WORKFLOW_EXAMPLES[0].workflowUrl;
  let exampleArtifact: string = WORKFLOW_EXAMPLES[0].artifact;
  let exampleDestination: string = absUrl(
    `/${WORKFLOW_EXAMPLES[0].repoOwner}/${WORKFLOW_EXAMPLES[0].repoName}/workflows/${WORKFLOW_EXAMPLES[0].workflow}/${WORKFLOW_EXAMPLES[0].branch}/${WORKFLOW_EXAMPLES[0].artifact}`
  );
  let exampleRunLink: string = `${GITHUB_WEB_BASE}/${WORKFLOW_EXAMPLES[0].repoOwner}/${WORKFLOW_EXAMPLES[0].repoName}/actions/runs/0`;
  let exampleArtifactLink: string = `${GITHUB_WEB_BASE}/${WORKFLOW_EXAMPLES[0].repoOwner}/${WORKFLOW_EXAMPLES[0].repoName}/suites/0/artifacts/0`;

  try {
    const example = await loadExample();
    exampleWorkflow = example.workflowUrl;
    exampleArtifact = example.artifactName;
    exampleDestination = absUrl(
      `/${encodePathSegment(example.repoOwner)}/${encodePathSegment(example.repoName)}/workflows/${encodePathSegment(
        stripYml(example.workflow)
      )}/${encodePathSegment(example.branch)}/${encodePathSegment(example.artifactName)}`
    );
    exampleRunLink = githubRunLink(example.repoOwner, example.repoName, example.runId);
    exampleArtifactLink = artifactGhDownloadLink({
      repoOwner: example.repoOwner,
      repoName: example.repoName,
      checkSuiteId: example.checkSuiteId,
      artifactId: example.artifactId
    });
  } catch {
    // Keep static examples when API calls fail.
  }

  const body = `<h1>arti-link</h1>
<div class="panel">
<p class="lead"><strong>arti-link</strong> turns GitHub Actions workflow/run/artifact links into shareable download pages.</p>
<p class="muted-note">Public repositories work out of the box. Private repositories require dashboard authorization and an <code>h</code> hash in generated links.</p>

<h2>Setup</h2>
<form action="https://github.com/apps/${escapeHtml(requiredEnv("GITHUB_APP_NAME"))}/installations/new">
  <input type="submit" value="Install and select your repositories">
</form>
<form action="/dashboard">
  <input type="submit" value="Authorize to see your repositories">
  (optional for public repositories, required for private repository access)
</form>

<h2>Convert a GitHub link</h2>
<form action="/">
  <input name="url" id="url" required pattern="^https://github.com/.+" value="${escapeHtml(inputUrl ?? "")}" style="width: 80%">
  <input type="submit" id="get" value="Generate links">
  ${h ? `<input type="hidden" name="h" value="${escapeHtml(h)}">` : ""}
</form>
${messages.map((message) => `<p class="absent">${escapeHtml(message)}</p>`).join("\n")}

<details>
<summary>Workflow URL -> latest artifact links</summary>
<p>Paste a workflow file URL, for example <a class="example" href="${escapeHtml(exampleWorkflow)}" target="_blank">${escapeHtml(
    exampleWorkflow
  )}</a>.</p>
<p>The generated route tracks the latest matching run for the same repository + workflow + branch combination.</p>
<p>Example output: <a rel="nofollow" href="${escapeHtml(exampleDestination)}">${escapeHtml(
    exampleDestination
  )}</a> [<a rel="nofollow" href="${escapeHtml(`${exampleDestination}.zip`)}">.zip</a>]</p>
</details>

<details>
<summary>Run / artifact URL conversion</summary>
<p>GitHub run example: <a class="example" href="${escapeHtml(exampleRunLink)}" target="_blank">${escapeHtml(
    exampleRunLink
  )}</a></p>
<p>GitHub artifact page example: <a class="example" href="${escapeHtml(exampleArtifactLink)}" target="_blank">${escapeHtml(
    exampleArtifactLink
  )}</a></p>
<p>arti-link keeps URL formats predictable and returns anonymous-friendly download pages.</p>
</details>

<details>
<summary>Usage notes</summary>
<p>If a run has multiple artifacts, you will get an artifact selection page first.</p>
<p>Add <code>?status=completed</code> when you want latest completed runs (instead of only successful runs).</p>
<p>For private repositories, use dashboard-generated links that include a valid <code>h</code> query parameter.</p>
</details>
</div>

<script>
  (function () {
    var field = document.getElementById('url');
    var button = document.getElementById('get');
    var links = document.getElementsByClassName('example');
    for (var i = 0; i < links.length; ++i) {
      links[i].onclick = function () {
        field.value = this.href;
        setTimeout(function () { field.focus(); }, 1);
        setTimeout(function () { button.focus(); }, 250);
        return false;
      }
    }
  })();
</script>`;

  return htmlResponse(renderLayout({ body, popup: true, canonical: absUrl("/") }));
}

async function loadExample(): Promise<{
  workflowUrl: string;
  runId: number;
  artifactId: number;
  checkSuiteId: number;
  repoOwner: string;
  repoName: string;
  workflow: string;
  branch: string;
  artifactName: string;
}> {
  if (exampleCache && Date.now() < exampleCache.expiresAt) {
    return exampleCache;
  }

  const item = WORKFLOW_EXAMPLES[Math.floor(Math.random() * WORKFLOW_EXAMPLES.length)];
  const fallbackToken = await getInstallationToken(getFallbackInstallationId());
  if (!fallbackToken) {
    throw new HttpError(500, "Fallback token unavailable for examples.");
  }

  const run = await latestRun({
    repoOwner: item.repoOwner,
    repoName: item.repoName,
    workflow: `${item.workflow}.yml`,
    branch: item.branch,
    status: "success",
    token: fallbackToken
  });

  const artifacts = await runArtifacts({
    repoOwner: item.repoOwner,
    repoName: item.repoName,
    runId: run.id,
    token: fallbackToken
  });
  const artifact = artifacts[0];
  if (!artifact) {
    throw new HttpError(500, "No example artifact found.");
  }

  const { owner, repo } = parseFullName(run.repository.full_name);
  const checkSuiteId = checkSuiteIdFromRun(run);
  if (!checkSuiteId) {
    throw new HttpError(500, "Example run missing check suite id.");
  }

  exampleCache = {
    expiresAt: Date.now() + 3 * 60 * 60 * 1000,
    workflowUrl: item.workflowUrl,
    runId: run.id,
    artifactId: artifact.id,
    checkSuiteId,
    repoOwner: owner,
    repoName: repo,
    workflow: `${item.workflow}.yml`,
    branch: item.branch,
    artifactName: artifact.name
  };

  return exampleCache;
}

async function handleDashboard(url: URL): Promise<Response> {
  const code = url.searchParams.get("code");
  if (!code) {
    const authUrl = new URL("https://github.com/login/oauth/authorize");
    authUrl.searchParams.set("client_id", requiredEnv("GITHUB_CLIENT_ID"));
    authUrl.searchParams.set("scope", "");
    authUrl.searchParams.set("redirect_uri", absUrl("/dashboard"));
    throw new HttpError(302, "", {
      Location: authUrl.toString(),
      "X-Robots-Tag": "noindex"
    });
  }

  const userToken = await oauthExchangeCode(code);
  const installations = await userInstallations(userToken);
  const records = await Promise.all(
    installations.map((installation) => refreshInstallationForUser(installation, userToken))
  );

  const publicItems: Array<{ owner: string; repo: string }> = [];
  const privateItems: Array<{ owner: string; repo: string; hash: string }> = [];

  for (const record of records) {
    for (const repo of record.publicRepos) {
      publicItems.push({ owner: record.repoOwner, repo });
    }
    for (const repo of record.privateRepos) {
      privateItems.push({ owner: record.repoOwner, repo, hash: repoPassword(record, repo) });
    }
  }

  const renderRepoForm = (item: { owner: string; repo: string; hash?: string }) => {
    const pattern = workflowPattern(item.owner, item.repo);
    const placeholder = workflowPlaceholder(item.owner, item.repo);
    return `<li>
      <a rel="nofollow" target="_blank" href="https://github.com/${escapeHtml(item.owner)}/${escapeHtml(item.repo)}">${escapeHtml(
        `${item.owner}/${item.repo}`
      )}</a>
      <form action="/">
        <label>Paste a workflow file URL that uploads artifacts (via <code>upload-artifact</code>):<br/>
        <input name="url" required pattern="${escapeHtml(pattern)}" placeholder="${escapeHtml(
          placeholder
        )}" style="width: 80%"></label>
        <input type="submit" value="Generate links">
        ${item.hash ? `<input type="hidden" name="h" value="${escapeHtml(item.hash)}">` : ""}
      </form>
    </li>`;
  };

  const body = `<h1><a href="/">arti-link</a></h1>
<p class="lead">Dashboard authorization completed. You can now generate repository-specific links below.</p>
<p class="muted-note">Private links contain an <code>h</code> hash token. Keep those URLs private.</p>

<h2>Private repositories (${privateItems.length})</h2>
<ul>
${privateItems.length > 0 ? privateItems.map((item) => renderRepoForm(item)).join("\n") : "<li>None</li>"}
</ul>
${
  privateItems.length > 0
    ? "<p class=\"muted-note\">To rotate private link hashes, uninstall and reinstall the GitHub App.</p>"
    : ""
}

<h2>Public repositories (${publicItems.length})</h2>
<ul>
${publicItems.length > 0 ? publicItems.map((item) => renderRepoForm(item)).join("\n") : "<li>None</li>"}
</ul>

<form action="https://github.com/apps/${escapeHtml(requiredEnv("GITHUB_APP_NAME"))}/installations/new">
  <input type="submit" value="Change repository selection">
</form>
<form action="">
  <input type="submit" value="Refresh dashboard data">
</form>
<script>
  window.history.replaceState(null, "", window.location.href.split("?")[0]);
</script>`;

  return htmlResponse(renderLayout({ title: "Dashboard", canonical: absUrl("/dashboard"), body }), 200, {
    "X-Robots-Tag": "noindex"
  });
}

async function handleSetup(url: URL): Promise<Response> {
  const installationIdRaw = url.searchParams.get("installation_id");
  const installationId = Number.parseInt(installationIdRaw ?? "", 10);
  if (!Number.isFinite(installationId)) {
    throw new HttpError(400, "installation_id query parameter is required.");
  }

  try {
    await refreshInstallationByApp(installationId);
  } catch {
    // Keep behavior close to the Crystal app: redirect even if refresh fails.
  }

  throw new HttpError(302, "", { Location: "/" });
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

async function handleDashByBranch({
  repoOwner,
  repoName,
  workflow,
  branch,
  searchParams
}: {
  repoOwner: string;
  repoName: string;
  workflow: string;
  branch: string;
  searchParams: URLSearchParams;
}): Promise<Response> {
  const inputHash = searchParams.get("h");
  const { token, h } = await verifiedToken(repoOwner, repoName, inputHash);
  const normalizedWorkflow = normalizeWorkflow(workflow);
  const status = parseStatus(searchParams);

  const run = await latestRun({
    repoOwner,
    repoName,
    workflow: normalizedWorkflow,
    branch,
    status,
    token
  });

  const runRepo = parseFullName(run.repository.full_name);
  const messages: string[] = [];
  if (Date.now() - new Date(run.updated_at).getTime() > 90 * 24 * 60 * 60 * 1000) {
    messages.push("Warning: the latest successful run is older than 90 days, and its artifacts likely expired.");
  }

  let artifacts: Artifact[];
  try {
    artifacts = await runArtifacts({
      repoOwner: runRepo.owner,
      repoName: runRepo.repo,
      runId: run.id,
      token
    });
  } catch (error) {
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(
        404,
        `No artifacts found for workflow '${normalizedWorkflow}' and branch '${branch}'.\nCheck on GitHub: <${githubRunLink(
          runRepo.owner,
          runRepo.repo,
          run.id
        )}>`
      );
    }
    throw error;
  }

  if (artifacts.length === 0) {
    throw new HttpError(
      404,
      `No artifacts found for workflow '${normalizedWorkflow}' and branch '${branch}'.\nCheck on GitHub: <${githubRunLink(
        runRepo.owner,
        runRepo.repo,
        run.id
      )}>`
    );
  }
  const branchPath = encodePathSegment(branch);
  const workflowPath = encodePathSegment(stripYml(normalizedWorkflow));
  const links = artifacts
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((artifact) => {
      const artifactPath = encodePathSegment(artifact.name);
      const linkPath = `/${encodePathSegment(runRepo.owner)}/${encodePathSegment(runRepo.repo)}/workflows/${workflowPath}/${branchPath}/${artifactPath}`;
      const linkUrl = appendHashToken(absUrl(linkPath), h);
      const linkZipUrl = appendHashToken(absUrl(`${linkPath}.zip`), h);
      return {
        title: artifact.name,
        url: linkUrl,
        zipUrl: linkZipUrl
      } satisfies ArtifactListLink;
    });

  if (links.length === 1) {
    if (searchParams.has("preview")) {
      messages.push(
        "As long as this workflow produces exactly 1 artifact, you can drop '?preview' and this URL will redirect automatically."
      );
    } else {
      throw new HttpError(302, "", { Location: links[0].url });
    }
  }

  const canonicalPath = `/${encodePathSegment(runRepo.owner)}/${encodePathSegment(runRepo.repo)}/workflows/${workflowPath}/${branchPath}`;
  const canonical = appendHashToken(absUrl(canonicalPath), h);

  const body = renderArtifactListPage({
    title: `Repository ${runRepo.owner}/${runRepo.repo}`,
    subtitle: `Workflow ${normalizedWorkflow} | Branch ${branch}`,
    messages,
    links
  });

  return htmlResponse(
    renderLayout({
      title: `Repository ${runRepo.owner}/${runRepo.repo} | Workflow ${normalizedWorkflow} | Branch ${branch}`,
      canonical,
      body
    })
  );
}

async function handleDashByRun({
  repoOwner,
  repoName,
  runId,
  searchParams
}: {
  repoOwner: string;
  repoName: string;
  runId: number;
  searchParams: URLSearchParams;
}): Promise<Response> {
  const inputHash = searchParams.get("h");
  const { token, h } = await verifiedToken(repoOwner, repoName, inputHash);

  let artifacts: Artifact[];
  try {
    artifacts = await runArtifacts({
      repoOwner,
      repoName,
      runId,
      token
    });
  } catch (error) {
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(
        404,
        `Repository '${repoOwner}/${repoName}' or run #${runId} not found.\nCheck on GitHub: <${githubRunLink(
          repoOwner,
          repoName,
          runId
        )}>`
      );
    }
    throw error;
  }

  if (artifacts.length === 0) {
    throw new HttpError(
      404,
      `No artifacts found for run #${runId}.\nCheck on GitHub: <${githubRunLink(repoOwner, repoName, runId)}>`
    );
  }

  let resolvedOwner = repoOwner;
  let resolvedRepo = repoName;
  const links = artifacts
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((artifact) => {
      const artifactRepo = artifactOwnerRepo(artifact);
      resolvedOwner = artifactRepo.owner;
      resolvedRepo = artifactRepo.repo;
      const artifactPath = encodePathSegment(artifact.name);
      const linkPath = `/${encodePathSegment(artifactRepo.owner)}/${encodePathSegment(
        artifactRepo.repo
      )}/actions/runs/${runId}/${artifactPath}`;
      const linkUrl = appendHashToken(absUrl(linkPath), h);
      const linkZipUrl = appendHashToken(absUrl(`${linkPath}.zip`), h);
      return {
        title: artifact.name,
        url: linkUrl,
        zipUrl: linkZipUrl
      } satisfies ArtifactListLink;
    });

  const canonicalPath = `/${encodePathSegment(resolvedOwner)}/${encodePathSegment(resolvedRepo)}/actions/runs/${runId}`;
  const canonical = appendHashToken(absUrl(canonicalPath), h);

  const body = renderArtifactListPage({
    title: `Repository ${resolvedOwner}/${resolvedRepo}`,
    subtitle: `Run #${runId}`,
    messages: [],
    links
  });

  return htmlResponse(
    renderLayout({
      title: `Repository ${resolvedOwner}/${resolvedRepo} | Run #${runId}`,
      canonical,
      body
    })
  );
}

function artifactOwnerRepo(artifact: Artifact): { owner: string; repo: string } {
  const match = artifact.url.match(/^https:\/\/[^/]+\/repos\/([^/]+)\/([^/]+)\//);
  if (!match) {
    throw new HttpError(500, `Invalid artifact URL from GitHub: ${artifact.url}`);
  }
  return {
    owner: match[1],
    repo: match[2]
  };
}

async function handleByBranch({
  repoOwner,
  repoName,
  workflow,
  branch,
  artifactName,
  zip,
  searchParams
}: {
  repoOwner: string;
  repoName: string;
  workflow: string;
  branch: string;
  artifactName: string;
  zip: boolean;
  searchParams: URLSearchParams;
}): Promise<Response> {
  const inputHash = searchParams.get("h");
  const { token, h } = await verifiedToken(repoOwner, repoName, inputHash);
  const normalizedWorkflow = normalizeWorkflow(workflow);
  const status = parseStatus(searchParams);

  const run = await latestRun({
    repoOwner,
    repoName,
    workflow: normalizedWorkflow,
    branch,
    status,
    token
  });
  const runRepo = parseFullName(run.repository.full_name);

  let artifacts: Artifact[];
  try {
    artifacts = await runArtifacts({
      repoOwner: runRepo.owner,
      repoName: runRepo.repo,
      runId: run.id,
      token
    });
  } catch (error) {
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(
        404,
        `No artifacts found for run #${run.id}.\nCheck on GitHub: <${githubRunLink(runRepo.owner, runRepo.repo, run.id)}>`
      );
    }
    throw error;
  }

  const resolvedArtifact =
    artifacts.find((item) => item.name === artifactName) ||
    artifacts.find((item) => item.name === `${artifactName}.zip`);
  if (!resolvedArtifact) {
    throw new HttpError(
      404,
      `Artifact '${artifactName}' not found for run #${run.id}.\nCheck on GitHub: <${githubRunLink(
        runRepo.owner,
        runRepo.repo,
        run.id
      )}>`
    );
  }
  const runCheckSuiteId = checkSuiteIdFromRun(run);
  const artifactGhLink = runCheckSuiteId
    ? artifactGhDownloadLink({
        repoOwner: runRepo.owner,
        repoName: runRepo.repo,
        checkSuiteId: runCheckSuiteId,
        artifactId: resolvedArtifact.id
      })
    : artifactApiLink(runRepo.owner, runRepo.repo, resolvedArtifact.id);
  if (resolvedArtifact.expired) {
    throw new HttpError(
      404,
      `GitHub produced an error for the download of artifact #${resolvedArtifact.id}.\nUsually this means that the artifact has expired (>90 days).\nCheck on GitHub: <${artifactGhLink}>`
    );
  }

  const artifactRepo = artifactOwnerRepo(resolvedArtifact);
  let tempLink: string;
  try {
    tempLink = await artifactZipLocation({
      repoOwner: artifactRepo.owner,
      repoName: artifactRepo.repo,
      artifactId: resolvedArtifact.id,
      token
    });
  } catch (error) {
    if (error instanceof GitHubArtifactDownloadError) {
      throw new HttpError(
        404,
        `GitHub produced an error for the download of artifact #${resolvedArtifact.id}.\nUsually this means that the artifact has expired (>90 days).\nCheck on GitHub: <${artifactGhLink}>`
      );
    }
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(
        404,
        `Artifact #${resolvedArtifact.id} not found.\nCheck on GitHub: <${artifactGhLink}>`
      );
    }
    throw error;
  }

  if (zip) {
    throw new HttpError(302, "", { Location: tempLink });
  }

  const workflowPath = encodePathSegment(stripYml(normalizedWorkflow));
  const branchPath = encodePathSegment(branch);
  const artifactPath = encodePathSegment(artifactName);
  const byBranchPath = `/${encodePathSegment(artifactRepo.owner)}/${encodePathSegment(
    artifactRepo.repo
  )}/workflows/${workflowPath}/${branchPath}/${artifactPath}`;
  const byRunPath = `/${encodePathSegment(artifactRepo.owner)}/${encodePathSegment(
    artifactRepo.repo
  )}/actions/runs/${run.id}/${artifactPath}`;
  const byArtifactPath = `/${encodePathSegment(artifactRepo.owner)}/${encodePathSegment(
    artifactRepo.repo
  )}/actions/artifacts/${resolvedArtifact.id}`;

  const checkSuiteId = runCheckSuiteId;
  const links: Link[] = [
    {
      title: appendHashToken(absUrl(`${byBranchPath}.zip`), h),
      url: appendHashToken(absUrl(`${byBranchPath}.zip`), h)
    },
    {
      title: appendHashToken(absUrl(`${byRunPath}.zip`), h),
      url: appendHashToken(absUrl(`${byRunPath}.zip`), h)
    },
    {
      title: appendHashToken(absUrl(`${byArtifactPath}.zip`), h),
      url: appendHashToken(absUrl(`${byArtifactPath}.zip`), h)
    },
    {
      title: "Ephemeral direct download link (expires in <1 minute)",
      url: tempLink
    },
    {
      title: `View run #${run.id}`,
      url: githubRunLink(artifactRepo.owner, artifactRepo.repo, run.id),
      ext: true
    },
    {
      title: `Browse workflow runs on branch '${branch}'`,
      url: githubActionsLink({
        repoOwner: artifactRepo.owner,
        repoName: artifactRepo.repo,
        event: run.event,
        branch,
        status
      }),
      ext: true
    }
  ];

  if (checkSuiteId) {
    links.push({
      title: `Direct download of artifact #${resolvedArtifact.id} (requires GitHub login)`,
      url: artifactGhDownloadLink({
        repoOwner: artifactRepo.owner,
        repoName: artifactRepo.repo,
        checkSuiteId,
        artifactId: resolvedArtifact.id
      }),
      ext: true
    });
  }

  const canonical = appendHashToken(absUrl(byBranchPath), h);
  const body = renderArtifactPage({
    title: `Repository ${artifactRepo.owner}/${artifactRepo.repo}`,
    subtitle: `Workflow ${normalizedWorkflow} | Branch ${branch} | Artifact ${artifactName}`,
    links
  });

  return htmlResponse(
    renderLayout({
      title: `Repository ${artifactRepo.owner}/${artifactRepo.repo} | Workflow ${normalizedWorkflow} | Branch ${branch} | Artifact ${artifactName}`,
      canonical,
      body
    })
  );
}

async function handleByRun({
  repoOwner,
  repoName,
  runId,
  artifactName,
  zip,
  searchParams
}: {
  repoOwner: string;
  repoName: string;
  runId: number;
  artifactName: string;
  zip: boolean;
  searchParams: URLSearchParams;
}): Promise<Response> {
  const inputHash = searchParams.get("h");
  const { token, h } = await verifiedToken(repoOwner, repoName, inputHash);

  let artifacts: Artifact[];
  try {
    artifacts = await runArtifacts({
      repoOwner,
      repoName,
      runId,
      token
    });
  } catch (error) {
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(404, `No artifacts found for run #${runId}.\nCheck on GitHub: <${githubRunLink(repoOwner, repoName, runId)}>`);
    }
    throw error;
  }

  const resolvedArtifact =
    artifacts.find((item) => item.name === artifactName) ||
    artifacts.find((item) => item.name === `${artifactName}.zip`);
  if (!resolvedArtifact) {
    throw new HttpError(
      404,
      `Artifact '${artifactName}' not found for run #${runId}.\nCheck on GitHub: <${githubRunLink(repoOwner, repoName, runId)}>`
    );
  }
  const artifactRepo = artifactOwnerRepo(resolvedArtifact);
  const artifactGhLink = artifactApiLink(artifactRepo.owner, artifactRepo.repo, resolvedArtifact.id);
  if (resolvedArtifact.expired) {
    throw new HttpError(
      404,
      `GitHub produced an error for the download of artifact #${resolvedArtifact.id}.\nUsually this means that the artifact has expired (>90 days).\nCheck on GitHub: <${artifactGhLink}>`
    );
  }

  let tempLink: string;
  try {
    tempLink = await artifactZipLocation({
      repoOwner: artifactRepo.owner,
      repoName: artifactRepo.repo,
      artifactId: resolvedArtifact.id,
      token
    });
  } catch (error) {
    if (error instanceof GitHubArtifactDownloadError) {
      throw new HttpError(
        404,
        `GitHub produced an error for the download of artifact #${resolvedArtifact.id}.\nUsually this means that the artifact has expired (>90 days).\nCheck on GitHub: <${artifactGhLink}>`
      );
    }
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(404, `Artifact #${resolvedArtifact.id} not found.\nCheck on GitHub: <${artifactGhLink}>`);
    }
    throw error;
  }

  if (zip) {
    throw new HttpError(302, "", { Location: tempLink });
  }

  const artifactPath = encodePathSegment(artifactName);
  const byRunPath = `/${encodePathSegment(artifactRepo.owner)}/${encodePathSegment(
    artifactRepo.repo
  )}/actions/runs/${runId}/${artifactPath}`;
  const byArtifactPath = `/${encodePathSegment(artifactRepo.owner)}/${encodePathSegment(
    artifactRepo.repo
  )}/actions/artifacts/${resolvedArtifact.id}`;

  const links: Link[] = [
    {
      title: appendHashToken(absUrl(`${byRunPath}.zip`), h),
      url: appendHashToken(absUrl(`${byRunPath}.zip`), h)
    },
    {
      title: appendHashToken(absUrl(`${byArtifactPath}.zip`), h),
      url: appendHashToken(absUrl(`${byArtifactPath}.zip`), h)
    },
    {
      title: "Ephemeral direct download link (expires in <1 minute)",
      url: tempLink
    },
    {
      title: `View run #${runId}`,
      url: githubRunLink(artifactRepo.owner, artifactRepo.repo, runId),
      ext: true
    }
  ];

  const canonical = appendHashToken(absUrl(byRunPath), h);
  const body = renderArtifactPage({
    title: `Repository ${artifactRepo.owner}/${artifactRepo.repo}`,
    subtitle: `Run #${runId} | Artifact ${artifactName}`,
    links
  });

  return htmlResponse(
    renderLayout({
      title: `Repository ${artifactRepo.owner}/${artifactRepo.repo} | Run #${runId} | Artifact ${artifactName}`,
      canonical,
      body
    })
  );
}

async function handleByArtifact({
  repoOwner,
  repoName,
  artifactId,
  zip,
  searchParams
}: {
  repoOwner: string;
  repoName: string;
  artifactId: number;
  zip: boolean;
  searchParams: URLSearchParams;
}): Promise<Response> {
  const inputHash = searchParams.get("h");
  const { token, h } = await verifiedToken(repoOwner, repoName, inputHash);

  let tempLink: string;
  try {
    tempLink = await artifactZipLocation({
      repoOwner,
      repoName,
      artifactId,
      token
    });
  } catch (error) {
    if (error instanceof GitHubArtifactDownloadError) {
      throw new HttpError(
        404,
        `GitHub produced an error for the download of artifact #${artifactId}.\nUsually this means that the artifact has expired (>90 days).\nCheck on GitHub: <${artifactApiLink(
          repoOwner,
          repoName,
          artifactId
        )}>`
      );
    }
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(404, `Artifact #${artifactId} not found.\nCheck on GitHub: <${artifactApiLink(repoOwner, repoName, artifactId)}>`);
    }
    throw error;
  }

  if (zip) {
    throw new HttpError(302, "", { Location: tempLink });
  }

  const path = `/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/actions/artifacts/${artifactId}`;
  const links: Link[] = [
    {
      title: appendHashToken(absUrl(`${path}.zip`), h),
      url: appendHashToken(absUrl(`${path}.zip`), h)
    },
    {
      title: "Ephemeral direct download link (expires in <1 minute)",
      url: tempLink
    }
  ];

  const canonical = appendHashToken(absUrl(path), h);
  const body = renderArtifactPage({
    title: `Repository ${repoOwner}/${repoName}`,
    subtitle: `Artifact #${artifactId}`,
    links
  });

  return htmlResponse(
    renderLayout({
      title: `Repository ${repoOwner}/${repoName} | Artifact #${artifactId}`,
      canonical,
      body
    })
  );
}

async function handleByJob({
  repoOwner,
  repoName,
  jobId,
  txt,
  searchParams
}: {
  repoOwner: string;
  repoName: string;
  jobId: number;
  txt: boolean;
  searchParams: URLSearchParams;
}): Promise<Response> {
  const inputHash = searchParams.get("h");
  const { token, h } = await verifiedToken(repoOwner, repoName, inputHash);

  let tempLink: string;
  try {
    tempLink = await jobLogsLocation({
      repoOwner,
      repoName,
      jobId,
      token
    });
  } catch (error) {
    if (error instanceof GitHubLogsDownloadError) {
      throw new HttpError(
        404,
        `It seems that the logs for job #${jobId} have expired.\nCheck on GitHub: <${githubJobLink(repoOwner, repoName, jobId)}>`
      );
    }
    if (error instanceof GitHubRequestError && isNotFoundStatus(error.status)) {
      throw new HttpError(404, `Job #${jobId} not found.\nCheck on GitHub: <${githubJobLink(repoOwner, repoName, jobId)}>`);
    }
    throw error;
  }

  if (txt) {
    throw new HttpError(302, "", { Location: tempLink });
  }

  const path = `/${encodePathSegment(repoOwner)}/${encodePathSegment(repoName)}/runs/${jobId}`;
  const links: Link[] = [
    {
      title: appendHashToken(absUrl(`${path}.txt`), h),
      url: appendHashToken(absUrl(`${path}.txt`), h)
    },
    {
      title: "Ephemeral link to logs (expires in <1 minute)",
      url: tempLink
    },
    {
      title: `View job #${jobId}`,
      url: githubJobLink(repoOwner, repoName, jobId),
      ext: true
    }
  ];

  const canonical = appendHashToken(absUrl(path), h);
  const body = renderJobPage({
    title: `Repository ${repoOwner}/${repoName}`,
    subtitle: `Job #${jobId}`,
    links
  });

  return htmlResponse(
    renderLayout({
      title: `Repository ${repoOwner}/${repoName} | Job #${jobId}`,
      canonical,
      body
    })
  );
}

function htmlResponse(body: string, status = 200, headers: HeadersInit = {}): Response {
  const merged = new Headers(headers);
  merged.set("Content-Type", "text/html; charset=utf-8");
  return new Response(body, { status, headers: merged });
}

function parseIntStrict(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new HttpError(404, "Not found");
  }
  const parsed = Number.parseInt(value, 10);
  return parsed;
}

async function routeByPath(url: URL): Promise<Response> {
  const pathname = url.pathname;

  if (pathname === "/") {
    return handleIndex(url);
  }

  if (pathname === "/dashboard") {
    return handleDashboard(url);
  }

  if (pathname === "/setup") {
    return handleSetup(url);
  }

  const segments = pathname.split("/").filter(Boolean).map(decodeSegment);

  if (segments.length === 6 && segments[2] === "workflows") {
    const [repoOwner, repoName, , workflow, branch, artifactRaw] = segments;
    const zip = artifactRaw.endsWith(".zip");
    const artifactName = zip ? artifactRaw.slice(0, -4) : artifactRaw;
    return handleByBranch({
      repoOwner,
      repoName,
      workflow,
      branch,
      artifactName,
      zip,
      searchParams: url.searchParams
    });
  }

  if (segments.length === 6 && segments[2] === "actions" && segments[3] === "runs") {
    const [repoOwner, repoName, , , runIdRaw, artifactRaw] = segments;
    const runId = parseIntStrict(runIdRaw);
    const zip = artifactRaw.endsWith(".zip");
    const artifactName = zip ? artifactRaw.slice(0, -4) : artifactRaw;

    return handleByRun({
      repoOwner,
      repoName,
      runId,
      artifactName,
      zip,
      searchParams: url.searchParams
    });
  }

  if (segments.length === 5 && segments[2] === "actions" && segments[3] === "artifacts") {
    const [repoOwner, repoName, , , artifactRaw] = segments;
    const zip = artifactRaw.endsWith(".zip");
    const artifactId = parseIntStrict(zip ? artifactRaw.slice(0, -4) : artifactRaw);

    return handleByArtifact({
      repoOwner,
      repoName,
      artifactId,
      zip,
      searchParams: url.searchParams
    });
  }

  if (segments.length === 4 && segments[2] === "runs") {
    const [repoOwner, repoName, , jobRaw] = segments;
    const txt = jobRaw.endsWith(".txt");
    const jobId = parseIntStrict(txt ? jobRaw.slice(0, -4) : jobRaw);
    return handleByJob({
      repoOwner,
      repoName,
      jobId,
      txt,
      searchParams: url.searchParams
    });
  }

  if (segments.length === 5 && segments[2] === "workflows") {
    const [repoOwner, repoName, , workflow, branch] = segments;
    return handleDashByBranch({
      repoOwner,
      repoName,
      workflow,
      branch,
      searchParams: url.searchParams
    });
  }

  if (segments.length === 5 && segments[2] === "actions" && segments[3] === "runs") {
    const [repoOwner, repoName, , , runIdRaw] = segments;
    return handleDashByRun({
      repoOwner,
      repoName,
      runId: parseIntStrict(runIdRaw),
      searchParams: url.searchParams
    });
  }

  const mapped = mapGitHubPath(pathname, true);
  if (mapped) {
    throw new HttpError(302, "", { Location: mapped });
  }

  throw new HttpError(404, pathname);
}

export async function handleNightlyRequest(request: Request): Promise<Response> {
  try {
    return await routeByPath(new URL(request.url));
  } catch (error) {
    if (error instanceof HttpError) {
      if (error.status >= 300 && error.status < 400) {
        return new Response(null, {
          status: error.status,
          headers: error.headers
        });
      }

      return htmlResponse(renderLayout({ body: renderErrorPage(error.status, error.message) }), error.status, error.headers);
    }

    if (error instanceof GitHubRequestError) {
      const message = isNotFoundStatus(error.status)
        ? "Resource not found on GitHub."
        : `GitHub API error (${error.status}).`;
      return htmlResponse(renderLayout({ body: renderErrorPage(502, message) }), 502);
    }

    return htmlResponse(
      renderLayout({ body: renderErrorPage(500, "Unexpected internal server error.") }),
      500
    );
  }
}
