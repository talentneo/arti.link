# arti-link

TypeScript + Vercel-compatible port of `nightly.link-master`. It turns GitHub Actions workflow / run / artifact links into stable, shareable download pages (including private-repo support via opt-in hashes).

## What it does

- Converts GitHub workflow/run/artifact/job links into anonymous-friendly download pages.
- Tracks the latest successful (or completed) workflow run for a given `repo / workflow / branch` and exposes artifact links.
- Lists artifacts for a specific run, or serves a single artifact by id.
- Serves job logs as portable `.txt` links.
- Handles private repositories via per-repo hash tokens plus a dashboard OAuth flow.
- Runs as a single Next.js route handler (`app/[[...slug]]/route.ts`) deployable on Vercel Node runtime.

## How it works (request flow)

- **Entry point**: `GET /app/[[...slug]]/route.ts` delegates everything to `handleNightlyRequest` in `lib/nightly.ts`.
- **Public index** (`/`): optional GitHub URL converter; auto-maps pasted GitHub workflow/run/artifact URLs to the corresponding arti-link route; shows live examples using a fallback installation.
- **Workflow route** (`/{owner}/{repo}/workflows/{workflow}/{branch}/{artifact}[.zip]`):
  - Validates `status` (`success` default, or `completed`).
  - Fetches latest matching run (push + schedule events) via GitHub Actions API.
  - Loads artifacts for that run; redirects if only one artifact unless `?preview` is set; otherwise renders a selection table.
  - For a specific artifact, builds stable links (branch/workflow-based, run-based, artifact-id-based) and an ephemeral direct URL; `.zip` variant redirects straight to the temporary download.
- **Run route** (`/{owner}/{repo}/actions/runs/{runId}/{artifact}[.zip]`): lists or serves artifacts for a specific run.
- **Artifact-id route** (`/{owner}/{repo}/actions/artifacts/{artifactId}[.zip]`): proxies artifact download by id.
- **Job logs route** (`/{owner}/{repo}/runs/{jobId}[.txt]`): provides portable log links, with `.txt` redirecting to the short-lived GitHub URL.
- **GitHub URL mapper**: direct GitHub links (workflow files, runs, artifacts, job logs) are auto-redirected to the matching arti-link route when pasted into `/`.
- **Private repo access**:
  - GitHub App installation data is cached in-memory and optionally persisted to Vercel KV (`lib/store.ts`).
  - Dashboard (`/dashboard`) runs OAuth to fetch user installations, stores public/private repo lists, and issues per-repo hash tokens (`h` query param) for private access.
  - Requests validate the `h` token before allowing private downloads; public repos fall back to a shared installation token defined by `FALLBACK_INSTALLATION_ID`.
- **Error handling**: typed `HttpError` responses render HTML error pages; GitHub API errors map to clear 4xx/5xx pages; expired artifacts/logs surface explicit guidance.

## Environment

Required (see [.env.example](./.env.example) for defaults and comments):

- `GITHUB_APP_NAME`
- `GITHUB_APP_ID`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `APP_SECRET`
- `FALLBACK_INSTALLATION_ID`
- One of `GITHUB_PEM`, `GITHUB_PEM_BASE64`, `GITHUB_PEM_FILENAME`

Optional:

- `URL` (base URL used to build absolute links; defaults to `https://arti-link/`)
- `KV_REST_API_URL`, `KV_REST_API_TOKEN` (persist installation cache on Vercel KV)

## Local development

```bash
npm install
npm run dev
```

## Build / verify

```bash
npm run typecheck
npm run build
```
