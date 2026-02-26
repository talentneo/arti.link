# arti-link

TypeScript + Vercel-compatible port of `nightly.link-master`, preserving the same core link conversion and artifact/log download behavior.

## Features

- Convert GitHub links to anonymous-friendly artifact/log download links.
- Support latest workflow artifact links by `repo/workflow/branch`.
- Support run-level artifact listings.
- Support artifact-id and job-log direct routes.
- Support private repository hash (`h`) protection and dashboard flows.
- OAuth + GitHub App installation refresh support.
- Deployable on Vercel (Node runtime route handler).

## Required Environment Variables

See [.env.example](./.env.example).

Detailed setup guide (Chinese): [GitHub App 环境变量获取指南](./docs/github-app-env-setup.zh-CN.md)

At minimum you need:

- `GITHUB_APP_NAME`
- `GITHUB_APP_ID`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `APP_SECRET`
- `FALLBACK_INSTALLATION_ID`
- One of `GITHUB_PEM`, `GITHUB_PEM_BASE64`, `GITHUB_PEM_FILENAME`

## Optional

- `URL` (defaults to `https://arti-link/`)
- `KV_REST_API_URL` and `KV_REST_API_TOKEN` for persistent installation storage on Vercel KV

## Run

```bash
npm install
npm run dev
```

## Build

```bash
npm run typecheck
npm run build
```
