# GitHub App 环境变量获取指南（arti-link）

本文对应以下变量：

```env
GITHUB_APP_NAME=nightly-link
GITHUB_APP_ID=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
APP_SECRET=
FALLBACK_INSTALLATION_ID=
```

另外，当前项目还需要 GitHub App 私钥三选一（必须有一个）：

- `GITHUB_PEM`
- `GITHUB_PEM_BASE64`
- `GITHUB_PEM_FILENAME`

---

## 1. 先创建 GitHub App

### 入口

- 个人账号：`https://github.com/settings/apps/new`
- 组织账号：`https://github.com/organizations/<你的组织名>/settings/apps/new`

官方文档：
- [Registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)

### 注册时建议配置（适配本项目）

1. `GitHub App name`：填你想要的名称（例如 `nightly-link`）。
2. `Homepage URL`：填你的线上域名（例如 `https://arti-link`）。
3. `Callback URL`：填 `https://<你的域名>/dashboard`。
4. `Setup URL`：填 `https://<你的域名>/setup`。
5. `Request user authorization (OAuth) during installation`：建议不要勾选（本项目通过 `/dashboard` 单独授权）。
6. `Permissions` 里至少设置：
   - `Actions`: **Read-only**
   - `Metadata`: **Read-only**
7. Webhook 可不启用（本项目核心流程不依赖 webhook）。

相关文档：
- [About the user authorization callback URL](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url)
- [About the setup URL](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/about-the-setup-url)

---

## 2. 每个环境变量怎么拿

## `GITHUB_APP_NAME`

含义：GitHub App 的 **slug**（安装链接中的名字）。

获取方式：

1. 打开你的 App 页面，URL 通常是：`https://github.com/apps/<slug>`。
2. `<slug>` 就是 `GITHUB_APP_NAME`。

例如：`https://github.com/apps/nightly-link` -> `GITHUB_APP_NAME=nightly-link`

---

## `GITHUB_APP_ID`

含义：GitHub App 的数字 ID（不是 Client ID）。

获取方式：

1. 进入 App 设置页（Developer settings -> GitHub Apps -> 你的 App -> Edit）。
2. 在设置页顶部 About 区域找到 `App ID`。
3. 填到环境变量（纯数字）。

---

## `GITHUB_CLIENT_ID`

含义：OAuth 流程使用的 Client ID（不是 App ID）。

获取方式：

1. 同样在 App 设置页 About 区域。
2. 找到 `Client ID`，填入。

参考（文档明确区分 Client ID 与 App ID）：
- [Generating a user access token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)

---

## `GITHUB_CLIENT_SECRET`

含义：OAuth 交换 token 用的密钥。

获取方式：

1. 进入 App 设置页。
2. 在 `Client secrets` 区域点击 `Generate a new client secret`。
3. 立即复制保存（页面通常只展示一次）。

---

## `APP_SECRET`

含义：项目内部用于生成私有仓库 `h` 参数哈希的服务端密钥。

获取方式：使用高强度随机字符串。

推荐命令：

```bash
openssl rand -hex 32
```

生成后直接填入，例如：

```env
APP_SECRET=5ef4c6f8...<省略>...a8b9
```

---

## `FALLBACK_INSTALLATION_ID`

含义：默认兜底安装实例 ID（当仓库未命中本地记录时使用）。

获取方式 A（最简单，推荐）：

1. 先安装你的 App：`https://github.com/apps/<GITHUB_APP_NAME>/installations/new`
2. 安装完成后，GitHub 页面 URL 常包含安装 ID（数字）。
3. 该数字即 `FALLBACK_INSTALLATION_ID`。

获取方式 B（API）：

1. 用 App JWT 调 `GET /app/installations` 或相关安装查询接口。
2. 从响应里取 `id` 字段。

参考：
- [Installing your own GitHub App](https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app)
- [REST API endpoints for GitHub App installations](https://docs.github.com/en/rest/apps/installations)
- [REST API endpoints for GitHub Apps](https://docs.github.com/en/enterprise-cloud@latest/rest/apps/apps)

---

## 3. 私钥（项目必需）

你的代码需要 GitHub App 私钥来签 JWT。

生成方式：

1. 进入 App 设置页。
2. `Private keys` -> `Generate a private key`。
3. 下载得到 `.pem` 文件。

官方文档：
- [Managing private keys for GitHub Apps](https://docs.github.com/en/enterprise-server%403.15/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)

在本项目可选三种接法（选一个）：

1. 文件路径：

```env
GITHUB_PEM_FILENAME=/absolute/path/to/xxx.private-key.pem
```

2. 直接放 PEM 文本（含换行）：

```env
GITHUB_PEM="-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"
```

3. Base64：

```bash
base64 -i /path/to/key.pem
```

写入：

```env
GITHUB_PEM_BASE64=<base64结果>
```

---

## 4. `.env` 示例

```env
GITHUB_APP_NAME=nightly-link
GITHUB_APP_ID=123456
GITHUB_CLIENT_ID=Iv1.1234567890abcdef
GITHUB_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
APP_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
FALLBACK_INSTALLATION_ID=98765432

# 三选一
GITHUB_PEM_FILENAME=/Users/you/secrets/nightly-link.pem
# GITHUB_PEM=...
# GITHUB_PEM_BASE64=...

URL=https://your-domain.example/
```

---

## 5. 配完后快速自检

1. 启动服务后访问首页：`/`
2. 点击 `Install and select your repositories` 能正确跳转到 GitHub App 安装页。
3. 点击 `Authorize to see your repositories` 后，回调到 `/dashboard` 不报错。
4. 安装后访问 `/setup?installation_id=<id>` 能正确返回首页。

---

## 6. 常见问题

1. `GITHUB_APP_ID` 和 `GITHUB_CLIENT_ID` 填反了：
   - `APP_ID` 是纯数字。
   - `CLIENT_ID` 通常是 `Iv1.` 开头。
2. `Callback URL` 不精确：
   - 需要与应用里 `redirect_uri` 匹配，建议固定用 `https://<domain>/dashboard`。
3. `Client Secret` 没保存：
   - 重新生成一个新的即可。
4. 没配私钥：
   - 会导致无法生成 installation token。
5. `FALLBACK_INSTALLATION_ID` 对应安装没有可访问仓库：
   - 可能导致示例/兜底请求失败，建议使用你常驻可访问的安装实例。

---

## 官方参考链接汇总

- [Registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)
- [Modifying a GitHub App registration](https://docs.github.com/en/enterprise-cloud@latest/apps/maintaining-github-apps/modifying-a-github-app-registration)
- [Installing your own GitHub App](https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app)
- [Generating a user access token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [About the user authorization callback URL](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url)
- [About the setup URL](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/about-the-setup-url)
- [Managing private keys for GitHub Apps](https://docs.github.com/en/enterprise-server%403.15/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
- [REST API endpoints for GitHub App installations](https://docs.github.com/en/rest/apps/installations)
- [REST API endpoints for GitHub Apps](https://docs.github.com/en/enterprise-cloud@latest/rest/apps/apps)
