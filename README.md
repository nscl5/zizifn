# $${\color{#3B82F6}\Huge Serverless \space Runtime}$$

***[⁠■ Persian Documentation][fa]***  
***[⁠■ English Documentation][en]***

<br/>

<!--
$${\color{silver} We\space are\space \color{gray} All\space \color{red} REvil}$$

## $${\color{#94A3B8}\Large \text{Required Cloudflare Information}}$$
-->

### $${\color{#94A3B8}\Large Recent \space Changes}$$

> <details>
> <summary><b><i>Click here to see details</i></b></summary><br/>
> 
> - **Modular architecture**: worker logic split into `src/core.js`, `src/network.js`, `src/routes.js`, and `src/clash.js` instead of a single large file.
> 
> - **Safer WASM startup**: WASM is initialized once per isolate via a lazy singleton pattern, only when a WebSocket connection is opened.
> 
> - **Self-contained config panel**: `index.html` is bundled at build time, no runtime fetch to GitHub Pages.
> 
> - **Faster proxy relay**: TCP response path uses `Uint8Array` instead of `Blob` for header concatenation.
> 
> - **Resilient ProxyIP fallback**: multiple ProxyIP domains are tried in sequence if the primary one is unreachable.
> 
> - **Non-TLS configs for xray-enhanced**: added TCP (non-TLS) variants alongside TLS ones, for clients that support them like PattNG.
> 
> - **Native Clash Meta subscription**: added `/clash/<uuid>`, generating a full Clash Meta (mihomo) config directly from the worker — no external subconverter api service required.
> 
> - **Multi-account deploys**: the deploy workflow can now deploy the same Worker to up to 4 separate Cloudflare accounts in one run, each ticked as a checkbox on the "Run workflow" form. See [Multi-Account Deployment](#multi-account-deployment) below.
> 
> </details>

<br/>

## $${\color{#94A3B8}\Large Setup}$$

_After forking this repository, you need to create a few GitHub repository secrets before running the workflow._

$${\color{silver}\large Go \space to:}$$

$${\color{#3B82F6}\Large Your \space Repository \space → \space Settings \space → \space}$$
$${\color{#3B82F6}\Large → \space Secrets \space and \space variables \space → \space actions}$$

$${\color{silver}\large Then \space click:}$$

$${\color{#3B82F6}\Large New \space repository \space secret}$$

$${\color{silver}\large and \space add \space the \space following \space variables.}$$ 


| **Secret Name** | **Required** | **Default** | **Description** |
| ------ | :-----: | :------: | :-------------- |
| `CLOUDFLARE_API_TOKEN` | ✔️Yes | -  | Your Cloudflare Account API Token, for account slot 1. It **must** have permission to **Edit Workers**. |
| `CLOUDFLARE_ACCOUNT_ID` | ✔️Yes | - | Your Cloudflare Account ID, for account slot 1. |
| `UUID` | Optional | `be0ff9df-1468-41a0-8865-796d1c6800db` | Your own [Version 4 UUID][1]. If not provided, the workflow will automatically generate a random one. |
| `PROXYIP` | Optional | `di.nscl.ir` | Optional proxy IP or hostname. If omitted, the default value will be used. [ProxyIP tools][2] |
| `PLACEMENT_MODE` | Optional | `off` | Worker [Placement][5] mode: `off`, `smart`, `region`, `host`, or `hostname`. Can also be picked per-run from the "Run workflow" dropdown when triggering the workflow manually. |
| `PLACEMENT_PROVIDER` | Optional | `aws` | Only used when `PLACEMENT_MODE` is `region`: `aws`, `gcp`, or `azure`. |
| `PLACEMENT_REGION` | Optional | - | Only used when `PLACEMENT_MODE` is `region`: a region code for the chosen provider, e.g. `us-east-1` (AWS), `us-east4` (GCP), `westeurope` (Azure). |
| `PLACEMENT_HOST` | Optional | - | Only used when `PLACEMENT_MODE` is `host`: a `host:port` Cloudflare probes over TCP, e.g. `db.example.com:5432`. |
| `PLACEMENT_HOSTNAME` | Optional | - | Only used when `PLACEMENT_MODE` is `hostname`: a hostname Cloudflare probes over HTTP, e.g. `api.example.com`. |

![rain]

<br/>

### $${\color{#94A3B8}\Large Required \space Information}$$

_The following two secrets are **required** and must be obtained from your own [Cloudflare account][3]_

- _`CLOUDFLARE_API_TOKEN`_
- _`CLOUDFLARE_ACCOUNT_ID`_

> [_**More details**_][4]

<br/>

### $${\color{#94A3B8}\Large Note}$$

> The API Token must include permission to **Edit Workers**. Otherwise, the deployment workflow will fail.  
>  
> Once these secrets have been added, the GitHub Actions workflow is ready to deploy.

<br/>

## $${\color{#94A3B8}\Large Multi \space Account \space Deployment}$$

_This Worker can be deployed to up to 4 separate Cloudflare accounts from the same run._

On the **Run workflow** form (Actions tab → Deploy Worker (Multi-Account) → Run workflow), the first four fields are checkboxes — one per account "slot" — labelled `Deploy to Account 1` through `Deploy to Account 4`. Tick every slot you want deployed; each ticked slot deploys in parallel, using that slot's own secrets. You can rename these checkbox labels in the workflow file to your own account names (e.g. "Deploy to Personal", "Deploy to Client A").

A plain `git push` to `main` (no form filled in) always deploys to slot 1 only, same as a single-account setup.

**Slot 1 uses the plain, unsuffixed secret names** (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, ...) — exactly like a normal single-account setup, so nothing changes for slot 1 if you're only deploying to one account. **Slots 2 and up use the same names with a `_N` suffix**, where `N` is the slot number:

| **Slot** | **Secret (required)** | **Secret / Variable (optional)** |
| :--: | :---- | :---- |
| 1 | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | `UUID`, `PROXYIP`, `WORKERNAME`, `CLOUDFLARE_ACCOUNT_LABEL` (variable) |
| 2 | `CLOUDFLARE_API_TOKEN_2`, `CLOUDFLARE_ACCOUNT_ID_2` | `UUID_2`, `PROXYIP_2`, `WORKERNAME_2`, `CLOUDFLARE_ACCOUNT_2_LABEL` (variable) |
| 3 | `CLOUDFLARE_API_TOKEN_3`, `CLOUDFLARE_ACCOUNT_ID_3` | `UUID_3`, `PROXYIP_3`, `WORKERNAME_3`, `CLOUDFLARE_ACCOUNT_3_LABEL` (variable) |
| 4 | `CLOUDFLARE_API_TOKEN_4`, `CLOUDFLARE_ACCOUNT_ID_4` | `UUID_4`, `PROXYIP_4`, `WORKERNAME_4`, `CLOUDFLARE_ACCOUNT_4_LABEL` (variable) |

A slot that isn't ticked — or whose required secrets were never set — is simply skipped, so leaving slots 2–4 empty is harmless; only slot 1 needs to be configured for a normal single-account setup.

`CLOUDFLARE_ACCOUNT_LABEL` / `CLOUDFLARE_ACCOUNT_N_LABEL` is a repository **Variable**, not a Secret (Settings → Secrets and variables → Actions → **Variables** tab), since it's just a human-readable name — e.g. `Personal`, `Client-A` — shown in the deploy step name and the run summary. It defaults to `Account N` if left unset.

To add a 5th (or further) account slot, copy one `account_N` block in the workflow's `workflow_dispatch` inputs, bump every `N` in it, add a matching `SEL_N` line and `add N` check in the **Build account matrix** step, and add that account's two required secrets (as `CLOUDFLARE_API_TOKEN_N` / `CLOUDFLARE_ACCOUNT_ID_N` — the unsuffixed names are reserved for slot 1).

### To add a new Cloudflare account:

1. Go to your repository → **Settings** → **Secrets and variables** → **Actions**.
2. Add `CLOUDFLARE_API_TOKEN_N` and `CLOUDFLARE_ACCOUNT_ID_N` as new **Secrets**, where `N` is the next free slot number (`2`, `3`, `4`, ...) — slot 1 uses the plain, unsuffixed names instead.
3. _(Optional)_ Add `CLOUDFLARE_ACCOUNT_N_LABEL` as a new **Variable** with a friendly name for that account.
4. _(Optional)_ Add `UUID_N`, `PROXYIP_N`, `WORKERNAME_N` if this account should use different values than the shared/default ones.
5. On the next manual run, tick that account's checkbox on the "Run workflow" form.

[1]: https://www.uuidgenerator.net
[2]: https://github.com/NiREvil/vless/blob/main/sub/ProxyIP.md
[3]: https://dash.cloudflare.com/?to=/:account/api-tokens/create
[4]: https://diana-cl.github.io/Diana-Cl/en/topics/zizifn#token-time
[fa]: https://diana-cl.github.io/Diana-Cl/topics/zizifn
[en]: https://diana-cl.github.io/Diana-Cl/en/topics/zizifn
[rain]: https://github.com/NiREvil/vless/assets/126243832/1aca7f5d-6495-44b7-aced-072bae52f256
[5]: https://developers.cloudflare.com/workers/configuration/placement/
