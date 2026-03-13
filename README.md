```
    .        .        .        .        .        .

    __      __ _  _____  ____   _  ___   _
    \ \    / /| ||_   _||  _ \ | |/ _ \ | |
     \ \  / / | |  | |  | |_) || | | | || |
      \ \/ /  | |  | |  |    / | | |_| || |___
       \  /   |_|  |_|  |_|\_\ |_|\___/ |_____|
        \/

    '        '        '        '        '        '
```

> *Visita Interiora Terrae Rectificando Invenies Occultum Lapidem*

Gate GitHub PRs to contributors with on-chain [Groundwire](https://groundwire.network) identities — and optionally require ecash payment per PR.

Every commit is signed with the contributor's ship's Ed25519 networking key — the same key attested on-chain via a Groundwire inscription. A CI check verifies each signature against the signer's on-chain key by asking a Groundwire ship to look it up in Jael.

Maintainers can set a sats-per-PR price. Committers load their wallet with sats from a Cashu mint via Lightning, and the right number of ecash tokens are automatically included with each signature. The maintainer's ship NUT-03 swaps the tokens to verify their value before passing CI.

## How it works

```
contributor's ship          GitHub Actions          maintainer's ship
       |                         |                        |
  signs commit             extracts sig from          verifies sig
  with Ed25519          gpgsig header, sends         against signer's
  networking key        to CI ship for check         on-chain pass
       |                         |                        |
  [ring + wallet]           [workflow]              [Jael + NUT-03]
```

Four pieces:

1. **`hooks/groundwire-sign`** — custom `gpg.program` that sends commit content to the contributor's ship for signing, fetches the maintainer's price, and includes ecash tokens if required
2. **`hooks/install.sh`** — one-line setup for contributors
3. **`desk/`** — Urbit `%vitriol` Gall agent that handles signing, verification, ecash wallet, and admin UI
4. **`.github/workflows/groundwire-verify.yml`** — GitHub Action that gates PRs on valid Groundwire signatures

## Ship setup

The `%vitriol` desk needs to be installed on two ships:

- **Committer ship** — the contributor's local ship, signs commits and holds ecash wallet
- **Maintainer ship** — a publicly reachable ship used by CI to verify signatures, receive ecash, and manage the ban list

Both run the same agent. The committer uses `/sign` (needs access to its own private key via Jael). The maintainer uses `/verify-commit` (reads the signer's public key from its own Jael, populated by `%ord-watcher`).

### Install the desk

On each ship, in dojo:

```
|merge %vitriol our %base
|mount %vitriol
```

Copy the desk files into the mounted directory:

```bash
cp -r desk/* <pier>/vitriol/
```

Back in dojo, commit and install:

```
|commit %vitriol
|install our %vitriol
```

The agent binds to `/vitriol` on Eyre on init. Verify it's running:

```bash
curl -s http://<ship-url>/vitriol/pubkey -H "Cookie: <auth-cookie>"
```

You should see the ship's pass, life, and @p.

### Admin panel

Visit `http://<ship-url>/vitriol/admin` (requires auth cookie) to:

- **Committer settings:** configure a Cashu mint, load sats via Lightning, view wallet balance
- **Maintainer settings:** toggle payment requirement, set sats-per-PR price, manage ban list, view ecash encryption pubkey

A landing page at `http://<ship-url>/vitriol` describes the app and lists all endpoints.

### Endpoints

#### Signing & verification

| Method | Path | Description |
|--------|------|-------------|
| POST | `/vitriol/sign` | Sign commit content with networking key. Accepts optional `sats_required` to include ecash tokens from wallet. |
| POST | `/vitriol/verify-commit` | Verify signature against signer's on-chain key. If ecash tokens are included with a `mint` URL, NUT-03 swaps them to verify value. Returns `verify_id` for polling. |
| GET | `/vitriol/verify-status/{id}` | Poll for async ecash verification result (pending/verified/failed). |

#### Identity

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vitriol/pubkey` | Ship's networking key from Jael |
| GET | `/vitriol/ecash-pubkey` | Ship's Curve25519 encryption pubkey for receiving ecash |
| GET | `/vitriol/check-id/~ship` | Check if a ship is attested on-chain |

#### Ecash & payment

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vitriol/sats-per-pr` | Maintainer's price per PR in sats |
| GET | `/vitriol/banned` | List banned ships |
| POST | `/vitriol/ban` | Ban a ship (JSON: `{"ship":"~sampel"}`) |
| POST | `/vitriol/unban` | Unban a ship (JSON: `{"ship":"~sampel"}`) |

#### Admin UI (form actions)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vitriol` | Landing page |
| GET | `/vitriol/admin` | Admin panel |
| POST | `/vitriol/admin/set-mint` | Set Cashu mint URL |
| POST | `/vitriol/admin/load-sats` | Request Lightning invoice to load wallet |
| POST | `/vitriol/admin/toggle-payment` | Toggle ecash payment requirement |
| POST | `/vitriol/admin/set-price` | Set sats-per-PR price |
| POST | `/vitriol/admin/ban` | Ban a ship (form) |
| POST | `/vitriol/admin/unban` | Unban a ship (form) |
| POST | `/vitriol/admin/withdraw` | Withdraw tokens to Lightning (mint + invoice) |

## Contributor setup

### Quick install

```bash
./hooks/install.sh <your-ship-url>/vitriol "<auth-cookie>"
```

To also configure ecash payment to a maintainer:

```bash
./hooks/install.sh <your-ship-url>/vitriol "<auth-cookie>" \
  --maintainer <maintainer-ship-url>/vitriol "<maintainer-auth-cookie>"
```

This configures git globally to sign all commits with your Groundwire key. The hook will automatically fetch the maintainer's price and include the right ecash tokens.

### Manual install

```bash
git config --global gpg.program /path/to/hooks/groundwire-sign
git config --global commit.gpgsign true
git config --global groundwire.sign-endpoint <your-ship-url>/vitriol
git config --global groundwire.sign-token "<auth-cookie>"

# Optional: maintainer ecash
git config --global groundwire.maintainer-endpoint <maintainer-url>/vitriol
git config --global groundwire.maintainer-token "<maintainer-auth-cookie>"
```

To configure per-repo instead of globally, drop the `--global` flag.

### Loading your wallet

1. Open `http://<your-ship-url>/vitriol/admin`
2. Under **Committer > Wallet**, enter a Cashu mint URL and click **Set mint**
3. Enter the amount of sats to load and click **Get invoice**
4. Pay the Lightning invoice — the agent polls the mint and stores the tokens automatically

### Test signing

```bash
git commit --allow-empty -m "test groundwire signing"
git cat-file commit HEAD
```

You should see a `gpgsig` header containing:

```
-----BEGIN GROUNDWIRE SIGNATURE-----
signer:~your-ship
pass:<hex>
sig:<hex>
ecash-pubkey:<hex>
ecash-amount:100
ecash-ciphertext:<hex>
ecash-ephemeral-pubkey:<hex>
ecash-mac:<hex>
-----END GROUNDWIRE SIGNATURE-----
```

The `ecash-*` fields are only present when a maintainer price is configured and the committer has tokens. Tokens are encrypted with the maintainer's Curve25519 pubkey — the ciphertext contains both the mint URL and the token proofs.

## Maintainer setup

### Requiring payment

1. Open `http://<your-ship-url>/vitriol/admin`
2. Under **Maintainer > Ecash payment**, click **Enable** to require payment
3. Set the **sats per PR** price
4. Share your ship URL with contributors so they can configure the `--maintainer` flag

### How token verification works

When a committer includes ecash tokens in their signature:

1. The CI workflow sends the tokens to the maintainer's `/verify-commit` endpoint
2. The maintainer's agent fetches the keyset keys from the Cashu mint
3. It performs a NUT-03 swap — exchanging the committer's tokens for fresh ones
4. If the swap succeeds, the tokens are real and the value is confirmed
5. The swapped tokens are stored in the maintainer's wallet
6. The CI polls `/verify-status/{id}` until the swap completes

This ensures the maintainer never accepts invalid or already-spent tokens.

### Token selection (committer side)

When the hook fetches a maintainer's `sats-per-pr` price, it passes `sats_required` to the committer's `/sign` endpoint. The agent selects tokens from the wallet using these rules:

- Total must be **>= required**
- Total must be **<= 110% of required** (no more than 10% overpayment)
- If no valid combination exists, the sign request fails with an error

This prevents accidentally overpaying while accommodating Cashu's power-of-2 denominations.

## CI setup

### Repository secrets

Add these secrets to your GitHub repo (Settings > Secrets and variables > Actions):

| Secret | Value |
|--------|-------|
| `GROUNDWIRE_ENDPOINT` | Base URL of the CI's verification ship (e.g. `https://my-ship.example.com`) |
| `GROUNDWIRE_AUTH` | Auth cookie for the CI ship (e.g. `urbauth-~ship=0v5.xxxxx`) |

### Workflow

Copy `.github/workflows/groundwire-verify.yml` into your repo. It runs on every PR and:

1. Iterates over all commits in the PR
2. Extracts the Groundwire signature from each commit's `gpgsig` header
3. Sends the signature, signer @p, and commit payload to the CI ship's `/vitriol/verify-commit`
4. The CI ship looks up the signer's on-chain public key in Jael and verifies the Ed25519 signature
5. If ecash tokens are present, the CI ship NUT-03 swaps them at the mint to verify value
6. Fails the check and comments on the PR if any commit is unsigned, unverified, or underpaid

### Requirements

- The CI ship must be running `%ord-watcher` (or equivalent) so that Jael has the signer's on-chain key
- The CI ship must be publicly reachable from GitHub Actions runners
- The signer must have a Groundwire identity attested on-chain

## Architecture

### Desk contents

```
desk/
  app/vitriol.hoon      — main Gall agent (signing, verification, wallet, HTTP)
  lib/vitriol-ui.hoon   — Sail admin UI and landing page
  lib/cashu.hoon        — Cashu wallet operations (NUT-00/03/04/05 BDHKE)
  lib/server.hoon       — HTTP response helpers
  sur/vitriol.hoon      — type definitions (cashu-proof, pending-mint-quote, pending-verify)
  sys.kelvin            — compatible with kelvin 408 and 409
```

### Agent state

The agent maintains:

- **ecash-key** — Curve25519 keypair for ecash encryption
- **banned** — set of @p's rejected during verification
- **require-payment** — whether ecash payment is required for verify-commit
- **sats-per-pr** — price per PR in sats (optional)
- **mint** — configured Cashu mint URL (optional)
- **wallet** — map of mint URL to list of cashu proofs
- **mint-keysets** — cached keyset keys from mints
- **pending-mints** — in-flight Lightning invoice → token flows
- **pending-verifies** — in-flight NUT-03 swap verifications

### Cryptography

Commits are signed with the ship's Ed25519 networking key — the same key stored in Jael and attested on-chain via a Groundwire Bitcoin inscription.

- **Signing:** the agent extracts the 32-byte signing seed from the ship's `ring` (Jael `/vein` scry) and signs with `sign-octs:ed:crypto`
- **Verification:** the agent extracts the 32-byte signing public key from the signer's `pass` (Jael `/pynt` scry) and verifies with `veri-octs:ed:crypto`
- **Ecash encryption:** Curve25519 keypair via `scalarmult-base:ed:crypto` for future DH key exchange (`shar:ed:crypto`)
- **Token operations:** BDHKE (Blind Diffie-Hellman Key Exchange) per Cashu NUT-00, using secp256k1 via `fo` modular arithmetic

Key format (Suite B):

```
pass: [1 byte 'b'] [32 bytes sgn pubkey] [32 bytes cry pubkey]
ring: [1 byte 'B'] [32 bytes sgn seed]   [32 bytes cry seed]
```

## Security

- All HTTP endpoints require Eyre authentication (403 for unauthenticated requests)
- No key material is generated or stored by the agent for signing — it uses whatever Jael has
- Ecash tokens are verified via NUT-03 swap before acceptance (prevents double-spending and invalid tokens)
- The ban list is checked before signature verification
- Token selection enforces a 110% cap to prevent accidental overpayment
