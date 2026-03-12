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

Gate GitHub PRs to contributors with on-chain [Groundwire](https://groundwire.network) identities.

Every commit is signed with the contributor's ship's Ed25519 networking key — the same key attested on-chain via a Groundwire inscription. A CI check verifies each signature against the signer's on-chain key by asking a Groundwire ship to look it up in Jael.

## How it works

```
contributor's ship          GitHub Actions          CI's ship
       |                         |                      |
  signs commit             extracts sig from        verifies sig
  with Ed25519          gpgsig header, sends       against signer's
  networking key        to CI ship for check       on-chain pass
       |                         |                      |
    [ring]                   [workflow]               [Jael]
```

Three pieces:

1. **`hooks/groundwire-sign`** — custom `gpg.program` that sends commit content to the contributor's ship for signing
2. **`desk/`** — Urbit `%vitriol` Gall agent that handles signing and verification
3. **`.github/workflows/groundwire-verify.yml`** — GitHub Action that gates PRs on valid Groundwire signatures

## Ship setup

The `%vitriol` desk needs to be installed on two ships:

- **Signing ship** — the contributor's local ship, signs commits
- **Verification ship** — a publicly reachable ship used by CI to verify signatures against on-chain keys

Both run the same agent. The signing ship uses the `/sign` endpoint (needs access to its own private key via Jael). The CI ship uses `/verify-commit` (reads the signer's public key from its own Jael, populated by `%ord-watcher`).

### Install the desk

On each ship, in dojo:

```
|merge %vitriol our %base
|mount %vitriol
```

Then copy the desk files from this repo into the mounted directory (replace `<pier>` with the ship's pier path):

```bash
cp desk/app/vitriol.hoon <pier>/vitriol/app/vitriol.hoon
cp desk/lib/server.hoon <pier>/vitriol/lib/server.hoon
cp desk/sur/vitriol.hoon <pier>/vitriol/sur/vitriol.hoon
cp desk/desk.bill <pier>/vitriol/desk.bill
cp desk/sys.kelvin <pier>/vitriol/sys.kelvin
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

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vitriol/pubkey` | Ship's networking key from Jael |
| POST | `/vitriol/sign` | Sign commit content with networking key |
| POST | `/vitriol/verify-commit` | Verify signature against signer's on-chain key |
| GET | `/vitriol/check-id/~ship` | Check if a ship is attested on-chain |

## Contributor setup

### Quick install

```bash
./hooks/install.sh <your-ship-url>/vitriol "<auth-cookie>"
```

This configures git globally to sign all commits with your Groundwire key.

### Manual install

```bash
git config --global gpg.program /path/to/hooks/groundwire-sign
git config --global commit.gpgsign true
git config --global groundwire.sign-endpoint <your-ship-url>/vitriol
git config --global groundwire.sign-token "<auth-cookie>"
```

To configure per-repo instead of globally, drop the `--global` flag.

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
-----END GROUNDWIRE SIGNATURE-----
```

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
5. Fails the check and comments on the PR if any commit is unsigned or unverified

### Requirements

- The CI ship must be running `%ord-watcher` (or equivalent) so that Jael has the signer's on-chain key
- The CI ship must be publicly reachable from GitHub Actions runners
- The signer must have a Groundwire identity attested on-chain

## Cryptography

Commits are signed with the ship's Ed25519 networking key — the same key stored in Jael and attested on-chain via a Groundwire Bitcoin inscription.

- **Signing:** the agent extracts the 32-byte signing seed from the ship's `ring` (Jael `/vein` scry) and signs with `sign-octs:ed:crypto`
- **Verification:** the agent extracts the 32-byte signing public key from the signer's `pass` (Jael `/deed` scry) and verifies with `veri-octs:ed:crypto`

Key format (Suite B):

```
pass: [1 byte 'b'] [32 bytes sgn pubkey] [32 bytes cry pubkey]
ring: [1 byte 'B'] [32 bytes sgn seed]   [32 bytes cry seed]
```

No key material is generated or stored by the agent — it uses whatever Jael has.
