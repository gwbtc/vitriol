#!/usr/bin/env bash
#
# Install Groundwire commit signing from a ship running %vitriol.
#
# Usage:
#   curl -fsSL http://<your-ship>/vitriol/install.sh | bash -s -- --local --code <code>
#   curl -fsSL http://<your-ship>/vitriol/install.sh | bash -s -- --global --cookie <cookie>
#
# Options:
#   --local                  Configure only the current git repo.
#   --global                 Configure the user's global git config.
#   --endpoint <url>         Override the vitriol endpoint baked into this script.
#   --code <code>            Exchange an Eyre +code for an auth cookie.
#   --cookie <cookie>        Use an existing urbauth cookie.
#   --maintainer <url> [cookie]
#                            Configure a maintainer vitriol endpoint and optional cookie.
#

set -euo pipefail

DEFAULT_ENDPOINT="${DEFAULT_ENDPOINT:-${VITRIOL_ENDPOINT:-}}"
SIGNER_PATH=""
SCOPE="--local"
ENDPOINT=""
TOKEN=""
LOGIN_CODE=""
MAINTAINER_ENDPOINT=""
MAINTAINER_TOKEN=""

usage() {
  printf '%s\n' \
    "Install Groundwire commit signing from a ship running %vitriol." \
    "" \
    "Usage:" \
    "  curl -fsSL http://<your-ship>/vitriol/install.sh | bash -s -- --local --code <code>" \
    "  curl -fsSL http://<your-ship>/vitriol/install.sh | bash -s -- --global --cookie <cookie>" \
    "" \
    "Options:" \
    "  --local                  Configure only the current git repo." \
    "  --global                 Configure the user's global git config." \
    "  --endpoint <url>         Override the vitriol endpoint baked into this script." \
    "  --code <code>            Exchange an Eyre +code for an auth cookie." \
    "  --cookie <cookie>        Use an existing urbauth cookie." \
    "  --maintainer <url> [cookie]" \
    "                           Configure a maintainer vitriol endpoint and optional cookie."
}

die() {
  echo "install.sh: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

trim_slash() {
  printf '%s' "${1%/}"
}

origin_from_endpoint() {
  printf '%s\n' "$1" | sed -E 's#^(https?://[^/]+).*#\1#'
}

cookie_from_code() {
  local endpoint="$1"
  local code="$2"
  local origin
  origin="$(origin_from_endpoint "$endpoint")"

  curl -fsS -i "${origin}/~/login" \
    -X POST \
    -d "password=${code}" |
    awk 'tolower($0) ~ /^set-cookie:/ {
      sub(/\r$/, "")
      if (match($0, /urbauth-[^=]+=[^;[:space:]]+/)) {
        print substr($0, RSTART, RLENGTH)
        exit
      }
    }'
}

ship_slug() {
  local endpoint="$1"
  local token="$2"
  local json ship fallback first last

  json="$(curl -fsS -H "Cookie: ${token}" "${endpoint}/pubkey" 2>/dev/null || true)"
  ship="$(printf '%s\n' "$json" | sed -nE 's/.*"ship"[[:space:]]*:[[:space:]]*"~?([^"]+)".*/\1/p' | head -n 1)"

  if [ -z "$ship" ]; then
    fallback="$(printf '%s\n' "$endpoint" | sed -E 's#^https?://##; s#/vitriol/?$##; s#[^A-Za-z0-9]+#_#g; s#^_+##; s#_+$##')"
    ship="${fallback:-ship}"
  fi

  ship="${ship#~}"
  ship="$(printf '%s\n' "$ship" | sed -E 's#[^A-Za-z0-9-]+#-#g; s#^-+##; s#-+$##')"

  if printf '%s\n' "$ship" | grep -q -- '--'; then
    first="${ship%%-*}"
    last="${ship##*-}"
    printf '%s_%s\n' "$first" "$last"
    return
  fi

  printf '%s\n' "$ship" | tr '-' '_' | sed -E 's#_+#_#g; s#^_+##; s#_+$##'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --local)
      SCOPE="--local"
      shift
      ;;
    --global)
      SCOPE="--global"
      shift
      ;;
    --endpoint)
      [ $# -ge 2 ] || die "--endpoint requires a URL"
      ENDPOINT="$2"
      shift 2
      ;;
    --code)
      [ $# -ge 2 ] || die "--code requires a login code"
      LOGIN_CODE="$2"
      shift 2
      ;;
    --cookie)
      [ $# -ge 2 ] || die "--cookie requires an auth cookie"
      TOKEN="$2"
      shift 2
      ;;
    --maintainer)
      [ $# -ge 2 ] || die "--maintainer requires a URL"
      MAINTAINER_ENDPOINT="$(trim_slash "$2")"
      shift 2
      if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
        MAINTAINER_TOKEN="$1"
        shift
      fi
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

need_cmd curl
need_cmd git
need_cmd awk
need_cmd sed
need_cmd jq

ENDPOINT="$(trim_slash "${ENDPOINT:-$DEFAULT_ENDPOINT}")"
[ -n "$ENDPOINT" ] || die "missing endpoint; pass --endpoint <url>"

case "$ENDPOINT" in
  */vitriol) ;;
  *) ENDPOINT="${ENDPOINT}/vitriol" ;;
esac

if [ -n "$LOGIN_CODE" ] && [ -z "$TOKEN" ]; then
  TOKEN="$(cookie_from_code "$ENDPOINT" "$LOGIN_CODE")"
  [ -n "$TOKEN" ] || die "could not exchange --code for an Eyre cookie"
fi

SLUG="$(ship_slug "$ENDPOINT" "$TOKEN")"
INSTALL_DIR="${HOME}/.groundwire/${SLUG}/vitriol"
SIGNER_PATH="${INSTALL_DIR}/gpg"
TMP_SIGNER="${SIGNER_PATH}.$$"

cleanup() {
  rm -f "$TMP_SIGNER"
}
trap cleanup EXIT

mkdir -p "$INSTALL_DIR"
curl -fsS -H "Cookie: ${TOKEN}" "${ENDPOINT}/groundwire-sign" -o "$TMP_SIGNER"
chmod 700 "$TMP_SIGNER"
mv "$TMP_SIGNER" "$SIGNER_PATH"

git config "$SCOPE" gpg.program "$SIGNER_PATH"
git config "$SCOPE" commit.gpgsign true
git config "$SCOPE" groundwire.sign-endpoint "$ENDPOINT"

if [ -n "$TOKEN" ]; then
  git config "$SCOPE" groundwire.sign-token "$TOKEN"
fi

if [ -n "$MAINTAINER_ENDPOINT" ]; then
  git config "$SCOPE" groundwire.maintainer-endpoint "$MAINTAINER_ENDPOINT"
  if [ -n "$MAINTAINER_TOKEN" ]; then
    git config "$SCOPE" groundwire.maintainer-token "$MAINTAINER_TOKEN"
  fi
fi

echo "Groundwire commit signing configured."
echo "  scope:                    ${SCOPE#--}"
echo "  gpg.program:              $SIGNER_PATH"
echo "  groundwire.sign-endpoint: $ENDPOINT"
echo "  commit.gpgsign:           true"
if [ -n "$MAINTAINER_ENDPOINT" ]; then
  echo "  groundwire.maintainer-endpoint: $MAINTAINER_ENDPOINT"
fi
