#!/usr/bin/env bash
#
# Install Groundwire commit signing.
#
# Usage:
#   ./install.sh <sign-endpoint> [auth-token]
#
# This configures git globally to sign all commits with your Groundwire key.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIGN_PROGRAM="${SCRIPT_DIR}/groundwire-sign"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <sign-endpoint> [auth-token]"
  echo ""
  echo "  sign-endpoint  URL of your Groundwire signing service"
  echo "  auth-token     Optional auth token"
  exit 1
fi

ENDPOINT="$1"
TOKEN="${2:-}"

chmod +x "$SIGN_PROGRAM"

git config --global gpg.program "$SIGN_PROGRAM"
git config --global commit.gpgsign true
git config --global groundwire.sign-endpoint "$ENDPOINT"

if [ -n "$TOKEN" ]; then
  git config --global groundwire.sign-token "$TOKEN"
fi

echo "Groundwire commit signing configured."
echo "  gpg.program:              $SIGN_PROGRAM"
echo "  groundwire.sign-endpoint: $ENDPOINT"
echo "  commit.gpgsign:           true"
echo ""
echo "All future commits will be signed with your Groundwire key."
