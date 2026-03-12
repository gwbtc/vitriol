#!/usr/bin/env bash
#
# Install Groundwire commit signing.
#
# Usage:
#   ./install.sh <ship-url> [auth-cookie]
#
# This configures git globally to sign all commits with your Groundwire key.
# Your ship must be running the %vitriol agent with a signing key configured.
#
# Example:
#   ./install.sh http://localhost:8080/vitriol "urbauth-~zod=0v5.abc..."
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIGN_PROGRAM="${SCRIPT_DIR}/groundwire-sign"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <ship-url> [auth-cookie]"
  echo ""
  echo "  ship-url     Base URL of your ship's vitriol endpoint (e.g. http://localhost:8080/vitriol)"
  echo "  auth-cookie  Auth cookie for your ship (e.g. urbauth-~zod=0v5.abc...)"
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
