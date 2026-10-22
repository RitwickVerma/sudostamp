#!/bin/sh
# One-time setup of a checkout: use the repository's git hooks (secret scan before every commit).
#   scripts/setup-dev.sh
set -eu
cd "$(dirname "$0")/.."
git config core.hooksPath .githooks
echo "git hooks: .githooks (pre-commit runs tools/check-secrets.py --staged)"
