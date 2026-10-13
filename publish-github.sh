#!/usr/bin/env bash
# One-command publication fallback for the GitHub connector's missing repo-create action.
set -euo pipefail

OWNER="TAY0123"
NAME="bleclip-rs"
REPO="${OWNER}/${NAME}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

for command_name in git gh; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Missing %s. Install it before publishing.\n' "$command_name" >&2
    exit 1
  fi
done

if ! gh auth status >/dev/null 2>&1; then
  printf 'GitHub CLI is not authenticated. Run: gh auth login\n' >&2
  exit 1
fi

CONNECTED_USER="$(gh api user --jq .login)"
if [[ "$CONNECTED_USER" != "$OWNER" ]]; then
  printf 'Authenticated as %s, expected %s. Use: gh auth switch -u %s\n' "$CONNECTED_USER" "$OWNER" "$OWNER" >&2
  exit 1
fi

if gh repo view "$REPO" --json name >/dev/null 2>&1; then
  printf 'Repository %s already exists; refusing to overwrite/push automatically.\n' "$REPO" >&2
  exit 1
fi

if [[ ! -d .git ]]; then
  git init -b main
fi
if [[ -n "$(git remote)" ]]; then
  printf 'Existing git remotes found; refusing to alter them.\n' >&2
  exit 1
fi

# Whitelist publication files. .gitignore excludes *.key and build products.
git add -- .github .gitignore Cargo.toml LICENSE README.md SECURITY.md src publish-github.sh publish-github.ps1
if ! git diff --cached --quiet; then
  git commit -m 'Initial public release: encrypted multi-peer BLE clipboard sync'
fi

gh repo create "$REPO" \
  --public \
  --description 'Rust serverless encrypted multi-peer BLE clipboard sync for Windows and Linux (experimental)' \
  --source . \
  --remote origin \
  --push

printf 'Published: https://github.com/%s\n' "$REPO"
