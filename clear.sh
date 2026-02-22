#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  ./clear.sh [--all] [--dry-run]

What it clears (default):
  - build/            (CMake/Ninja build directories)
  - out/              (packaging output, zips, staged module dir)

With --all, also clears:
  - tools/ninja-*/    (downloaded portable ninja)

Options:
  --dry-run   Print what would be removed, without deleting.
  --all       Also remove downloaded build tools (safe to re-download).
  -h|--help   Show this help.
EOF
}

DRY_RUN=0
ALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --all) ALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "[ERROR] Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

say() { echo "[clear] $*"; }

rm_path() {
  local p="$1"
  # only allow removing inside project root
  local abs="$ROOT_DIR/$p"
  abs="$(cd "$ROOT_DIR" && realpath -m "$p")"
  if [[ "$abs" != "$ROOT_DIR"* ]]; then
    echo "[ERROR] Refusing to delete outside project root: $abs" >&2
    exit 3
  fi
  if [[ "$abs" == "$ROOT_DIR" ]]; then
    echo "[ERROR] Refusing to delete project root" >&2
    exit 3
  fi

  if [[ -e "$abs" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      say "would remove: $abs"
    else
      say "removing: $abs"
      rm -rf --one-file-system "$abs"
    fi
  else
    say "skip (not found): $abs"
  fi
}

say "project: $ROOT_DIR"
rm_path "build"
rm_path "out"

if [[ "$ALL" -eq 1 ]]; then
  # Remove downloaded ninja bundles but keep tools/ for future use.
  shopt -s nullglob
  for d in "$ROOT_DIR"/tools/ninja-*; do
    if [[ -d "$d" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        say "would remove: $d"
      else
        say "removing: $d"
        rm -rf --one-file-system "$d"
      fi
    fi
  done
  shopt -u nullglob
fi

say "done"

