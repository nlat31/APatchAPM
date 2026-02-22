#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"

usage() {
  cat <<'EOF'
Usage:
  ./compile_hook.sh                 # compile Hooker.java for all modules
  MODULES="envcloak sample" ./compile_hook.sh

What it does:
  - For each module under modules/<id>/java/Hooker.java
    compile to modules/<id>/magisk/classes.dex
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

# Locate Android SDK Build Tools
if [ -z "${ANDROID_HOME}" ]; then
    echo "ANDROID_HOME not set. Using default search paths..."
    POSSIBLE_SDK_LOCATIONS=(
        "$HOME/Android/Sdk"
        "$HOME/Library/Android/sdk"
        "/usr/lib/android-sdk"
    )
    for loc in "${POSSIBLE_SDK_LOCATIONS[@]}"; do
        if [ -d "$loc" ]; then
            ANDROID_HOME="$loc"
            break
        fi
    done
fi

if [ -z "${ANDROID_HOME}" ]; then
    echo "Error: Android SDK not found. Please set ANDROID_HOME."
    exit 1
fi

# Find d8 or dx
D8_BIN=""
DX_BIN=""

# Check build-tools
BUILD_TOOLS_DIR="$ANDROID_HOME/build-tools"
if [ -d "$BUILD_TOOLS_DIR" ]; then
    LATEST_BUILD_TOOLS=$(ls -1 "$BUILD_TOOLS_DIR" | sort -V | tail -n 1)
    if [ -n "$LATEST_BUILD_TOOLS" ]; then
        if [ -f "$BUILD_TOOLS_DIR/$LATEST_BUILD_TOOLS/d8" ]; then
            D8_BIN="$BUILD_TOOLS_DIR/$LATEST_BUILD_TOOLS/d8"
        elif [ -f "$BUILD_TOOLS_DIR/$LATEST_BUILD_TOOLS/dx" ]; then
            DX_BIN="$BUILD_TOOLS_DIR/$LATEST_BUILD_TOOLS/dx"
        fi
    fi
fi

if [ -z "$D8_BIN" ] && [ -z "$DX_BIN" ]; then
    echo "Error: d8 or dx not found in Android SDK build-tools."
    exit 1
fi

want_module() {
  local id="$1"
  if [[ -z "${MODULES:-}" ]]; then
    return 0
  fi
  for m in ${MODULES}; do
    [[ "$m" == "$id" ]] && return 0
  done
  return 1
}

echo "Discovering modules..."
shopt -s nullglob
FOUND=0
for mod_dir in "$PROJECT_DIR"/modules/*; do
  [[ -d "$mod_dir" ]] || continue
  mod_id="$(basename "$mod_dir")"
  want_module "$mod_id" || continue

  hooker_java="$mod_dir/java/Hooker.java"
  out_dir="$mod_dir/magisk"
  [[ -f "$hooker_java" ]] || continue

  FOUND=1
  mkdir -p "$out_dir"

  echo ""
  echo "==> [$mod_id] Compiling Hooker.java"

  tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t zray_java)"
  trap 'rm -rf "$tmp_dir" 2>/dev/null || true' EXIT

  javac -source 1.8 -target 1.8 -d "$tmp_dir" "$hooker_java"

  echo "==> [$mod_id] Converting to DEX"
  if [ -n "$D8_BIN" ]; then
      # d8 expects .class/.jar/.zip as program inputs (passing a directory may fail)
      CLASS_FILES=()
      while IFS= read -r -d '' f; do CLASS_FILES+=("$f"); done < <(find "$tmp_dir" -type f -name "*.class" -print0)
      if [[ "${#CLASS_FILES[@]}" -eq 0 ]]; then
          echo "Error: no .class files produced by javac for $mod_id" >&2
          exit 1
      fi
      # d8 output directory will contain classes.dex
      "$D8_BIN" --output "$out_dir" "${CLASS_FILES[@]}"
  else
      # dx needs class files as inputs
      CLASS_FILES=()
      while IFS= read -r -d '' f; do CLASS_FILES+=("$f"); done < <(find "$tmp_dir" -type f -name "*.class" -print0)
      "$DX_BIN" --dex --output="$out_dir/classes.dex" "${CLASS_FILES[@]}"
  fi

  rm -rf "$tmp_dir" 2>/dev/null || true
  trap - EXIT

  echo "==> [$mod_id] Done: $out_dir/classes.dex"
done
shopt -u nullglob

if [[ "$FOUND" -eq 0 ]]; then
  echo "No modules with java/Hooker.java found under modules/* (or filtered out by MODULES=...)." >&2
  exit 1
fi

