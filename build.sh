#!/bin/bash
set -euo pipefail

# ================================================================
# Zygisk Modules - One-Click Build (Linux/macOS)
# ================================================================
# Usage:
#   ./build.sh
#   BUILD_TYPE=Debug ./build.sh
#   ABIS="arm64-v8a" ./build.sh
#
# Environment:
#   ANDROID_NDK  - NDK path (required or auto-detect)
#   BUILD_TYPE   - Release / Debug (default: Release)
#   API_LEVEL    - Android API Level (default: 29)
#   ABIS         - Space-separated ABI list
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { printf "\n${CYAN}==>${NC} %s\n" "$*"; }

# ========== Step 1: Check and fetch dependencies ==========
step "Checking dependencies"

DEPS_OK=true
[ -f "${PROJECT_DIR}/external/dobby/CMakeLists.txt" ] || DEPS_OK=false
[ -f "${PROJECT_DIR}/external/lsplant/lsplant/src/main/jni/CMakeLists.txt" ] || DEPS_OK=false
[ -f "${PROJECT_DIR}/external/zygisk/zygisk.hpp" ] || DEPS_OK=false
[ -f "${PROJECT_DIR}/external/CSOLoader/CMakeLists.txt" ] || DEPS_OK=false

if [ "${DEPS_OK}" = false ]; then
    info "Dependencies missing - running setup.sh ..."
    bash "${PROJECT_DIR}/setup.sh"
    [ -f "${PROJECT_DIR}/external/dobby/CMakeLists.txt" ] || error "Dobby setup failed"
    [ -f "${PROJECT_DIR}/external/lsplant/lsplant/src/main/jni/CMakeLists.txt" ] || error "lsplant setup failed"
    [ -f "${PROJECT_DIR}/external/zygisk/zygisk.hpp" ] || error "zygisk.hpp setup failed"
    [ -f "${PROJECT_DIR}/external/CSOLoader/CMakeLists.txt" ] || error "CSOLoader setup failed"
else
    info "All dependencies present"
fi

# Dobby upstream 的 trampoline asm 使用 Mach-O 的 `@PAGE/@PAGEOFF` 语法，
# Android/ELF 下会汇编失败。我们在这里做一次轻量补丁：Android 下禁用这些 asm，
# 让 Dobby 走 C++ TurboAssembler 版本（BUILD_WITH_TRAMPOLINE_ASSEMBLER）。
patch_dobby_android() {
    local dobby_dir="${PROJECT_DIR}/external/dobby"
    local cmake_file="${dobby_dir}/CMakeLists.txt"
    [ -f "${cmake_file}" ] || return 0

    command -v python3 &>/dev/null || { warn "python3 not found; skip patching Dobby (build may fail)"; return 0; }

    # Ensure we start from a clean upstream checkout (offline-friendly).
    if command -v git &>/dev/null && [ -d "${dobby_dir}/.git" ]; then
        git -C "${dobby_dir}" reset --hard >/dev/null || true
    fi

    PROJECT_DIR="${PROJECT_DIR}" python3 <<'PYEOF'
import os, re
from pathlib import Path

root = Path(os.environ["PROJECT_DIR"]) / "external" / "dobby"

def read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")

def write(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8")

# ---- Patch 0: Provide missing core/arch/Cpu.h for this Dobby snapshot ----
cpu_h = root / "source/core/arch/Cpu.h"
if not cpu_h.exists():
    cpu_h.parent.mkdir(parents=True, exist_ok=True)
    write(cpu_h, """#pragma once

#include <cstdint>

#include "core/arch/CpuRegister.h"
#include "PlatformUnifiedInterface/ExecMemory/ClearCacheTool.h"

// This repository snapshot references core/arch/Cpu.h from multiple places,
// but upstream may not ship it. Provide a minimal header to satisfy builds.

#if defined(TARGET_ARCH_ARM)
using arm_inst_t = uint32_t;
using thumb1_inst_t = uint16_t;
using thumb2_inst_t = uint32_t;
#endif

class CpuFeatures {
public:
  static void ClearCache(void *start, void *end) { ::ClearCache(start, end); }
  static void FlushICache(void *start, void *end);
};
""")

# ---- Patch 1: Fix non-existent header include ----
cpp = root / "source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc"
if cpp.exists():
    t = read(cpp)
    t = re.sub(r'(?m)^\s*#include "core/arch/Cpu\.h"\s*\n', "", t)
    write(cpp, t)

# ---- Patch 2: Fix Android include-cycle in os_arch_features.h ----
hdr = root / "common/os_arch_features.h"
if hdr.exists():
    t = read(hdr)
    if "ZrayPatch: Android make_memory_readable" not in t:
        if "<unistd.h>" not in t:
            t = re.sub(
                r'(#include "pac_kit\.h"\s*\n)',
                r'\1\n'
                r'#if defined(ANDROID)\n'
                r'#include <unistd.h>\n'
                r'#include <sys/mman.h>\n'
                r'#endif\n',
                t,
                count=1,
            )
        t = re.sub(
            r'(?s)(namespace android\s*\{\s*\ninline void make_memory_readable\([^\)]*\)\s*\{\s*\n).*?(\n\}\s*\n\}\s*// namespace android)',
            r'\1'
            '#if defined(ANDROID)\n'
            '  // ZrayPatch: Android make_memory_readable - avoid OSMemory (platform.h includes common.h -> cycle)\n'
            '  long page_size = sysconf(_SC_PAGESIZE);\n'
            '  if (page_size <= 0) return;\n'
            '  (void)size;\n'
            '  void *page = (void *)ALIGN_FLOOR(address, (size_t)page_size);\n'
            '  mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);\n'
            '#endif\n'
            r'\2',
            t,
            count=1,
        )
        write(hdr, t)

# ---- Patch 3: Fix ProcessRuntime.cc against current headers ----
pr = root / "source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc"
if pr.exists():
    t = read(pr)
    t = t.replace("return a.start < b.start;", "return a.start() < b.start();")
    t = t.replace("return (a.start < b.start);", "return a.start() < b.start();")
    t = t.replace("module.load_address_", "module.base")
    t = t.replace("module.load_address", "module.base")
    write(pr, t)

# ---- Patch 4: Fix SymbolResolver RuntimeModule field name ----
sr = root / "builtin-plugin/SymbolResolver/elf/dobby_symbol_resolver.cc"
if sr.exists():
    t = read(sr)
    t = t.replace("module.load_address", "module.base")
    write(sr, t)

# ---- Patch 5: Patch Mach-O @PAGE/@PAGEOFF asm for Android/ELF ----
asm_files = [
    root / "source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.asm",
    root / "source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_trampoline_arm64.asm",
    root / "source/TrampolineBridge/ClosureTrampolineBridge/x64/closure_bridge_x64.asm",
    root / "source/TrampolineBridge/ClosureTrampolineBridge/x64/closure_trampoline_x64.asm",
]
for p in asm_files:
    if not p.exists():
        continue
    s = read(p)
    # TOKEN@PAGE    -> TOKEN
    # TOKEN@PAGEOFF -> :lo12:TOKEN
    # TOKEN may be symbol or macro-call token (e.g., cdecl(foo)).
    s2 = re.sub(r'([A-Za-z0-9_.$()]+)@PAGEOFF', r':lo12:\1', s)
    s2 = re.sub(r'([A-Za-z0-9_.$()]+)@PAGE', r'\1', s2)

    # PIC fix for Android/ELF: direct adrp+add to a symbol in a shared library can produce non-PIC relocations.
    # Use GOT-based load for common_closure_bridge_handler.
    if p.name == "closure_bridge_arm64.asm":
        s2 = re.sub(
            r'(?m)^adrp\s+(\w+),\s*([A-Za-z0-9_.$()]+)\s*\nadd\s+\1,\s*\1,\s*:lo12:\2\s*$',
            r'adrp \1, :got:\2\nldr \1, [\1, :got_lo12:\2]',
            s2,
        )

    if s2 != s:
        write(p, s2)
PYEOF

    # Sanity checks / hard enforcement (some environments may have CRLF or unexpected formatting).
    local cpu_inc="${dobby_dir}/source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc"
    if [ -f "${cpu_inc}" ] && grep -q 'core/arch/Cpu.h' "${cpu_inc}"; then
        warn "Dobby still includes core/arch/Cpu.h; patching again..."
        DOBBY_DIR="${dobby_dir}" python3 - <<'PY'
import re
import os
from pathlib import Path
p = Path(os.environ["DOBBY_DIR"]) / "source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc"
t = p.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")
t2 = re.sub(r'(?m)^\s*#include "core/arch/Cpu\.h"\s*\n', "", t)
if t2 != t:
    p.write_text(t2, encoding="utf-8")
PY
    fi

    local os_hdr="${dobby_dir}/common/os_arch_features.h"
    if [ -f "${os_hdr}" ] && grep -q 'OSMemory::\|kReadExecute' "${os_hdr}"; then
        warn "Dobby os_arch_features.h still references OSMemory; patching again..."
        DOBBY_DIR="${dobby_dir}" python3 - <<'PY'
import re
import os
from pathlib import Path
p = Path(os.environ["DOBBY_DIR"]) / "common/os_arch_features.h"
t = p.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")
if "<unistd.h>" not in t:
    t = re.sub(
        r'(#include "pac_kit\.h"\s*\n)',
        r'\1\n#if defined(ANDROID)\n#include <unistd.h>\n#include <sys/mman.h>\n#endif\n',
        t,
        count=1,
    )
# Replace body inside namespace android::make_memory_readable
t = re.sub(
    r'(?s)(namespace android\s*\{\s*\ninline void make_memory_readable\([^\)]*\)\s*\{\s*\n).*?(\n\}\s*\n\}\s*// namespace android)',
    r'\1'
    r'#if defined(ANDROID)\n'
    r'  // ZrayPatch: Android make_memory_readable - avoid OSMemory include-cycle\n'
    r'  long page_size = sysconf(_SC_PAGESIZE);\n'
    r'  if (page_size <= 0) return;\n'
    r'  (void)size;\n'
    r'  void *page = (void *)ALIGN_FLOOR(address, (size_t)page_size);\n'
    r'  mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);\n'
    r'#endif\n'
    r'\2',
    t,
    count=1,
)
p.write_text(t, encoding="utf-8")
PY
    fi

    local pr_cc="${dobby_dir}/source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc"
    if [ -f "${pr_cc}" ] && grep -q 'a\.start < b\.start' "${pr_cc}"; then
        warn "Dobby ProcessRuntime comparator still uses a.start; patching again..."
        DOBBY_DIR="${dobby_dir}" python3 - <<'PY'
import os
from pathlib import Path
p = Path(os.environ["DOBBY_DIR"]) / "source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc"
t = p.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")
t = t.replace("return a.start < b.start;", "return a.start() < b.start();")
t = t.replace("return (a.start < b.start);", "return a.start() < b.start();")
p.write_text(t, encoding="utf-8")
PY
    fi
}

patch_dobby_android

# ========== Step 2: Locate Android NDK ==========
step "Locating Android NDK"

if [ -z "${ANDROID_NDK:-}" ]; then
    if [ -n "${ANDROID_NDK_ROOT:-}" ]; then
        ANDROID_NDK="${ANDROID_NDK_ROOT}"
    elif [ -d "${ANDROID_HOME:-}/ndk" ]; then
        ANDROID_NDK="$(ls -d "${ANDROID_HOME}/ndk"/*/ 2>/dev/null | sort -V | tail -1)"
        ANDROID_NDK="${ANDROID_NDK%/}"
    elif [ -d "${HOME}/Android/Sdk/ndk" ]; then
        ANDROID_NDK="$(ls -d "${HOME}/Android/Sdk/ndk"/*/ 2>/dev/null | sort -V | tail -1)"
        ANDROID_NDK="${ANDROID_NDK%/}"
    fi
fi

[ -n "${ANDROID_NDK:-}" ] || error "ANDROID_NDK not set. export ANDROID_NDK=/path/to/ndk"

TOOLCHAIN="${ANDROID_NDK}/build/cmake/android.toolchain.cmake"
[ -f "${TOOLCHAIN}" ] || error "Invalid NDK path: ${ANDROID_NDK}"

info "NDK: ${ANDROID_NDK}"

# ========== Step 3: Locate build tools ==========
step "Checking build tools"

CMAKE_BIN=""
if command -v cmake &>/dev/null; then
    CMAKE_BIN="cmake"
else
    SDK_CMAKE="$(find "${ANDROID_NDK}/../cmake" -name cmake -type f 2>/dev/null | sort -V | tail -1 || true)"
    if [ -n "${SDK_CMAKE}" ] && [ -x "${SDK_CMAKE}" ]; then
        CMAKE_BIN="${SDK_CMAKE}"
    else
        error "cmake not found"
    fi
fi
info "CMake: $(${CMAKE_BIN} --version | head -1)"

GENERATOR_ARGS=""

# CMake 4.x + lsplant may trigger C++20 modules capability checks.
# Ninja >= 1.11 is required, so we pick a sufficiently new ninja (or download one).
ver_ge() {
    # usage: ver_ge 1.11.0 1.8.2  -> false
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

HOST_TAG=""
case "$(uname -s)" in
    Linux*)  HOST_TAG="linux-x86_64" ;;
    Darwin*) HOST_TAG="darwin-x86_64" ;;
esac

pick_ninja() {
    local candidate ver
    for candidate in \
        "$(command -v ninja 2>/dev/null || true)" \
        "${ANDROID_NDK}/prebuilt/${HOST_TAG:-none}/bin/ninja" \
        "$(find "${ANDROID_HOME:-/nonexistent}/cmake" -path '*/bin/ninja' -type f 2>/dev/null | sort -V | tail -1 || true)" \
        "$(find "${HOME}/Android/Sdk/cmake" -path '*/bin/ninja' -type f 2>/dev/null | sort -V | tail -1 || true)"; do
        [ -n "${candidate}" ] || continue
        [ -f "${candidate}" ] || continue
        ver="$("${candidate}" --version 2>/dev/null || true)"
        [ -n "${ver}" ] || continue
        if ver_ge "1.11.0" "${ver}"; then
            echo "${candidate}"
            return 0
        fi
    done
    echo ""
    return 0
}

NINJA_BIN="$(pick_ninja)"
if [ -n "${NINJA_BIN}" ]; then
    GENERATOR_ARGS="-G Ninja -DCMAKE_MAKE_PROGRAM=${NINJA_BIN}"
    info "Generator: Ninja (${NINJA_BIN}, v$(${NINJA_BIN} --version))"
else
    step "Ninja >= 1.11 not found; downloading portable ninja..."
    NINJA_VER="1.11.1"
    TOOLS_DIR="${PROJECT_DIR}/tools/ninja-${NINJA_VER}"
    mkdir -p "${TOOLS_DIR}"

    case "$(uname -s)" in
        Linux*)  NINJA_URL="https://github.com/ninja-build/ninja/releases/download/v${NINJA_VER}/ninja-linux.zip" ;;
        Darwin*) NINJA_URL="https://github.com/ninja-build/ninja/releases/download/v${NINJA_VER}/ninja-mac.zip" ;;
        *) error "Unsupported host OS for auto-downloading ninja" ;;
    esac

    if command -v curl &>/dev/null; then
        curl -fsSL "${NINJA_URL}" -o "${TOOLS_DIR}/ninja.zip"
    elif command -v wget &>/dev/null; then
        wget -q "${NINJA_URL}" -O "${TOOLS_DIR}/ninja.zip"
    else
        error "curl or wget required to auto-download ninja. Alternatively: sudo apt install ninja-build"
    fi

    if command -v unzip &>/dev/null; then
        unzip -o -q "${TOOLS_DIR}/ninja.zip" -d "${TOOLS_DIR}"
    else
        error "unzip required to extract ninja.zip (sudo apt install unzip)"
    fi

    chmod +x "${TOOLS_DIR}/ninja" 2>/dev/null || true
    [ -f "${TOOLS_DIR}/ninja" ] || error "Failed to extract ninja binary"
    info "Downloaded ninja: ${TOOLS_DIR}/ninja (v$(${TOOLS_DIR}/ninja --version))"

    GENERATOR_ARGS="-G Ninja -DCMAKE_MAKE_PROGRAM=${TOOLS_DIR}/ninja"
fi

# ========== Step 4: Parameters ==========
BUILD_TYPE="${BUILD_TYPE:-Release}"
API_LEVEL="${API_LEVEL:-29}"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
BUILD_DEX="${BUILD_DEX:-0}"

if [ -n "${ABIS:-}" ]; then
    IFS=' ' read -ra ABI_ARRAY <<< "${ABIS}"
else
    # Default to arm64-v8a for reliability: upstream Dobby/LSPlant snapshots may not always support armeabi-v7a cleanly.
    # If you need 32-bit support, run: ABIS="arm64-v8a armeabi-v7a" ./build.sh
    ABI_ARRAY=("arm64-v8a")
fi

printf "\n"
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN} Zygisk Modules Build Configuration${NC}"
echo -e "${CYAN}================================================================${NC}"
echo    "  NDK:        ${ANDROID_NDK}"
echo    "  Build:      ${BUILD_TYPE}"
echo    "  API:        ${API_LEVEL}"
echo    "  ABIs:       ${ABI_ARRAY[*]}"
echo    "  Jobs:       ${JOBS}"
echo    "  Modules:    ${MODULES:-<all>}"
echo    "  Build DEX:  ${BUILD_DEX}  (set BUILD_DEX=1 to run ./compile_hook.sh)"
echo -e "${CYAN}================================================================${NC}"

# ========== Optional: Compile Hooker.java -> classes.dex ==========
if [[ "${BUILD_DEX}" == "1" ]]; then
    step "Building Java hook DEX (classes.dex) for modules"
    if [[ -f "${PROJECT_DIR}/compile_hook.sh" ]]; then
        if bash "${PROJECT_DIR}/compile_hook.sh"; then
            info "DEX build OK"
        else
            warn "DEX build failed (Android SDK build-tools needed). Continuing native build..."
        fi
    else
        warn "compile_hook.sh not found; skip DEX build"
    fi
fi

# ========== Step 5: Build each ABI ==========
rm -rf "${PROJECT_DIR}/out"

for abi in "${ABI_ARRAY[@]}"; do
    step "Building ${abi}"

    BUILD_DIR="${PROJECT_DIR}/build/${abi}"

    # If a previous run used a different generator, clear this ABI build dir.
    if [ -f "${BUILD_DIR}/CMakeCache.txt" ]; then
        CURRENT_GEN="$(grep '^CMAKE_GENERATOR:INTERNAL=' "${BUILD_DIR}/CMakeCache.txt" | cut -d= -f2- || true)"
        case "${GENERATOR_ARGS}" in
            *"-G Ninja"*) EXPECTED_GEN="Ninja" ;;
            *) EXPECTED_GEN="" ;;
        esac
        if [ -n "${EXPECTED_GEN}" ] && [ "${CURRENT_GEN}" != "${EXPECTED_GEN}" ]; then
            warn "Generator changed (${CURRENT_GEN} -> ${EXPECTED_GEN}), cleaning ${BUILD_DIR}"
            rm -rf "${BUILD_DIR}"
        fi
    fi

    ${CMAKE_BIN} -B "${BUILD_DIR}" \
        ${GENERATOR_ARGS} \
        -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DCMAKE_CXX_SCAN_FOR_MODULES=OFF \
        -DANDROID_ABI="${abi}" \
        -DANDROID_PLATFORM="android-${API_LEVEL}" \
        -DANDROID_STL=c++_static \
        "${PROJECT_DIR}"

    ${CMAKE_BIN} --build "${BUILD_DIR}" --config "${BUILD_TYPE}" -j "${JOBS}"

    info "${abi} OK"
done

printf "\n"
echo -e "${GREEN} All ABIs built!${NC}"

# ========== Step 6: Package modules ==========
step "Packaging modules"

OUT_DIR="${PROJECT_DIR}/out"

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

PACKED=0
shopt -s nullglob
for mod_dir in "${PROJECT_DIR}"/modules/*; do
    [[ -d "${mod_dir}" ]] || continue
    mod_id="$(basename "${mod_dir}")"
    want_module "${mod_id}" || continue

    magisk_dir="${mod_dir}/magisk"
    prop="${magisk_dir}/module.prop"
    [[ -f "${prop}" ]] || continue

    stage_dir="${OUT_DIR}/${mod_id}/module"
    if [[ ! -d "${stage_dir}/zygisk" ]]; then
        error "[${mod_id}] No .so output found. Build failed or module has no native target."
    fi

    # Copy Magisk template files into staging dir (CMake already staged zygisk/<abi>.so)
    id_in_prop="$(grep '^id=' "${prop}" | cut -d= -f2 | tr -d '\r' || true)"
    if [[ -n "${id_in_prop}" && "${id_in_prop}" != "${mod_id}" ]]; then
        warn "[${mod_id}] module.prop id=${id_in_prop} does not match directory name; using directory name for build/output paths"
    fi
    cp "${prop}" "${stage_dir}/"
    [[ -f "${magisk_dir}/customize.sh" ]] && cp "${magisk_dir}/customize.sh" "${stage_dir}/"
    [[ -f "${magisk_dir}/classes.dex" ]] && cp "${magisk_dir}/classes.dex" "${stage_dir}/"
    if [[ -d "${magisk_dir}/META-INF" ]]; then
        cp -R "${magisk_dir}/META-INF" "${stage_dir}/"
        [[ -f "${stage_dir}/META-INF/com/google/android/update-binary" ]] && chmod 0755 "${stage_dir}/META-INF/com/google/android/update-binary" 2>/dev/null || true
    fi

    version="$(grep '^version=' "${prop}" | cut -d= -f2 | tr -d '\r' || true)"
    [[ -n "${version}" ]] || version="v0.0.0"

    ZIP_NAME="${mod_id}-${version}.zip"
    rm -f "${OUT_DIR}/${ZIP_NAME}"

    info "[${mod_id}] Libraries:"
    ls -lh "${stage_dir}/zygisk/" || true

    if command -v zip &>/dev/null; then
        (cd "${stage_dir}" && zip -r9 "${OUT_DIR}/${ZIP_NAME}" . -x '*.DS_Store')
    elif command -v python3 &>/dev/null; then
        python3 << PYEOF
import zipfile, os
src = "${stage_dir}"
dst = "${OUT_DIR}/${ZIP_NAME}"
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(src):
        for f in files:
            fp = os.path.join(root, f)
            zf.write(fp, os.path.relpath(fp, src))
PYEOF
    else
        error "zip or python3 required"
    fi

    [ -f "${OUT_DIR}/${ZIP_NAME}" ] || error "[${mod_id}] Zip creation failed"
    info "[${mod_id}] Packaged: ${OUT_DIR}/${ZIP_NAME}"
    PACKED=1
done
shopt -u nullglob

[[ "${PACKED}" -eq 1 ]] || error "No modules packaged. Check modules/*/magisk/module.prop"

printf "\n"
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN} Build complete!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo "  Output dir: ${OUT_DIR}"
echo "  ABIs:       ${ABI_ARRAY[*]}"
echo ""

