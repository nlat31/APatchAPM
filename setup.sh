#!/bin/bash
set -euo pipefail

# ================================================================
# Zygisk Modules - 依赖库自动拉取脚本 (Linux/macOS)
# ================================================================
# 从 GitHub 拉取最新版本的:
#   - Dobby       (Native inline hook 框架)
#   - lsplant     (ART Java hook 框架)
#   - frida-gum   (Frida GUM DevKit, static lib)
#   - zygisk.hpp  (Zygisk Module API 头文件)
#   - CSOLoader   (Custom linker, static lib)
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTERNAL_DIR="${SCRIPT_DIR}/external"

# 仓库地址
DOBBY_REPO="https://github.com/jmpews/Dobby.git"
LSPLANT_REPO="https://github.com/LSPosed/LSPlant.git"
ZYGISK_HPP_URL="https://raw.githubusercontent.com/topjohnwu/zygisk-module-sample/master/module/jni/zygisk.hpp"
FRIDA_GUM_VERSION="17.7.3"
FRIDA_MIRROR_BASE="https://sourceforge.net/projects/frida.mirror/files"
CSOLOADER_REPO="https://github.com/nlat31/CSOLoader.git"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "${CYAN}==>${NC} $*"; }

# ==================== 前置检查 ====================
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        error "$1 is not installed. Please install it first."
    fi
}

check_tool git
check_tool tar

# 检查下载工具
DOWNLOAD_CMD=""
if command -v curl &>/dev/null; then
    DOWNLOAD_CMD="curl"
elif command -v wget &>/dev/null; then
    DOWNLOAD_CMD="wget"
else
    error "Neither curl nor wget found. Please install one of them."
fi

echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN} Fetching Dependencies from GitHub${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""

mkdir -p "${EXTERNAL_DIR}"

# ==================== 1. Dobby ====================
DOBBY_DIR="${EXTERNAL_DIR}/dobby"
step "[1/5] Dobby (Native Hook Framework)"

if [ -d "${DOBBY_DIR}/.git" ]; then
    info "Dobby already exists, pulling latest..."
    cd "${DOBBY_DIR}"
    if git fetch --depth 1 origin; then
        # Prefer origin/HEAD if present; fallback to remote HEAD branch name.
        if git rev-parse --verify --quiet origin/HEAD >/dev/null; then
            git reset --hard origin/HEAD
        else
            HEAD_BRANCH="$(git remote show origin 2>/dev/null | grep 'HEAD branch' | awk '{print $NF}' || true)"
            if [ -n "${HEAD_BRANCH}" ] && git rev-parse --verify --quiet "origin/${HEAD_BRANCH}" >/dev/null; then
                git reset --hard "origin/${HEAD_BRANCH}"
            else
                warn "Unable to resolve origin HEAD; keeping current Dobby checkout"
            fi
        fi
    else
        warn "Network fetch failed; keeping current Dobby checkout"
    fi
    cd "${SCRIPT_DIR}"
else
    if [ -d "${DOBBY_DIR}" ]; then
        warn "Removing incomplete Dobby directory..."
        rm -rf "${DOBBY_DIR}"
    fi
    info "Cloning Dobby (shallow)..."
    git clone --depth 1 "${DOBBY_REPO}" "${DOBBY_DIR}"
fi

# 验证
if [ -f "${DOBBY_DIR}/CMakeLists.txt" ]; then
    info "Dobby OK: ${DOBBY_DIR}"
else
    error "Dobby clone failed - CMakeLists.txt not found"
fi

#
# Android/NDK 构建说明:
#   Dobby upstream 的 trampoline asm (closure_bridge_*.asm) 使用了 Mach-O 的 `@PAGE/@PAGEOFF` 语法，
#   在 Android/ELF 下会汇编失败。这里直接把 `TOKEN@PAGE/@PAGEOFF` patch 成 Android/ELF 可用写法：
#     TOKEN@PAGE    -> TOKEN
#     TOKEN@PAGEOFF -> :lo12:TOKEN
#
patch_dobby_android() {
    local cmake_file="${DOBBY_DIR}/CMakeLists.txt"
    [ -f "${cmake_file}" ] || return 0

    # We keep the patch idempotent by making each edit conditional in the python script,
    # so don't early-return here (source fixes may still be missing).

    if ! command -v python3 &>/dev/null; then
        warn "python3 not found; skip patching Dobby trampoline asm (build may fail on Android)"
        return 0
    fi

    DOBBY_DIR="${DOBBY_DIR}" python3 <<'PYEOF'
import os, re
from pathlib import Path

root = Path(os.environ["DOBBY_DIR"])

def read(p: Path) -> str:
    # Normalize newlines to make patches robust across checkouts (LF/CRLF).
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

# ---- Patch 1: code-patch-tool-posix.cc (remove non-existent header) ----
cpp = root / "source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc"
if cpp.exists():
    t = read(cpp)
    t = re.sub(r'(?m)^\s*#include "core/arch/Cpu\.h"\s*\n', "", t)
    write(cpp, t)

# ---- Patch 2: os_arch_features.h (avoid include-cycle on Android) ----
hdr = root / "common/os_arch_features.h"
if hdr.exists():
    t = read(hdr)
    if "ZrayPatch: Android make_memory_readable" not in t:
        # Add required system headers
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

        # Replace the Android implementation to not depend on OSMemory/kReadExecute (can be incomplete due to include cycle)
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

# ---- Patch 3: ProcessRuntime.cc (fix broken member access) ----
pr = root / "source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc"
if pr.exists():
    t = read(pr)
    t = t.replace("return a.start < b.start;", "return a.start() < b.start();")
    t = t.replace("return (a.start < b.start);", "return a.start() < b.start();")
    # RuntimeModule has `base`, not `load_address_` in current upstream header.
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
    s2 = re.sub(r'([A-Za-z0-9_.$()]+)@PAGEOFF', r':lo12:\1', s)
    s2 = re.sub(r'([A-Za-z0-9_.$()]+)@PAGE', r'\1', s2)

    # PIC fix for Android/ELF: use GOT-based load for common_closure_bridge_handler.
    if p.name == "closure_bridge_arm64.asm":
        s2 = re.sub(
            r'(?m)^adrp\s+(\w+),\s*([A-Za-z0-9_.$()]+)\s*\nadd\s+\1,\s*\1,\s*:lo12:\2\s*$',
            r'adrp \1, :got:\2\nldr \1, [\1, :got_lo12:\2]',
            s2,
        )
    if s2 != s:
        write(p, s2)
PYEOF

    info "Patched Dobby for Android/ELF"
}

patch_dobby_android

    info "Dobby source patches applied"

# ==================== 2. lsplant ====================
LSPLANT_DIR="${EXTERNAL_DIR}/lsplant"
step "[2/5] lsplant (ART Java Hook Framework)"

if [ -d "${LSPLANT_DIR}/.git" ]; then
    info "lsplant already exists, pulling latest..."
    cd "${LSPLANT_DIR}"
    if git fetch --depth 1 origin; then
        if git rev-parse --verify --quiet origin/HEAD >/dev/null; then
            git reset --hard origin/HEAD
        else
            HEAD_BRANCH="$(git remote show origin 2>/dev/null | grep 'HEAD branch' | awk '{print $NF}' || true)"
            if [ -n "${HEAD_BRANCH}" ] && git rev-parse --verify --quiet "origin/${HEAD_BRANCH}" >/dev/null; then
                git reset --hard "origin/${HEAD_BRANCH}"
            else
                warn "Unable to resolve origin HEAD; keeping current lsplant checkout"
            fi
        fi
    else
        warn "Network fetch failed; keeping current lsplant checkout"
    fi
    git submodule update --init --recursive --depth 1 -- lsplant/src/main/jni/external/dex_builder || warn "lsplant submodule update failed (offline?)"
    cd "${SCRIPT_DIR}"
else
    if [ -d "${LSPLANT_DIR}" ]; then
        warn "Removing incomplete lsplant directory..."
        rm -rf "${LSPLANT_DIR}"
    fi
    info "Cloning lsplant (shallow)..."
    git clone --depth 1 "${LSPLANT_REPO}" "${LSPLANT_DIR}"
    # 只初始化构建所需的子模块 (dex_builder 及其嵌套依赖)，跳过 test 和 docs 中的私有/无关子模块
    cd "${LSPLANT_DIR}"
    git submodule update --init --recursive --depth 1 -- lsplant/src/main/jni/external/dex_builder
    cd "${SCRIPT_DIR}"
fi

# 验证
LSPLANT_JNI="${LSPLANT_DIR}/lsplant/src/main/jni"
if [ -f "${LSPLANT_JNI}/CMakeLists.txt" ]; then
    info "lsplant OK: ${LSPLANT_DIR}"
else
    error "lsplant clone failed - CMakeLists.txt not found at ${LSPLANT_JNI}"
fi

# ==================== 3. frida-gum (devkit) ====================
FRIDA_DIR="${EXTERNAL_DIR}/frida-gum"
FRIDA_INCLUDE_DIR="${FRIDA_DIR}/include"
FRIDA_LIB_DIR="${FRIDA_DIR}/lib"
step "[3/5] frida-gum (DevKit ${FRIDA_GUM_VERSION})"

mkdir -p "${FRIDA_INCLUDE_DIR}" "${FRIDA_LIB_DIR}"

download_file() {
    local url="$1"
    local out="$2"
    if [ "${DOWNLOAD_CMD}" = "curl" ]; then
        curl -fsSL "${url}" -o "${out}"
    else
        wget -q "${url}" -O "${out}"
    fi
}

extract_devkit_one() {
    local abi="$1"
    local frida_arch="$2"

    local url_github="https://github.com/frida/frida/releases/download/${FRIDA_GUM_VERSION}/frida-gum-devkit-${FRIDA_GUM_VERSION}-${frida_arch}.tar.xz"
    local url_sf="${FRIDA_MIRROR_BASE}/${FRIDA_GUM_VERSION}/frida-gum-devkit-${FRIDA_GUM_VERSION}-${frida_arch}.tar.xz/download"
    local tmpbase
    tmpbase="$(mktemp -d)"
    local archive="${tmpbase}/frida-gum-devkit.tar.xz"

    info "Downloading ${abi} devkit..."
    if ! download_file "${url_github}" "${archive}"; then
        warn "GitHub download failed; trying SourceForge mirror..."
        if ! download_file "${url_sf}" "${archive}"; then
            rm -rf "${tmpbase}"
            error "Failed to download frida-gum devkit for ${abi}\n  ${url_github}\n  ${url_sf}"
        fi
    fi

    tar -xJf "${archive}" -C "${tmpbase}"

    local hdr=""
    if [ -f "${tmpbase}/frida-gum.h" ]; then
        hdr="${tmpbase}/frida-gum.h"
    elif [ -f "${tmpbase}/include/frida-gum.h" ]; then
        hdr="${tmpbase}/include/frida-gum.h"
    fi

    local lib=""
    if [ -f "${tmpbase}/libfrida-gum.a" ]; then
        lib="${tmpbase}/libfrida-gum.a"
    elif [ -f "${tmpbase}/lib/libfrida-gum.a" ]; then
        lib="${tmpbase}/lib/libfrida-gum.a"
    fi

    if [ -z "${hdr}" ] || [ -z "${lib}" ]; then
        rm -rf "${tmpbase}"
        error "Unexpected frida-gum devkit layout for ${abi} (${frida_arch})"
    fi

    # Header should be identical across ABIs; overwrite is fine.
    cp -f "${hdr}" "${FRIDA_INCLUDE_DIR}/frida-gum.h"
    mkdir -p "${FRIDA_LIB_DIR}/${abi}"
    cp -f "${lib}" "${FRIDA_LIB_DIR}/${abi}/libfrida-gum.a"

    rm -rf "${tmpbase}"
    info "frida-gum OK: ${abi}"
}

extract_devkit_one "arm64-v8a" "android-arm64"
extract_devkit_one "armeabi-v7a" "android-arm"
extract_devkit_one "x86" "android-x86"
extract_devkit_one "x86_64" "android-x86_64"

# ==================== 4. zygisk.hpp ====================
ZYGISK_DIR="${EXTERNAL_DIR}/zygisk"
ZYGISK_HPP="${ZYGISK_DIR}/zygisk.hpp"
step "[4/5] zygisk.hpp (Zygisk Module API Header)"

mkdir -p "${ZYGISK_DIR}"

info "Downloading zygisk.hpp from Magisk module sample..."
if [ "${DOWNLOAD_CMD}" = "curl" ]; then
    if ! curl -fsSL "${ZYGISK_HPP_URL}" -o "${ZYGISK_HPP}.tmp"; then
        warn "Failed to download zygisk.hpp (offline?)."
    fi
elif [ "${DOWNLOAD_CMD}" = "wget" ]; then
    if ! wget -q "${ZYGISK_HPP_URL}" -O "${ZYGISK_HPP}.tmp"; then
        warn "Failed to download zygisk.hpp (offline?)."
    fi
fi

# 验证下载的文件不为空且包含关键标记
if [ -s "${ZYGISK_HPP}.tmp" ] && grep -q "ModuleBase" "${ZYGISK_HPP}.tmp"; then
    mv "${ZYGISK_HPP}.tmp" "${ZYGISK_HPP}"
    info "zygisk.hpp OK: ${ZYGISK_HPP}"
else
    rm -f "${ZYGISK_HPP}.tmp"
    if [ -s "${ZYGISK_HPP}" ] && grep -q "ModuleBase" "${ZYGISK_HPP}" 2>/dev/null; then
        warn "Using existing zygisk.hpp: ${ZYGISK_HPP}"
    else
        error "Failed to download valid zygisk.hpp from:\n  ${ZYGISK_HPP_URL}"
    fi
fi

# ==================== 5. CSOLoader ====================
CSOLOADER_DIR="${EXTERNAL_DIR}/CSOLoader"
step "[5/5] CSOLoader (Custom Linker)"

if [ -d "${CSOLOADER_DIR}/.git" ]; then
    info "CSOLoader already exists, pulling latest..."
    cd "${CSOLOADER_DIR}"
    if git fetch --depth 1 origin; then
        if git rev-parse --verify --quiet origin/HEAD >/dev/null; then
            git reset --hard origin/HEAD
        else
            HEAD_BRANCH="$(git remote show origin 2>/dev/null | grep 'HEAD branch' | awk '{print $NF}' || true)"
            if [ -n "${HEAD_BRANCH}" ] && git rev-parse --verify --quiet "origin/${HEAD_BRANCH}" >/dev/null; then
                git reset --hard "origin/${HEAD_BRANCH}"
            else
                warn "Unable to resolve origin HEAD; keeping current CSOLoader checkout"
            fi
        fi
    else
        warn "Network fetch failed; keeping current CSOLoader checkout"
    fi
    cd "${SCRIPT_DIR}"
else
    if [ -d "${CSOLOADER_DIR}" ]; then
        warn "Removing incomplete CSOLoader directory..."
        rm -rf "${CSOLOADER_DIR}"
    fi
    info "Cloning CSOLoader (shallow)..."
    git clone --depth 1 "${CSOLOADER_REPO}" "${CSOLOADER_DIR}"
fi

# 验证
if [ -f "${CSOLOADER_DIR}/CMakeLists.txt" ]; then
    info "CSOLoader OK: ${CSOLOADER_DIR}"
else
    error "CSOLoader clone failed - CMakeLists.txt not found"
fi

# ==================== 完成 ====================
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN} All dependencies fetched successfully!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo "  Dobby:       ${DOBBY_DIR}"
echo "  lsplant:     ${LSPLANT_DIR}"
echo "  frida-gum:   ${FRIDA_DIR}"
echo "  zygisk.hpp:  ${ZYGISK_HPP}"
echo "  CSOLoader:   ${CSOLOADER_DIR}"
echo ""

# 显示版本信息
echo "  Versions:"
cd "${DOBBY_DIR}" && echo "    Dobby:   $(git log -1 --format='%h %s' 2>/dev/null || echo 'unknown')" && cd "${SCRIPT_DIR}"
cd "${LSPLANT_DIR}" && echo "    lsplant: $(git log -1 --format='%h %s' 2>/dev/null || echo 'unknown')" && cd "${SCRIPT_DIR}"
cd "${CSOLOADER_DIR}" && echo "    CSOLoader: $(git log -1 --format='%h %s' 2>/dev/null || echo 'unknown')" && cd "${SCRIPT_DIR}"
echo "    frida-gum: ${FRIDA_GUM_VERSION}"
echo ""
echo -e "  Run ${CYAN}./build.sh${NC} to build the Zygisk module."
echo ""

