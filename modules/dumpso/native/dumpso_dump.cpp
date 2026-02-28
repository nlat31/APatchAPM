#include "dumpso_dump.h"

#include <android/log.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "frida-gum.h"

#include "ObElfReader.h"
#include "ElfRebuilder.h"

#ifndef ZMOD_ID
#define ZMOD_ID "dumpso"
#endif

#define LOG_TAG    "DumpSo/Dump"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

namespace dumpso {

static bool ensure_dir(const std::string& dir, mode_t mode) {
    if (dir.empty()) return false;
    if (dir == "/") return true;

    size_t pos = 1;
    while (pos <= dir.size()) {
        pos = dir.find('/', pos);
        std::string part = (pos == std::string::npos) ? dir : dir.substr(0, pos);
        if (!part.empty()) {
            if (mkdir(part.c_str(), mode) != 0 && errno != EEXIST) {
                return false;
            }
        }
        if (pos == std::string::npos) break;
        pos++;
    }
    return true;
}

static int rebuild_so(const std::string& dumped_path, uintptr_t module_base, size_t module_size) {
    std::string out_path = dumped_path + ".fix.so";

    ObElfReader elf_reader;
    elf_reader.setDumpSoBaseAddr(module_base);
    elf_reader.setDumpSoSize(module_size);

    if (!elf_reader.setSource(dumped_path.c_str())) {
        LOGE("SoFixer: unable to open source: %s", dumped_path.c_str());
        return -1;
    }
    if (!elf_reader.Load()) {
        LOGE("SoFixer: source is invalid: %s", dumped_path.c_str());
        return -1;
    }

    ElfRebuilder elf_rebuilder(&elf_reader);
    if (!elf_rebuilder.Rebuild()) {
        LOGE("SoFixer: rebuild failed: %s", dumped_path.c_str());
        return -1;
    }

    std::ofstream out(out_path, std::ofstream::out | std::ofstream::binary);
    if (!out.is_open()) {
        LOGE("SoFixer: cannot write: %s", out_path.c_str());
        return -1;
    }
    out.write(reinterpret_cast<const char*>(elf_rebuilder.getRebuildData()),
              static_cast<std::streamsize>(elf_rebuilder.getRebuildSize()));
    out.close();

    LOGI("Output: %s", out_path.c_str());
    return 0;
}

void dump_module(const std::string& package_name,
                 const char* so_path,
                 uintptr_t module_base,
                 size_t module_size,
                 bool fix) {
    if (module_base == 0 || module_size == 0) return;

    std::string output_dir = "/data/data/" + package_name + "/dumpso/";
    if (!ensure_dir(output_dir, 0700)) {
        LOGE("Failed to create output dir: %s (errno=%d)", output_dir.c_str(), errno);
        return;
    }

    const uintptr_t module_end = module_base + module_size;

    std::stringstream range_hex;
    range_hex << "0x" << std::hex << module_base << "-0x" << std::hex << module_end;
    const std::string range_tag = range_hex.str();

    std::string module_name;
    if (so_path && so_path[0] != '\0') {
        std::string s(so_path);
        size_t slash = s.find_last_of('/');
        std::string base = (slash == std::string::npos) ? s : s.substr(slash + 1);
        module_name = !base.empty() ? std::move(base) : std::move(s);
    }
    if (module_name.empty()) {
        module_name = range_tag;
    }

    std::string dump_path;
    if (module_name == range_tag) {
        dump_path = output_dir + module_name + ".dump.so";
    } else {
        dump_path = output_dir + module_name + ".dump[" + range_tag + "].so";
    }

    gum_ensure_code_readable(reinterpret_cast<void*>(module_base), module_size);

    std::ofstream dump(dump_path, std::ofstream::out | std::ofstream::binary);
    if (!dump.is_open()) {
        LOGE("Failed to open output: %s", dump_path.c_str());
        return;
    }

    auto* buffer = new uint8_t[module_size];
    std::memmove(buffer, reinterpret_cast<const void*>(module_base), module_size);
    dump.write(reinterpret_cast<const char*>(buffer), static_cast<std::streamsize>(module_size));
    delete[] buffer;
    dump.close();

    LOGI("Dump done: %s", dump_path.c_str());

    if (fix) {
        if (rebuild_so(dump_path, module_base, module_size) == 0) {
            LOGI("Rebuild complete");
        } else {
            LOGW("Rebuild failed");
        }
    }
}

} // namespace dumpso

