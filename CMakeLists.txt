cmake_minimum_required(VERSION 3.18.1)
project(zygisk_modules VERSION 1.0.0 LANGUAGES C CXX)

# ==================== 编译选项 ====================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

# 禁用 C++20 模块扫描 (lsplant 不使用 C++ modules，CMake 4.x 会误检测)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF CACHE BOOL "" FORCE)

# Android NDK 相关检查
if(NOT ANDROID)
    message(FATAL_ERROR "This project must be built with Android NDK toolchain.\n"
            "Please set -DCMAKE_TOOLCHAIN_FILE=<NDK>/build/cmake/android.toolchain.cmake")
endif()

if(NOT DEFINED ANDROID_ABI)
    message(FATAL_ERROR "ANDROID_ABI is not defined. Please specify the target ABI.")
endif()

message(STATUS "=== Building ${PROJECT_NAME} for ${ANDROID_ABI} ===")
message(STATUS "Android API Level: ${ANDROID_PLATFORM}")
message(STATUS "NDK Path: ${ANDROID_NDK}")

# ==================== 全局编译标志 ====================
# 注意: 限制性选项 (如 -fno-exceptions) 不在全局设置，避免影响外部依赖库
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")

# Release 优化
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -DNDEBUG")

# 减小二进制体积
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all")

# ==================== 外部依赖 ====================

# --- Dobby (Native Hook Framework) ---
set(DOBBY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/dobby)
if(EXISTS ${DOBBY_DIR}/CMakeLists.txt)
    # Dobby 构建选项
    set(DOBBY_GENERATE_SHARED OFF CACHE BOOL "" FORCE)
    set(DOBBY_DEBUG OFF CACHE BOOL "" FORCE)
    # 某些 NDK/Clang 版本下 Dobby 的 trampoline asm 可能不兼容，优先禁用（如 Dobby 支持该选项）
    set(BUILD_WITH_TRAMPOLINE_ASM OFF CACHE BOOL "" FORCE)
    set(DOBBY_BUILD_TRAMPOLINE_ASM OFF CACHE BOOL "" FORCE)
    set(DOBBY_TRAMPOLINE_ASM OFF CACHE BOOL "" FORCE)
    add_subdirectory(${DOBBY_DIR} dobby)
    message(STATUS "Dobby: Found at ${DOBBY_DIR}")
    # Ensure static lib is PIC so it can be linked into our shared module.
    if (TARGET dobby_static)
        set_property(TARGET dobby_static PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()
else()
    message(FATAL_ERROR "Dobby not found at ${DOBBY_DIR}\n"
            "Please run: ./setup.sh")
endif()

# --- lsplant (ART Java Hook Framework) ---
set(LSPLANT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/lsplant)
set(LSPLANT_JNI_DIR ${LSPLANT_DIR}/lsplant/src/main/jni)
if(EXISTS ${LSPLANT_JNI_DIR}/CMakeLists.txt)
    # lsplant 的 CMakeLists 在 shared library 的 POST_BUILD 里使用 DEBUG_SYMBOLS_PATH，
    # 但它在文件后半段才 set()，导致未定义时会展开成空字符串，生成类似 `/${ANDROID_ABI}` 的绝对路径。
    # 这里提前提供一个合理默认值（每个 ABI build dir 下的 symbols/），避免写入根目录导致构建失败。
    set(DEBUG_SYMBOLS_PATH "${CMAKE_BINARY_DIR}/symbols" CACHE PATH "" FORCE)
    add_subdirectory(${LSPLANT_JNI_DIR} lsplant)
    message(STATUS "lsplant: Found at ${LSPLANT_JNI_DIR}")
    # Ensure static lib is PIC so it can be linked into our shared module.
    if (TARGET lsplant_static)
        set_property(TARGET lsplant_static PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()
else()
    message(FATAL_ERROR "lsplant not found at ${LSPLANT_JNI_DIR}\n"
            "Please run: ./setup.sh")
endif()

# --- frida-gum (Frida GUM DevKit, static lib) ---
set(FRIDA_GUM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/frida-gum)
set(FRIDA_GUM_HEADER ${FRIDA_GUM_DIR}/include/frida-gum.h)
set(FRIDA_GUM_LIB ${FRIDA_GUM_DIR}/lib/${ANDROID_ABI}/libfrida-gum.a)
if(EXISTS ${FRIDA_GUM_HEADER} AND EXISTS ${FRIDA_GUM_LIB})
    add_library(frida_gum_static STATIC IMPORTED GLOBAL)
    set_target_properties(frida_gum_static PROPERTIES
        IMPORTED_LOCATION "${FRIDA_GUM_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${FRIDA_GUM_DIR}/include"
    )
    message(STATUS "frida-gum: Found devkit at ${FRIDA_GUM_DIR} (${ANDROID_ABI})")
else()
    message(FATAL_ERROR "frida-gum devkit not found.\n"
            "Expected:\n"
            "  - ${FRIDA_GUM_HEADER}\n"
            "  - ${FRIDA_GUM_LIB}\n"
            "Please run: ./setup.sh")
endif()

# --- CSOLoader (custom linker, static lib) ---
set(CSOLOADER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/CSOLoader)
if(EXISTS ${CSOLOADER_DIR}/CMakeLists.txt)
    add_subdirectory(${CSOLOADER_DIR} csoloader_build)
    message(STATUS "CSOLoader: Found at ${CSOLOADER_DIR}")
    # Ensure static lib is PIC so it can be linked into our shared module.
    if(TARGET csoloader)
        set_property(TARGET csoloader PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()
else()
    message(FATAL_ERROR "CSOLoader not found at ${CSOLOADER_DIR}\n"
            "Please run: ./setup.sh")
endif()

# ==================== Zygisk 模块库 ====================

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ZygiskModule.cmake)

# ==================== Modules discovery ====================
# Each module lives under:
#   modules/<id>/native/CMakeLists.txt
file(GLOB _module_roots LIST_DIRECTORIES true "${CMAKE_CURRENT_SOURCE_DIR}/modules/*")
set(_found 0)
foreach(_m IN LISTS _module_roots)
    if(EXISTS "${_m}/native/CMakeLists.txt")
        get_filename_component(_id "${_m}" NAME)
        message(STATUS "Module: ${_id} (${_m})")
        add_subdirectory("${_m}/native" "modules/${_id}")
        math(EXPR _found "${_found}+1")
    endif()
endforeach()

if(_found EQUAL 0)
    message(WARNING "No modules found under ${CMAKE_CURRENT_SOURCE_DIR}/modules/*/native")
endif()
