cmake_minimum_required(VERSION 3.18.1)

set(MOD_ID "dumpso")

set(MOD_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/main.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/dumpso_hook.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/dumpso_dump.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/dumpso_enum.cpp"

    "${CMAKE_CURRENT_LIST_DIR}/SoFixer/ElfReader.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SoFixer/ObElfReader.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SoFixer/ElfRebuilder.cpp"
)

add_zygisk_module(
    NAME        ${MOD_ID}
    MODULE_ID   ${MOD_ID}
    HOOKER_CLASS "dumpso.Hooker"
    USE_DOBBY    OFF
    USE_LSPLANT  OFF
    SOURCES     ${MOD_SOURCES}
    INCLUDE_DIRS
        "${CMAKE_CURRENT_LIST_DIR}"
        "${CMAKE_CURRENT_LIST_DIR}/SoFixer"
        "${CMAKE_SOURCE_DIR}/external/frida-gum/include"
    EXPORT_MAP  "${CMAKE_CURRENT_LIST_DIR}/export.map"
    LINK_LIBS
        frida_gum_static
        dl
        m
)

