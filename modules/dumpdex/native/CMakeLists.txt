cmake_minimum_required(VERSION 3.18.1)

set(MOD_ID "dumpdex")

set(MOD_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/main.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/dumpdex_hook.cpp"
)

add_zygisk_module(
    NAME        ${MOD_ID}
    MODULE_ID   ${MOD_ID}
    HOOKER_CLASS "dumpdex.Hooker"
    USE_DOBBY    ON
    USE_LSPLANT  OFF
    SOURCES     ${MOD_SOURCES}
    INCLUDE_DIRS
        "${CMAKE_CURRENT_LIST_DIR}"
    EXPORT_MAP  "${CMAKE_CURRENT_LIST_DIR}/export.map"
    LINK_LIBS
        dl
)

