cmake_minimum_required(VERSION 3.18.1)

set(MOD_ID "sample")

file(GLOB MOD_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_LIST_DIR}/*.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/*.c"
)

add_zygisk_module(
    NAME        ${MOD_ID}
    MODULE_ID   ${MOD_ID}
    HOOKER_CLASS "sample.Hooker"
    SOURCES     ${MOD_SOURCES}
    INCLUDE_DIRS
        "${CMAKE_CURRENT_LIST_DIR}"
    EXPORT_MAP  "${CMAKE_CURRENT_LIST_DIR}/export.map"
)

