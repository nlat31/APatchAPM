include_guard(GLOBAL)

include(CMakeParseArguments)

function(add_zygisk_module)
    set(options)
    set(oneValueArgs NAME MODULE_ID EXPORT_MAP OUTPUT_ROOT HOOKER_CLASS USE_DOBBY USE_LSPLANT)
    set(multiValueArgs SOURCES INCLUDE_DIRS COMPILE_DEFS LINK_LIBS)
    cmake_parse_arguments(ZM "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ZM_NAME)
        message(FATAL_ERROR "add_zygisk_module: NAME is required")
    endif()

    if(NOT ZM_MODULE_ID)
        set(ZM_MODULE_ID "${ZM_NAME}")
    endif()

    if(NOT ZM_SOURCES)
        message(FATAL_ERROR "add_zygisk_module(${ZM_NAME}): SOURCES is empty")
    endif()

    if(NOT ZM_OUTPUT_ROOT)
        set(ZM_OUTPUT_ROOT "${CMAKE_SOURCE_DIR}/out")
    endif()

    if(NOT ZM_HOOKER_CLASS)
        # Convention: <module_id>.Hooker
        set(ZM_HOOKER_CLASS "${ZM_MODULE_ID}.Hooker")
    endif()

    # Defaults: keep backward compatibility (all modules used to link these).
    set(_use_dobby TRUE)
    set(_use_lsplant TRUE)
    if(NOT "${ZM_USE_DOBBY}" STREQUAL "")
        set(_use_dobby ${ZM_USE_DOBBY})
    endif()
    if(NOT "${ZM_USE_LSPLANT}" STREQUAL "")
        set(_use_lsplant ${ZM_USE_LSPLANT})
    endif()

    add_library(${ZM_NAME} SHARED ${ZM_SOURCES})

    target_compile_options(${ZM_NAME} PRIVATE
        -fno-exceptions
        -fno-rtti
        -Wall
        -Wextra
    )

    target_compile_definitions(${ZM_NAME} PRIVATE
        ZMOD_ID="${ZM_MODULE_ID}"
        ZMOD_HOOKER_CLASS="${ZM_HOOKER_CLASS}"
        ${ZM_COMPILE_DEFS}
    )

    target_include_directories(${ZM_NAME} PRIVATE
        ${ZM_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/external/zygisk
    )

    if(_use_dobby)
        target_include_directories(${ZM_NAME} PRIVATE
            ${DOBBY_DIR}/include
        )
    endif()
    if(_use_lsplant)
        target_include_directories(${ZM_NAME} PRIVATE
            ${LSPLANT_JNI_DIR}/include
        )
    endif()

    target_link_libraries(${ZM_NAME} PRIVATE
        log
        ${ZM_LINK_LIBS}
    )

    if(_use_dobby)
        target_link_libraries(${ZM_NAME} PRIVATE dobby_static)
    endif()
    if(_use_lsplant)
        target_link_libraries(${ZM_NAME} PRIVATE lsplant_static)
    endif()

    if(ZM_EXPORT_MAP)
        target_link_options(${ZM_NAME} PRIVATE
            -Wl,--version-script=${ZM_EXPORT_MAP}
        )
    endif()

    # Build output staging: out/<module_id>/module/zygisk/<abi>.so
    set(_out_dir "${ZM_OUTPUT_ROOT}/${ZM_MODULE_ID}/module/zygisk")
    add_custom_command(TARGET ${ZM_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_out_dir}"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${ZM_NAME}>" "${_out_dir}/${ANDROID_ABI}.so"
        COMMENT "Staging ${ZM_MODULE_ID} (${ANDROID_ABI}) -> ${_out_dir}/${ANDROID_ABI}.so"
    )
endfunction()

