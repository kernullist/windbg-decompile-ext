cmake_minimum_required(VERSION 3.24)

project(WindbgLlmDecomp LANGUAGES CXX)

if (NOT WIN32)
    message(FATAL_ERROR "This project targets Windows only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(DEBUGGERS_ROOT "" CACHE PATH "Root directory of Debugging Tools for Windows x64")
set(DBGENG_INCLUDE_DIR "" CACHE PATH "Explicit directory containing dbgeng.h")
set(DBGENG_LIBRARY "" CACHE FILEPATH "Explicit path to dbgeng.lib")
option(DECOMP_USE_SYMBOL_ENTRY_APIS "Use IDebugSymbols3 symbol entry APIs such as GetSymbolEntryOffsetRegions and GetSymbolEntryString" ON)

function(set_common_warnings target_name)
    if (MSVC)
        target_compile_options(
            ${target_name}
            PRIVATE
            /W4
            /EHsc
            /permissive-
            /D_CRT_SECURE_NO_WARNINGS
        )
    endif()
endfunction()

function(try_resolve_dbgeng_layout candidate out_include out_library)
    file(TO_CMAKE_PATH "${candidate}" candidate_normalized)

    set(layout_includes
        "${candidate_normalized}/sdk/inc"
        "${candidate_normalized}/inc"
        "${candidate_normalized}"
    )

    set(layout_libraries
        "${candidate_normalized}/sdk/lib/dbgeng.lib"
        "${candidate_normalized}/sdk/lib/amd64/dbgeng.lib"
        "${candidate_normalized}/sdk/lib/x64/dbgeng.lib"
        "${candidate_normalized}/lib/dbgeng.lib"
        "${candidate_normalized}/lib/amd64/dbgeng.lib"
        "${candidate_normalized}/lib/x64/dbgeng.lib"
        "${candidate_normalized}/dbgeng.lib"
    )

    foreach(include_dir IN LISTS layout_includes)
        if (NOT EXISTS "${include_dir}/dbgeng.h")
            continue()
        endif()

        foreach(library_path IN LISTS layout_libraries)
            if (EXISTS "${library_path}")
                set(${out_include} "${include_dir}" PARENT_SCOPE)
                set(${out_library} "${library_path}" PARENT_SCOPE)
                return()
            endif()
        endforeach()
    endforeach()
endfunction()

set(_resolved_dbgeng_include "")
set(_resolved_dbgeng_library "")

if (DBGENG_INCLUDE_DIR AND DBGENG_LIBRARY)
    if (EXISTS "${DBGENG_INCLUDE_DIR}/dbgeng.h" AND EXISTS "${DBGENG_LIBRARY}")
        set(_resolved_dbgeng_include "${DBGENG_INCLUDE_DIR}")
        set(_resolved_dbgeng_library "${DBGENG_LIBRARY}")
    else()
        message(FATAL_ERROR "DBGENG_INCLUDE_DIR or DBGENG_LIBRARY is invalid.")
    endif()
else()
    set(_debugger_root_candidates
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dbgeng"
    )

    if (DEBUGGERS_ROOT)
        list(APPEND _debugger_root_candidates "${DEBUGGERS_ROOT}")
    endif()

    if (DEFINED ENV{DEBUGGERS_ROOT} AND NOT "$ENV{DEBUGGERS_ROOT}" STREQUAL "")
        list(APPEND _debugger_root_candidates "$ENV{DEBUGGERS_ROOT}")
    endif()

    if (DEFINED ENV{DBGENG_ROOT} AND NOT "$ENV{DBGENG_ROOT}" STREQUAL "")
        list(APPEND _debugger_root_candidates "$ENV{DBGENG_ROOT}")
    endif()

    set(_progfiles_x86 "$ENV{ProgramFiles\(x86\)}")
    if (NOT "${_progfiles_x86}" STREQUAL "")
        list(APPEND _debugger_root_candidates "${_progfiles_x86}/Windows Kits/10/Debuggers/x64")
    endif()

    set(_progw6432 "$ENV{ProgramW6432}")
    if (NOT "${_progw6432}" STREQUAL "")
        list(APPEND _debugger_root_candidates "${_progw6432}/Windows Kits/10/Debuggers/x64")
    endif()

    foreach(candidate IN LISTS _debugger_root_candidates)
        try_resolve_dbgeng_layout("${candidate}" candidate_include candidate_library)

        if (candidate_include AND candidate_library)
            set(_resolved_dbgeng_include "${candidate_include}")
            set(_resolved_dbgeng_library "${candidate_library}")
            set(DEBUGGERS_ROOT_RESOLVED "${candidate}")
            break()
        endif()
    endforeach()
endif()

if (_resolved_dbgeng_include STREQUAL "" OR _resolved_dbgeng_library STREQUAL "")
    message(FATAL_ERROR
        "Could not locate dbgeng.h and dbgeng.lib. "
        "Set DEBUGGERS_ROOT, place a vendor copy under third_party/dbgeng, or provide DBGENG_INCLUDE_DIR and DBGENG_LIBRARY explicitly.")
endif()

message(STATUS "Using dbgeng include: ${_resolved_dbgeng_include}")
message(STATUS "Using dbgeng library: ${_resolved_dbgeng_library}")
if (DEFINED DEBUGGERS_ROOT_RESOLVED)
    message(STATUS "Resolved dbgeng root: ${DEBUGGERS_ROOT_RESOLVED}")
endif()
message(STATUS "DECOMP_USE_SYMBOL_ENTRY_APIS=${DECOMP_USE_SYMBOL_ENTRY_APIS}")

add_library(
    decomp_shared
    STATIC
    src/shared/json.cpp
    src/shared/protocol.cpp
    src/shared/analyzer.cpp
    src/shared/verifier.cpp
)

target_include_directories(
    decomp_shared
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_common_warnings(decomp_shared)

add_library(
    decomp_extension
    SHARED
    src/extension/extension.cpp
    src/extension/llm_client.cpp
    src/extension/decomp.def
)

target_include_directories(
    decomp_extension
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${_resolved_dbgeng_include}
)

target_link_libraries(
    decomp_extension
    PRIVATE
    decomp_shared
    ${_resolved_dbgeng_library}
    winhttp
)

if (DECOMP_USE_SYMBOL_ENTRY_APIS)
    target_compile_definitions(decomp_extension PRIVATE DECOMP_USE_SYMBOL_ENTRY_APIS=1)
else()
    target_compile_definitions(decomp_extension PRIVATE DECOMP_USE_SYMBOL_ENTRY_APIS=0)
endif()

set_target_properties(
    decomp_extension
    PROPERTIES
    OUTPUT_NAME "decomp"
)

set_common_warnings(decomp_extension)