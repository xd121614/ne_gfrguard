# gfrguard — Anti-ransomware protection suite
# CMake build for daemon, recover, VFS module, and unit tests.
#
# Quick start:
#   cmake -B build && cmake --build build              # daemon + recover + tests
#   cmake -B build -DBUILD_VFS=ON -DSAMBA_SRC=/path/to/samba-source && cmake --build build
#   cd build && ctest --output-on-failure               # run unit tests

cmake_minimum_required(VERSION 3.10)
project(gfrguard
    VERSION 1.0.0
    DESCRIPTION "GF2000 anti-ransomware protection (daemon + VFS + recover)"
    LANGUAGES C
)

# ── Standard ────────────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Compiler flags ──────────────────────────────────────────────────────────
add_compile_definitions(_GNU_SOURCE)
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR NOT DEFINED CMAKE_BUILD_TYPE)
    add_compile_options(-g -O0)
else()
    add_compile_options(-O2)
endif()

# ── Dependencies ────────────────────────────────────────────────────────────
find_package(PkgConfig)

# sqlite3
pkg_check_modules(SQLITE3 sqlite3)
if(NOT SQLITE3_FOUND)
    # Fallback: try find_library + find_path
    find_library(SQLITE3_LIBRARY sqlite3 REQUIRED)
    find_path(SQLITE3_INCLUDE_DIR sqlite3.h REQUIRED)
    set(SQLITE3_LIBRARIES ${SQLITE3_LIBRARY})
    set(SQLITE3_INCLUDE_DIRS ${SQLITE3_INCLUDE_DIR})
endif()

# yara
pkg_check_modules(YARA yara)
if(NOT YARA_FOUND)
    find_library(YARA_LIBRARY yara)
    find_path(YARA_INCLUDE_DIR yara.h)
    if(YARA_LIBRARY AND YARA_INCLUDE_DIR)
        set(YARA_LIBRARIES ${YARA_LIBRARY})
        set(YARA_INCLUDE_DIRS ${YARA_INCLUDE_DIR})
        set(YARA_FOUND TRUE)
    endif()
endif()

find_library(M_LIB m REQUIRED)
find_package(Threads REQUIRED)

# ── Common static library ───────────────────────────────────────────────────
set(COMMON_SRCS
    src/common/rguard_errors.c
    src/common/rguard_log.c
    src/common/rguard_config.c
    src/common/rguard_db.c
    src/common/cJSON.c
)
add_library(rguard_common STATIC ${COMMON_SRCS})
target_include_directories(rguard_common
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    PRIVATE ${SQLITE3_INCLUDE_DIRS}
)
target_link_libraries(rguard_common PUBLIC ${SQLITE3_LIBRARIES})

# ── Daemon library (without main.c — shared between daemon and tests) ───────
set(DAEMON_LIB_SRCS
    src/daemon/gfrguardd_session.c
    src/daemon/gfrguardd_scorer.c
    src/daemon/gfrguardd_blocker.c
    src/daemon/gfrguardd_restore.c
    src/daemon/gfrguardd_space.c
    src/daemon/gfrguardd_entropy.c
    src/daemon/gfrguardd_yara.c
    src/daemon/gfrguardd_fanotify.c
    src/daemon/gfrguardd_fanchannel.c
    src/daemon/gfrguardd_fangate.c
    src/daemon/gfrguardd_ftp.c
    src/daemon/gfrguardd_cloud.c
    src/daemon/gfrguardd_local.c
)
add_library(rguard_daemon_lib STATIC ${DAEMON_LIB_SRCS})
target_include_directories(rguard_daemon_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/src/common
)
target_link_libraries(rguard_daemon_lib PUBLIC rguard_common ${M_LIB})
# yara is optional — daemon compiles without it (yara calls become no-ops)
if(YARA_FOUND)
    target_include_directories(rguard_daemon_lib PUBLIC ${YARA_INCLUDE_DIRS})
    target_link_libraries(rguard_daemon_lib PUBLIC ${YARA_LIBRARIES})
    target_compile_definitions(rguard_daemon_lib PUBLIC HAVE_YARA=1)
endif()

# ── Daemon executable (main.c + daemon library) ─────────────────────────────
add_executable(gfrguardd src/daemon/gfrguardd_main.c)
target_link_libraries(gfrguardd
    rguard_daemon_lib
    rguard_common
    ${SQLITE3_LIBRARIES}
    ${M_LIB}
    Threads::Threads
)
if(YARA_FOUND)
    target_link_libraries(gfrguardd ${YARA_LIBRARIES})
endif()

# ── Recover executable ──────────────────────────────────────────────────────
set(RECOVER_SRCS
    src/recover/gfrguard_recover.c
    src/daemon/gfrguardd_blocker.c
)
add_executable(gfrguard-recover ${RECOVER_SRCS})
target_include_directories(gfrguard-recover
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/recover
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/common
)
target_link_libraries(gfrguard-recover
    rguard_common
    ${SQLITE3_LIBRARIES}
    Threads::Threads
)

# ── VFS shared module (optional, needs Samba source headers) ────────────────
option(BUILD_VFS "Build the Samba VFS module gfrguard.so" OFF)

if(BUILD_VFS OR DEFINED ENV{SAMBA_SRC})
    # SAMBA_SRC can be passed as -DSAMBA_SRC=/path or via environment
    if(NOT SAMBA_SRC AND DEFINED ENV{SAMBA_SRC})
        set(SAMBA_SRC $ENV{SAMBA_SRC})
    endif()

    if(SAMBA_SRC)
        message(STATUS "Samba source: ${SAMBA_SRC}")
        set(SAMBA_BIN "${SAMBA_SRC}/bin/default")

        add_library(gfrguard_vfs MODULE
            src/vfs/vfs_gfrguard.c
            src/common/cJSON.c
        )
        target_include_directories(gfrguard_vfs
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/common
            PRIVATE ${SAMBA_BIN}/include
            PRIVATE ${SAMBA_BIN}
            PRIVATE ${SAMBA_BIN}/source3
            PRIVATE ${SAMBA_BIN}/source3/include
            PRIVATE ${SAMBA_SRC}
            PRIVATE ${SAMBA_SRC}/source3/include
            PRIVATE ${SAMBA_SRC}/source3
            PRIVATE ${SAMBA_SRC}/lib/replace
            PRIVATE ${SAMBA_SRC}/lib/talloc
            PRIVATE ${SAMBA_SRC}/include
        )
        target_compile_definitions(gfrguard_vfs PRIVATE _GNU_SOURCE)
        set_target_properties(gfrguard_vfs PROPERTIES
            PREFIX ""
            SUFFIX ".so"
            OUTPUT_NAME "gfrguard"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        )
        install(TARGETS gfrguard_vfs
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/samba/vfs"
        )
    else()
        message(WARNING "BUILD_VFS=ON but SAMBA_SRC not set — skipping VFS module")
    endif()
endif()

# ── Install rules ───────────────────────────────────────────────────────────
install(TARGETS gfrguardd        RUNTIME DESTINATION sbin)
install(TARGETS gfrguard-recover RUNTIME DESTINATION bin)

# ── Unit tests (L2) ─────────────────────────────────────────────────────────
option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    enable_testing()

    # Each test compiles its sources directly instead of linking the
    # static libs: several tests stub functions (fanotify, process_msg)
    # that the libs also define — raw sources never collide.
    set(TEST_CFLAGS
        -std=c17 -Wall -Wextra -Wno-unused-parameter
    )
    set(TEST_INC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${SQLITE3_INCLUDE_DIRS}
        ${YARA_INCLUDE_DIRS}
    )
    set(TEST_LIBS
        ${SQLITE3_LIBRARIES}
        ${M_LIB}
        Threads::Threads
    )
    if(YARA_FOUND)
        list(APPEND TEST_LIBS ${YARA_LIBRARIES})
    endif()

    # Source sets (same grouping as the production libs)
    set(CS
        src/common/rguard_errors.c
        src/common/rguard_log.c
        src/common/rguard_config.c
        src/common/rguard_db.c
        src/common/cJSON.c
    )
    set(DS
        src/daemon/gfrguardd_session.c
        src/daemon/gfrguardd_scorer.c
        src/daemon/gfrguardd_entropy.c
        src/daemon/gfrguardd_blocker.c
    )
    set(DS2 ${DS}
        src/daemon/gfrguardd_yara.c
        src/daemon/gfrguardd_restore.c
        src/daemon/gfrguardd_space.c
    )
    set(CH
        src/daemon/gfrguardd_ftp.c
        src/daemon/gfrguardd_local.c
        src/daemon/gfrguardd_fanchannel.c
        src/daemon/gfrguardd_cloud.c
    )

    # gfr_test(<name> SOURCES ... [DEFS ...])
    function(gfr_test name)
        cmake_parse_arguments(T "" "" "SOURCES;DEFS" ${ARGN})
        add_executable(${name} ${T_SOURCES})
        target_include_directories(${name} PRIVATE ${TEST_INC})
        target_compile_options(${name} PRIVATE ${TEST_CFLAGS})
        if(T_DEFS)
            target_compile_definitions(${name} PRIVATE ${T_DEFS})
        endif()
        target_link_libraries(${name} ${TEST_LIBS})
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    gfr_test(test_protocol  SOURCES tests/test_protocol.c ${CS})
    gfr_test(test_entropy   SOURCES tests/test_entropy.c ${DS} ${CS})
    gfr_test(test_session   SOURCES tests/test_session.c ${DS} ${CS})
    gfr_test(test_scorer    SOURCES tests/test_scorer.c ${DS} ${CS})
    gfr_test(test_config    SOURCES tests/test_config.c ${CS})
    gfr_test(test_db        SOURCES tests/test_db.c ${CS})
    gfr_test(test_blacklist SOURCES tests/test_blacklist.c ${DS} ${CS})
    gfr_test(test_fangate   SOURCES tests/test_fangate.c
             src/daemon/gfrguardd_fangate.c)
    gfr_test(test_backup    SOURCES tests/test_backup.c)
    gfr_test(test_blocker   SOURCES tests/test_blocker.c ${DS} ${CS})
    gfr_test(test_space     SOURCES tests/test_space.c
             src/daemon/gfrguardd_space.c ${CS})
    gfr_test(test_log       SOURCES tests/test_log.c ${CS})
    gfr_test(test_channels  SOURCES tests/test_channels.c ${CH} ${DS} ${CS}
             DEFS NEO_CRONER_TIMEOUT_MS=400)
    gfr_test(test_hash      SOURCES tests/test_hash.c)
    gfr_test(test_restore   SOURCES tests/test_restore.c
             src/daemon/gfrguardd_restore.c ${CS}
             DEFS RECOVER_BIN=\"/bin/true\")
    gfr_test(test_recover   SOURCES tests/test_recover.c
             src/daemon/gfrguardd_blocker.c ${CS})

    if(YARA_FOUND)
        gfr_test(test_yara  SOURCES tests/test_yara.c
                 src/daemon/gfrguardd_yara.c ${CS})
    else()
        message(STATUS "yara not found — test_yara skipped")
    endif()

    # daemon_main: main.c with renamed entry + redirected RUN_DIR so the
    # test can call daemon_main() and process_msg() directly.
    add_library(daemon_main_obj OBJECT src/daemon/gfrguardd_main.c)
    target_include_directories(daemon_main_obj PRIVATE ${TEST_INC})
    target_compile_definitions(daemon_main_obj PRIVATE
        main=daemon_main RUN_DIR=\"/tmp/tmain_run\")
    gfr_test(test_main_daemon SOURCES
        tests/test_main_daemon.c $<TARGET_OBJECTS:daemon_main_obj> ${DS2} ${CS})
endif()
