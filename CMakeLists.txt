cmake_minimum_required(VERSION 3.13)
project(stice
	VERSION 0.10.0
	LANGUAGES CXX
	DESCRIPTION "C++17 ICE + TURN client (ported from pion/webrtc), libjuice replacement"
	HOMEPAGE_URL "https://github.com/zlyadvocate/stice")

# Project metadata
set(PROJECT_AUTHOR "zlyadvocate")
set(PROJECT_LICENSE "MPL-2.0")
set(PROJECT_DESCRIPTION_SUMMARY "C++17 ICE + TURN client library, libjuice replacement")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Source files (excluding stserver, tests, and interop — not needed by
# libdatachannel).  juice_compat.cpp provides the libjuice-compatible
# juice_* C API backed by stice_*.
# ---------------------------------------------------------------------------
set(STICE_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/src/log.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/crypto.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/addr.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/udp.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/tcp.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/poll.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/udp_mux.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/tcp_mux.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/net/mdns.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/stun/message.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/stun/attributes.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/stun/client.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/turn/channeldata.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/turn/stunconn.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/turn/turn.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice/candidate.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice/candidatepair.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice/sdp.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice/addr_rewrite.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice/agent.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice/pairing_strategy.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/c_api.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/juice_compat.cpp
)

set(STICE_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/include/stice/stice.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/juice/juice.h
)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# USE_TLS is set by the parent project (libdatachannel) when
# USE_JUICE_TLS=ON and the crypto backend is OpenSSL.
option(STICE_USE_OPENSSL "Use OpenSSL for HMAC/MD5/SHA and TURN over TLS" ON)
if(USE_TLS)
	set(STICE_USE_OPENSSL ON)
endif()
if(STICE_USE_OPENSSL)
	find_package(OpenSSL QUIET)
	if(OpenSSL_FOUND)
		set(STICE_HAVE_OPENSSL ON)
	endif()
endif()

if(WIN32)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	if(MSVC)
		add_definitions(-DNOMINMAX -D_CRT_SECURE_NO_WARNINGS)
		add_compile_options(/utf-8)
	endif()
endif()

# ---------------------------------------------------------------------------
# Helper: apply common settings to a stice target
# ---------------------------------------------------------------------------
function(stice_apply_common target_name)
	target_include_directories(${target_name} PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:include>)
	target_link_libraries(${target_name} PUBLIC Threads::Threads)
	if(WIN32)
		target_link_libraries(${target_name} PUBLIC ws2_32)
	endif()
	if(STICE_HAVE_OPENSSL)
		target_compile_definitions(${target_name} PUBLIC STICE_HAVE_OPENSSL=1)
		target_link_libraries(${target_name} PRIVATE OpenSSL::Crypto)
		if(TARGET OpenSSL::SSL)
			target_link_libraries(${target_name} PRIVATE OpenSSL::SSL)
		endif()
	endif()
	if(NOT MSVC)
		target_compile_options(${target_name} PRIVATE -Wall -Wextra)
	endif()
endfunction()

# ---------------------------------------------------------------------------
# juice target (respects BUILD_SHARED_LIBS from parent, same convention
# as libjuice).  Aliased as LibJuice::LibJuice so libdatachannel links
# against it without any source changes.
# ---------------------------------------------------------------------------
add_library(juice ${STICE_SOURCES} ${STICE_HEADERS})
set_target_properties(juice PROPERTIES VERSION ${PROJECT_VERSION})
target_compile_definitions(juice PRIVATE STICE_EXPORTS JUICE_EXPORTS)
if(NOT BUILD_SHARED_LIBS)
	target_compile_definitions(juice PUBLIC STICE_STATIC JUICE_STATIC)
endif()
stice_apply_common(juice)
set_target_properties(juice PROPERTIES EXPORT_NAME LibJuice C_VISIBILITY_PRESET hidden)
add_library(LibJuice::LibJuice ALIAS juice)

# ---------------------------------------------------------------------------
# juice-static target (always static, mirrors libjuice's juice-static).
# Aliased as LibJuice::LibJuiceStatic for datachannel-static linking.
# ---------------------------------------------------------------------------
add_library(juice-static STATIC EXCLUDE_FROM_ALL ${STICE_SOURCES} ${STICE_HEADERS})
set_target_properties(juice-static PROPERTIES VERSION ${PROJECT_VERSION})
target_compile_definitions(juice-static PRIVATE STICE_EXPORTS JUICE_EXPORTS)
target_compile_definitions(juice-static PUBLIC STICE_STATIC JUICE_STATIC)
stice_apply_common(juice-static)
set_target_properties(juice-static PROPERTIES EXPORT_NAME LibJuiceStatic)
add_library(LibJuice::LibJuiceStatic ALIAS juice-static)

# ---------------------------------------------------------------------------
# Installation (only when INSTALL_DEPS_LIBS is set by parent)
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS juice EXPORT LibJuiceTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES
	${CMAKE_CURRENT_SOURCE_DIR}/include/stice/stice.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/stice)
install(FILES
	${CMAKE_CURRENT_SOURCE_DIR}/include/juice/juice.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/juice)

# ---------------------------------------------------------------------------
# stserver: built-in TURN/STUN server (optional, default ON)
# ---------------------------------------------------------------------------
option(STICE_BUILD_STSERVER "Build the stice TURN/STUN server (stserver)" ON)
if(STICE_BUILD_STSERVER)
	set(STSERVER_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/main.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/config.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/turn_server.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/io_select.cpp
	)
	# Platform-specific accelerated IO backend (D plan).
	# io_select.cpp always provides createIoBackend() + SelectBackend fallback;
	# on Windows/Linux we additionally compile IOCP/epoll and enable STSERVER_IOCP.
	if(WIN32)
		list(APPEND STSERVER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/io_iocp.cpp)
		set(STSERVER_IO_DEFINE STSERVER_IOCP)
	elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
		list(APPEND STSERVER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/io_epoll.cpp)
		set(STSERVER_IO_DEFINE STSERVER_IOCP)
	endif()
	add_executable(stserver ${STSERVER_SOURCES})
	target_compile_definitions(stserver PRIVATE STICE_STATIC JUICE_STATIC ${STSERVER_IO_DEFINE})
	stice_apply_common(stserver)
	target_link_libraries(stserver PRIVATE LibJuice::LibJuiceStatic)
	if(WIN32 AND STICE_HAVE_OPENSSL)
		target_link_libraries(stserver PRIVATE crypt32)
	endif()
endif()

# ==============================================================================
# Tests 编译配置 + FetchContent 获取 Catch2
# ==============================================================================
option(STICE_BUILD_TESTS "Build stice unit tests" ON)
if (STICE_BUILD_TESTS)
    enable_testing()
    set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

    # Fetch Catch2 v3.4.0 from GitHub and build it as part of this project.
    # This replaces the previously vendored third_party/catch2 submodule.
    include(FetchContent)
    set(CATCH_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
    set(CATCH_INSTALL_EXTRAS OFF CACHE BOOL "" FORCE)
    set(CATCH_DEVELOPMENT_BUILD OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.4.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(Catch2)

    # 遍历所有测试文件，每个cpp单独生成一个exe
    file(GLOB ALL_TEST_CPP ${TEST_DIR}/*.cpp)
    foreach(test_src ${ALL_TEST_CPP})
        get_filename_component(test_name ${test_src} NAME_WE)
        add_executable(${test_name} ${test_src})
        stice_apply_common(${test_name})
        # Detect whether the test file provides its own main().
        # Catch2-only tests (TEST_CASE, no main) need Catch2WithMain;
        # standalone tests with int main() must not link it (duplicate symbol).
        file(READ ${test_src} test_src_content)
        string(FIND "${test_src_content}" "int main(" has_main)
        if(has_main EQUAL -1)
            target_link_libraries(${test_name}
                PRIVATE LibJuice::LibJuiceStatic Catch2::Catch2WithMain
            )
        else()
            target_link_libraries(${test_name}
                PRIVATE LibJuice::LibJuiceStatic Catch2::Catch2
            )
        endif()
        if (WIN32 AND STICE_HAVE_OPENSSL)
            target_link_libraries(${test_name} PRIVATE crypt32)
        endif()
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()
