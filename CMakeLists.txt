cmake_minimum_required(VERSION 3.13)
project(stice
	VERSION 0.13.1
	LANGUAGES CXX C
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

# ---------------------------------------------------------------------------
# Event-loop backend: an epoll-style API is used wherever one exists, so the
# PollRegistry event loop in src/net/poll.cpp has ONE epoll implementation for
# both platforms; only the handle create/close and the one-shot sticePoll()
# helper are platform specific:
#   * Windows -> wepoll (IOCP-based epoll implementation, src/wepoll/)
#   * Linux   -> the native epoll(7) API (src/net/epoll_poll.cpp)
#   * other POSIX (macOS/BSD) -> poll(2) fallback, no extra sources
# STICE_EPOLL_BACKEND=1 is exported to every stice target (see
# stice_apply_common) so the public header and the compiled sources agree.
# ---------------------------------------------------------------------------
if(WIN32)
	list(APPEND STICE_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/src/net/wepoll_poll.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/wepoll/wepoll.c
	)
	# wepoll.c is C; keep it compiled as C so its epoll_* symbols are unmangled
	# (matching the extern "C" declarations used by poll.cpp / wepoll_poll.cpp).
	set_source_files_properties(
		${CMAKE_CURRENT_SOURCE_DIR}/src/wepoll/wepoll.c PROPERTIES LANGUAGE C)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	# Native epoll(7) implementation of the sticePoll() one-shot helper. The
	# event loop itself needs no extra source: poll.cpp includes <sys/epoll.h>
	# directly on Linux.
	list(APPEND STICE_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/src/net/epoll_poll.cpp)
endif()

set(STICE_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/include/stice/stice.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/juice/juice.h
)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# TLS backend for TURN over TLS (RFC 8656 §4).
#
# The selection mirrors libdatachannel so that a parent project which already
# picked a crypto backend for libdatachannel gets the same backend here with no
# extra configuration — stice reads the very same cache variables:
#
#   USE_GNUTLS=ON   -> GnuTLS   (find_package(GnuTLS), target GnuTLS::GnuTLS,
#                               compile definition USE_GNUTLS=1)
#   USE_MBEDTLS=ON  -> Mbed TLS (find_package(MbedTLS), target MbedTLS::MbedTLS,
#                               compile definition USE_MBEDTLS=1)
#   otherwise       -> OpenSSL  (find_package(OpenSSL), USE_GNUTLS=0)
#
# Enabling GnuTLS and Mbed TLS together is a configuration error, exactly as in
# libdatachannel. Standalone builds may use the STICE_USE_* aliases instead of
# libdatachannel's names. With no backend at all (STICE_USE_OPENSSL=OFF and
# neither GnuTLS nor Mbed TLS) stice still builds; TURN over TLS then degrades
# to plain TCP, as it did before TLS support existed.
#
# Note: the ICE/STUN/TURN crypto primitives (MD5/SHA/HMAC/CRC32/CSPRNG) stay
# self-contained in src/crypto/crypto.cpp — they never depended on OpenSSL, and
# the TLS library is used only for the TLS record layer.
# ---------------------------------------------------------------------------
option(STICE_USE_OPENSSL "Use OpenSSL for TURN over TLS" ON)
option(STICE_USE_GNUTLS "Use GnuTLS for TURN over TLS (same as USE_GNUTLS)" OFF)
option(STICE_USE_MBEDTLS "Use Mbed TLS for TURN over TLS (same as USE_MBEDTLS)" OFF)

if(USE_GNUTLS AND USE_MBEDTLS)
	message(FATAL_ERROR "Both USE_MBEDTLS and USE_GNUTLS cannot be enabled at the same time")
endif()
if((USE_GNUTLS OR STICE_USE_GNUTLS) AND (USE_MBEDTLS OR STICE_USE_MBEDTLS))
	message(FATAL_ERROR "Both STICE_USE_MBEDTLS and STICE_USE_GNUTLS cannot be enabled at the same time")
endif()

# USE_TLS is set by some parents (libdatachannel integrations that only set
# USE_TLS) to mean "TLS enabled with the default backend".
if(USE_TLS)
	set(STICE_USE_OPENSSL ON)
endif()

set(STICE_TLS_BACKEND "none")
if(USE_GNUTLS OR STICE_USE_GNUTLS)
	find_package(GnuTLS REQUIRED)
	if(NOT TARGET GnuTLS::GnuTLS)
		# Same fallback libdatachannel uses for older CMake/FindGnuTLS.
		add_library(GnuTLS::GnuTLS UNKNOWN IMPORTED)
		set_target_properties(GnuTLS::GnuTLS PROPERTIES
			INTERFACE_INCLUDE_DIRECTORIES "${GNUTLS_INCLUDE_DIRS}"
			INTERFACE_COMPILE_DEFINITIONS "${GNUTLS_DEFINITIONS}"
			IMPORTED_LINK_INTERFACE_LANGUAGES C
			IMPORTED_LOCATION "${GNUTLS_LIBRARIES}")
	endif()
	set(STICE_TLS_BACKEND "gnutls")
	set(STICE_TLS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/net/tls_gnutls.cpp)
	set(STICE_TLS_LIBRARIES GnuTLS::GnuTLS)
elseif(USE_MBEDTLS OR STICE_USE_MBEDTLS)
	# Prefer the package config (Mbed TLS 3.x ships MbedTLS::MbedTLS, 2.x only
	# the three component targets); fall back to a plain header/library search
	# so both the 2.28 and the 3.x series work.
	if(NOT TARGET MbedTLS::MbedTLS AND NOT TARGET MbedTLS::mbedtls)
		find_package(MbedTLS 3 QUIET)
	endif()
	if(NOT TARGET MbedTLS::MbedTLS AND NOT TARGET MbedTLS::mbedtls)
		find_package(MbedTLS QUIET)
	endif()
	if(TARGET MbedTLS::MbedTLS)
		set(STICE_TLS_LIBRARIES MbedTLS::MbedTLS)
	elseif(TARGET MbedTLS::mbedtls)
		set(STICE_TLS_LIBRARIES MbedTLS::mbedtls)
		foreach(mbed_component mbedx509 mbedcrypto)
			if(TARGET MbedTLS::${mbed_component})
				list(APPEND STICE_TLS_LIBRARIES MbedTLS::${mbed_component})
			endif()
		endforeach()
	else()
		find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)
		find_library(MBEDTLS_LIBRARY NAMES mbedtls)
		find_library(MBEDX509_LIBRARY NAMES mbedx509)
		find_library(MBEDCRYPTO_LIBRARY NAMES mbedcrypto)
		if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_LIBRARY)
			message(FATAL_ERROR
				"Mbed TLS not found (USE_MBEDTLS): point CMAKE_PREFIX_PATH at an "
				"Mbed TLS 2.x/3.x installation, or set STICE_USE_MBEDTLS=OFF.")
		endif()
		set(STICE_TLS_LIBRARIES ${MBEDTLS_LIBRARY})
		foreach(mbed_lib MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
			if(${mbed_lib})
				list(APPEND STICE_TLS_LIBRARIES ${${mbed_lib}})
			endif()
		endforeach()
		set(STICE_MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
	endif()
	set(STICE_TLS_BACKEND "mbedtls")
	set(STICE_TLS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/net/tls_mbedtls.cpp)
elseif(STICE_USE_OPENSSL)
	find_package(OpenSSL QUIET)
	if(OpenSSL_FOUND)
		set(STICE_TLS_BACKEND "openssl")
		set(STICE_TLS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/net/tls_openssl.cpp)
		set(STICE_TLS_LIBRARIES OpenSSL::Crypto)
		if(TARGET OpenSSL::SSL)
			list(APPEND STICE_TLS_LIBRARIES OpenSSL::SSL)
		endif()
		set(STICE_HAVE_OPENSSL ON)
	endif()
endif()

if(STICE_TLS_BACKEND STREQUAL "none")
	message(WARNING
		"stice: building without a TLS backend — TURN over TLS will fall back to "
		"plain TCP. Enable OpenSSL (default), or USE_GNUTLS / USE_MBEDTLS.")
	set(STICE_TLS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/net/tls_none.cpp)
endif()
message(STATUS "stice: TLS backend = ${STICE_TLS_BACKEND}")
list(APPEND STICE_SOURCES ${STICE_TLS_SOURCES})

if(WIN32)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	if(MSVC)
		add_definitions(-DNOMINMAX -D_CRT_SECURE_NO_WARNINGS)
		add_compile_options(/utf-8)
	endif()
endif()

# ---------------------------------------------------------------------------
# Developer / CI hardening switches (both default OFF so release consumers are
# unaffected). Enable in CI to catch the classes of defect static review cannot:
#   STICE_WARNINGS_AS_ERRORS=ON  -> /W4 /WX (MSVC) or -Werror (GCC/Clang)
#   STICE_ENABLE_SANITIZERS=ON   -> AddressSanitizer (MSVC) or
#                                   ASan+UBSan (GCC/Clang)
# Recommended CI: one plain unit-test run, one sanitizer run, and a periodic
# ThreadSanitizer run of the multi-threaded paths.
# ---------------------------------------------------------------------------
option(STICE_WARNINGS_AS_ERRORS "Fail the build on any enabled compiler warning" OFF)
option(STICE_ENABLE_SANITIZERS "Build with AddressSanitizer/UBSan (debugging only)" OFF)

# ---------------------------------------------------------------------------
# Helper: apply common settings to a stice target
# ---------------------------------------------------------------------------
function(stice_apply_common target_name)
	target_include_directories(${target_name} PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
		$<INSTALL_INTERFACE:include>)
	target_link_libraries(${target_name} PUBLIC Threads::Threads)
	# Event-loop backend selector: 1 where an epoll-style backend exists
	# (Windows/wepoll, Linux/native epoll), 0 elsewhere (poll(2) fallback).
	# PUBLIC because it changes PollRegistry's member layout in the public
	# header include/stice/net/poll.hpp, so every consumer that links stice
	# must be compiled against the same value.
	if(WIN32 OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
		target_compile_definitions(${target_name} PUBLIC STICE_EPOLL_BACKEND=1)
	else()
		target_compile_definitions(${target_name} PUBLIC STICE_EPOLL_BACKEND=0)
	endif()
	if(WIN32)
		# ws2_32: sockets. bcrypt: BCryptGenRandom, the CSPRNG in
		# src/crypto/crypto.cpp (MSVC picks it up from the #pragma comment in
		# that file, other toolchains such as MinGW-w64 need it on the link
		# line).
		target_link_libraries(${target_name} PUBLIC ws2_32 bcrypt)
	endif()
	if(STICE_HAVE_OPENSSL)
		target_compile_definitions(${target_name} PUBLIC STICE_HAVE_OPENSSL=1)
	endif()
	# TLS record-layer backend (exactly one file of src/net/tls_*.cpp is
	# compiled, see the backend selection above). STICE_TLS_BACKEND is exposed
	# as a PRIVATE compile definition so the sources and the C API's
	# stice_get_tls_backend() agree with what was actually linked.
	if(STICE_TLS_BACKEND STREQUAL "openssl")
		target_compile_definitions(${target_name} PRIVATE STICE_TLS_OPENSSL=1 STICE_TLS_BACKEND_NAME="openssl")
	elseif(STICE_TLS_BACKEND STREQUAL "gnutls")
		target_compile_definitions(${target_name} PRIVATE STICE_TLS_GNUTLS=1 STICE_TLS_BACKEND_NAME="gnutls")
	elseif(STICE_TLS_BACKEND STREQUAL "mbedtls")
		target_compile_definitions(${target_name} PRIVATE STICE_TLS_MBEDTLS=1 STICE_TLS_BACKEND_NAME="mbedtls")
		if(STICE_MBEDTLS_INCLUDE_DIRS)
			target_include_directories(${target_name} PRIVATE ${STICE_MBEDTLS_INCLUDE_DIRS})
		endif()
	else()
		target_compile_definitions(${target_name} PRIVATE STICE_TLS_NONE=1 STICE_TLS_BACKEND_NAME="none")
	endif()
	if(STICE_TLS_LIBRARIES)
		target_link_libraries(${target_name} PRIVATE ${STICE_TLS_LIBRARIES})
	endif()
	if(MSVC)
		if(STICE_WARNINGS_AS_ERRORS)
			target_compile_options(${target_name} PRIVATE /W4 /WX)
		endif()
		if(STICE_ENABLE_SANITIZERS)
			target_compile_options(${target_name} PRIVATE /fsanitize=address)
			target_link_options(${target_name} PRIVATE /fsanitize=address)
		endif()
	else()
		target_compile_options(${target_name} PRIVATE -Wall -Wextra)
		if(STICE_WARNINGS_AS_ERRORS)
			target_compile_options(${target_name} PRIVATE -Werror)
		endif()
		if(STICE_ENABLE_SANITIZERS)
			target_compile_options(${target_name} PRIVATE
				-fsanitize=address,undefined -fno-omit-frame-pointer)
			target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
		endif()
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
	#
	# Default is the platform's accelerated backend on BOTH platforms:
	#   * Windows -> IocpBackend (io_iocp.cpp). The single-in-flight recv fix
	#     (at most one WSARecvFrom per socket, CancelIoEx instead of the
	#     cross-thread no-op CancelIo, and a stale-completion identity guard)
	#     removed the "rx_total > sent_total" over-delivery that used to force
	#     SelectBackend here.
	#   * Linux -> EpollBackend (io_epoll.cpp). It used to be opt-in because it
	#     over-delivered on TURN-over-TCP (rx_total > sent_total). The root cause
	#     turned out to be the stserver RFC 6062 data pipe itself, not the event
	#     loop: the IO-worker fast path could overtake a chunk queued during the
	#     pair-publish window, so the peer received whole app frames OUT OF ORDER;
	#     the de-framer then read payload bytes as a length and inflated rx_total.
	#     Fixed by routing data-pipe chunks through one ordered path (see
	#     ioOnTcpConnData) plus two TURN-client hand-off fixes.
	# Verified byte-exact at 10 clients x 4 MiB/s and 40 clients x 1 MiB/s
	# (tcpturn + udpturn) on both backends.
	#
	# STICE_STSERVER_USE_SELECT=ON still forces SelectBackend on all platforms
	# (escape hatch for bisecting the data plane).
	if(WIN32)
		set(STICE_STSERVER_USE_SELECT_DEFAULT OFF) # IOCP
	else()
		set(STICE_STSERVER_USE_SELECT_DEFAULT OFF) # native epoll
	endif()
	option(STICE_STSERVER_USE_SELECT
		"stserver: force SelectBackend on all platforms (default OFF = IOCP on Windows, epoll on Linux)"
		${STICE_STSERVER_USE_SELECT_DEFAULT})
	if(NOT STICE_STSERVER_USE_SELECT AND WIN32)
		list(APPEND STSERVER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/io_iocp.cpp)
		set(STSERVER_IO_DEFINE STSERVER_IOCP)
	elseif(NOT STICE_STSERVER_USE_SELECT AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
		list(APPEND STSERVER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/stserver/io_epoll.cpp)
		set(STSERVER_IO_DEFINE STSERVER_IOCP)
	endif()
	add_executable(stserver ${STSERVER_SOURCES})
	target_compile_definitions(stserver PRIVATE STICE_STATIC JUICE_STATIC ${STSERVER_IO_DEFINE})
	if(WIN32)
		# FD_SETSIZE is a per-TU macro and the Winsock default is 64: without this
		# the select backend's fd_set would silently stop monitoring relay/TCP
		# sockets past 64 per worker. Define it for EVERY stserver TU (the source
		# files also guard it locally, so non-CMake builds stay correct).
		target_compile_definitions(stserver PRIVATE FD_SETSIZE=8192)
	endif()
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
        # Test fixtures (TLS test certificate/key live in tests/data).
        target_compile_definitions(${test_name} PRIVATE STICE_TEST_DATA_DIR="${TEST_DIR}/data")
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
