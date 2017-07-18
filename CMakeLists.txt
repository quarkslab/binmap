##################################################################################""
cmake_minimum_required(VERSION 3.2)
project(binmap C CXX)
include(ExternalProject)
##################################################################################""

##################################################################################""
# cmake extensions
##################################################################################""
set(LIEF_ROOT CACHE PATH "${CMAKE_INSTALL_PREFIX}")
set(LIEF_VERSION 0.7.0 CACHE STRING "LIEF version to be used")

option(USE_LIEF "Use LIEF as collector" ON)
set(LIEF_FROM_EXTERNAL_PROJECT OFF)

if(NOT EXISTS "${LIEF_ROOT}/share/LIEF/cmake" AND USE_LIEF)
  message(STATUS "Setting LIEF as an External project")
  set(LIEF_FROM_EXTERNAL_PROJECT ON)
  # Setup LIEF as an External Project
  set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
  set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
  set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

  # LIEF static library
  set(LIEF_LIBRARIES
    "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}")

  # URL of the LIEF repo (Can be your fork)
  set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

  # LIEF compilation config
  set(LIEF_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DCMAKE_BUILD_TYPE=Release
    -DLIEF_DOC=off
    -DLIEF_PYTHON_API=off
    -DLIEF_ENABLE_JSON=off
    -DLIEF_EXAMPLES=off
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
  )

  ExternalProject_Add(LIEF
    PREFIX           "${LIEF_PREFIX}"
    GIT_REPOSITORY   ${LIEF_GIT_URL}
    GIT_TAG          0.8.3
    INSTALL_DIR      ${LIEF_INSTALL_DIR}
    CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
    BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
    UPDATE_COMMAND   ""
  )
  set(LIEF_FOUND TRUE)
elseif(USE_LIEF)
  list(APPEND CMAKE_MODULE_PATH "${LIEF_ROOT}/share/LIEF/cmake" ${CMAKE_SOURCE_DIR}/cmake)
  include(FindLIEF)
  find_package(LIEF ${LIEF_VERSION} COMPONENTS STATIC)
endif()


##################################################################################""
# version
##################################################################################""
set(BINMAP_VERSION_MAJOR 0)
set(BINMAP_VERSION_MINOR 1)

##################################################################################""
# configure & options
##################################################################################""
option(BINMAP_FULL "Build ${CMAKE_PROJECT_NAME} tools in addition to the scanner" ON)
set(BINMAP_DRIVERS "native" CACHE STRING "drivers used by the scanners")


if(BINMAP_FULL)
    # full fledge mode, shared libraries etc
    set(Boost_USE_STATIC_LIBS OFF)
    set(Boost_USE_STATIC_RUNTIME OFF)
    if(WIN32)
        set(Boost_USE_MULTITHREADED ON)
        add_definitions(-DBOOST_ALL_DYN_LINK)
    else()
        set(Boost_USE_MULTITHREADED OFF)
    endif()
else()
    # think embded : static libraries
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(BUILD_SHARED_LIBS OFF)
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_MULTITHREADED OFF)
    set(Boost_USE_STATIC_RUNTIME ON)
    if(WIN32)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    else()
        set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc")
    endif()
endif()


# automatically compute default drivers
if("${BINMAP_DRIVERS}" STREQUAL native)
    set(BINMAP_DRIVERS "")
    set(BINMAP_DRIVER_LIBRARIES "")

    if(LIEF_FOUND)
        include_directories("${LIEF_INCLUDE_DIRS}")
        set(BINMAP_DRIVERS ${BINMAP_DRIVERS} ELF)
        set(BINMAP_DRIVER_LIBRARIES ${BINMAP_DRIVER_LIBRARIES} ${LIEF_LIBRARIES})
    endif()

    # LINK always set, boost filesystem handles it
    set(BINMAP_DRIVERS ${BINMAP_DRIVERS} PE LINK DEFAULT)
endif()

message(STATUS "Using following dependency drivers:")
foreach(LOOP_VAR ${BINMAP_DRIVERS})
    string(TOLOWER ${LOOP_VAR} BINMAP_DRIVER)
    message(STATUS "  ${BINMAP_DRIVER}")
endforeach()

# finally generate config file
configure_file("${PROJECT_SOURCE_DIR}/binmap_config.hpp.in" "${PROJECT_BINARY_DIR}/binmap_config.hpp")

##################################################################################""
# Auxillary tools
##################################################################################""
# when crosscompiling import the executable targets from a file
if(CMAKE_CROSSCOMPILING)
  if(BINMAP_NATIVE_BUILD)
  if( EXISTS "${BINMAP_NATIVE_BUILD}/" )
	if(EXISTS "${BINMAP_NATIVE_BUILD}/ImportExecutables.cmake")
		include("${CMAKE_BINARY_DIR}/${BINMAP_NATIVE_BUILD}/ImportExecutables.cmake")
	else()
		message(SEND_ERROR "file '${BINMAP_NATIVE_BUILD}/ImportExecutables.cmake' not found")
	endif()
  else()
	message(SEND_ERROR "native build '${BINMAP_NATIVE_BUILD}' not found")
  endif()
  else()
	message(SEND_ERROR "BINMAP_NATIVE_BUILD must be set to the relative native build location when cross compiling")
  endif()

endif()

# only build the generator if not crosscompiling
if(NOT CMAKE_CROSSCOMPILING)
   add_executable(mempack tools/mempack.cpp)
endif()

# export the generator target to a file, so it can be imported (see above) by another build
if(NOT CMAKE_CROSSCOMPILING)
  export(TARGETS mempack FILE ${CMAKE_BINARY_DIR}/ImportExecutables.cmake )
endif(NOT CMAKE_CROSSCOMPILING)

##################################################################################""
# libs
##################################################################################""

set(BOOST_COMPONENTS  system program_options filesystem regex serialization)
if(BINMAP_FULL)
    set(BOOST_COMPONENTS ${BOOST_COMPONENTS} python)
endif()
find_package(Boost 1.49 COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
find_package(ZLIB REQUIRED)
if(UNIX)
find_package(OpenSSL REQUIRED)
endif()
find_package(Threads)
if(BINMAP_FULL)
    find_package(PythonLibs 2.7 REQUIRED)
endif()

##################################################################################""
# paths
##################################################################################""
include_directories("${PROJECT_BINARY_DIR}"
    "${Boost_INCLUDE_DIR}"
    "${ZLIB_INCLUDE_DIR}"
    "${PROJECT_SOURCE_DIR}/include"
    )
if(BINMAP_FULL)
    include_directories("${PROJECT_BINARY_DIR}" ${PYTHON_INCLUDE_DIRS})
endif()
link_directories(${Boost_LIBRARY_DIRS})

##################################################################################""
# sources
##################################################################################""
set(BINMAP_SOURCES
    src/binmap.cpp
    src/blobmap.cpp
    src/collector.cpp
    src/env.cpp
    src/graph.cpp
    src/hash.cpp
    src/log.cpp
    src/metadata.cpp
    src/scan.cpp
    src/version.cpp
)
if (UNIX)
  list(APPEND BINMAP_SOURCES
    src/env_analyzers/linux_shared_library.cpp
  )
endif()
list(APPEND BINMAP_SOURCES src/env_analyzers/windows_shared_library.cpp)

# add specific drivers depending on the content of BINMAP_DRIVERS
# there are two ways to implement a driver:
#  - put a single my_driver.cpp file in src/collectors/
#  - fill a directory my_driver with any cpp files in src/collectors/
foreach(LOOP_VAR ${BINMAP_DRIVERS})
    string(TOLOWER ${LOOP_VAR} BINMAP_DRIVER)
    if(EXISTS ${CMAKE_SOURCE_DIR}/src/collectors/${BINMAP_DRIVER}.cpp)
        set(BINMAP_SOURCES ${BINMAP_SOURCES}
            src/collectors/${BINMAP_DRIVER}.cpp)
    else()
        file(GLOB DRIVER_SOURCES src/collectors/${BINMAP_DRIVER}/*.cpp)
        set(BINMAP_SOURCES ${BINMAP_SOURCES} ${DRIVER_SOURCES})
    endif()
endforeach()

if(BINMAP_FULL)
    set(BINMAP_SOURCES
        ${BINMAP_SOURCES}
        src/view.cpp
        )
endif()
add_executable(binmap ${BINMAP_SOURCES})
target_link_libraries(binmap
    ${Boost_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${BINMAP_DRIVER_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

if (USE_LIEF AND LIEF_FROM_EXTERNAL_PROJECT)
  add_dependencies(binmap LIEF)
endif()

if(BINMAP_FULL)
    target_link_libraries(binmap ${PYTHON_LIBRARIES})
    add_library(blobmap SHARED
        src/blobmap.cpp
        src/blobmap_wrapper.cpp
        src/graph.cpp
        src/hash.cpp
        src/log.cpp
        src/metadata.cpp
        )
    set_target_properties(blobmap PROPERTIES PREFIX "")
    if (WIN32)
        set_target_properties(example PROPERTIES SUFFIX ".pyd")
    endif()

    target_link_libraries(blobmap ${PYTHON_LIBRARIES} ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES})
endif()


##################################################################################""
# install
##################################################################################""
install (TARGETS binmap DESTINATION bin)

##################################################################################""
# testing
##################################################################################""
if(BINMAP_FULL)
	enable_testing()

    # create a few dummy executables for the tests
    add_executable(myprog tests/myprog.cpp)
    add_executable(mynewprog tests/mynewprog.cpp)
    add_library(mylib SHARED tests/mylib.cpp)
    add_library(otherlib SHARED tests/otherlib.cpp)
    target_link_libraries(myprog mylib)
    target_link_libraries(mynewprog mylib otherlib)

    # test help
    add_test(binmap_help binmap --help)

    # test scan
    add_test(binmap_scan_cleanup rm -f $(CMAKE_BINARY_DIR)/*.dat)
    add_test(binmap_scan_help binmap scan --help)
    add_test(binmap_scan_usr_bin binmap scan /usr/bin)
    add_test(binmap_scan_usr_bin_consistency python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; b =g.last() ; [g[k] for k in g.keys()]")
    add_test(binmap_scan_self binmap scan -oself.dat ./binmap)
    add_test(binmap_scan_other binmap scan -opyblobs.dat ./blobmap.so)
    add_test(binmap_scan_verbose_self binmap scan -v1 ./binmap)
    add_test(binmap_scan_verbose_output_self binmap scan -v2 -otest.dat ./binmap)
    add_test(binmap_scan_myprog  binmap scan -o myprog.dat ./myprog)
    add_test(binmap_scan_mynewprog  binmap scan -o mynewprog.dat ./myprog)
    add_test(binmap_scan_prog_again binmap scan -o mynewprog.dat ./mynewprog)
    add_test(binmap_scan_prog_again_and_again binmap scan -o mynewprog.dat ./myprog)
    add_test(binmap_scan_prog_space_in_name binmap scan -o space_in_name.dat "${CMAKE_SOURCE_DIR}/tests/space in name.exe")

    # test view
    add_test(binmap_view binmap view)
    add_test(binmap_view_help binmap view --help)
    add_test(binmap_view_input binmap view -itest.dat)
    add_test(binmap_view_output binmap view -otest.dot)
    add_test(binmap_view_input_output binmap view -itest.dat -otest.dot)

    # test scan in chroot mode
    #add_test(binmap_chroot_untar tar xzf ${CMAKE_SOURCE_DIR}/base.tar.gz)
    #add_test(binmap_chroot_create binmap scan -ochroot.dat --chroot ./base)
    #add_test(binmap_chroot_consistency  python -c "import blobmap ; g = blobmap.BlobMap('chroot.dat').last() ; [g[k] for k in g.keys()]")
    #add_test(binmap_chroot_aptitude_curses  python -c "import blobmap ; g = blobmap.BlobMap('chroot.dat').last() ; s = g.successors('/usr/bin/aptitude-curses') ; ref = set(s.strip() for s in open('${CMAKE_SOURCE_DIR}/tests/aptitude_successors.txt')) ; assert s.issubset(ref)")
    #add_test(binmap_chroot_libm  python -c "import blobmap ; g = blobmap.BlobMap('chroot.dat').last() ; s = g.predecessors('/lib/x86_64-linux-gnu/libm.so.6') ; ref = set(s.strip() for s in open('${CMAKE_SOURCE_DIR}/tests/libm_predecessors.txt')) ; print ref ; print s ; assert s.issubset(ref)")
    ##    set_tests_properties(binmap_chroot_create PROPERTIES DEPEND binmap_chroot_untar)

    # test scan of dummy windows archive
    add_test(binmap_pe_untar tar xzf ${CMAKE_SOURCE_DIR}/win95.tar.gz)
    add_test(binmap_pe_create binmap scan -owin95.dat --chroot ./win95)
    add_test(binmap_pe_consistency  python -c "import blobmap ; g = blobmap.BlobMap('win95.dat').last() ; [g[k] for k in g.keys()]")
    add_test(binmap_pe_calc  python -c "import blobmap ; g = blobmap.BlobMap('win95.dat').last() ; s = g.successors('/calc.exe') ; ref = set(s.strip() for s in open('${CMAKE_SOURCE_DIR}/tests/calc_successors.txt')) ; assert s.issubset(ref)")

    ## test scan of android archive
    #add_test(binmap_chroot_android_untar tar xzf ${CMAKE_SOURCE_DIR}/android.tar.gz )
    #add_test(binmap_chroot_android_create binmap scan -oandroid.dat --chroot ./android)
    #add_test(binmap_chroot_android_consistency  python -c "import blobmap ; g = blobmap.BlobMap('android.dat').last() ; [g[k] for k in g.keys()]")
    #set_tests_properties(binmap_chroot_android_create PROPERTIES DEPEND binmap_chroot_android_untar)

    # test nm feature
    add_test(binmap_python_interface_nm_imported python -c "from blobmap import BlobMap as BM ; b = BM('mynewprog.dat') ; g = b.last() ; mnp = g['${CMAKE_BINARY_DIR}/myprog']; assert  'dep' in mnp.imported_symbols")
    add_test(binmap_python_interface_nm_exported python -c "from blobmap import BlobMap as BM ; b = BM('mynewprog.dat') ; g = b.last() ; mnp = g['${CMAKE_BINARY_DIR}/libmylib.so']; assert  'dep' in mnp.exported_symbols")

    # test hardening feature
    add_test(binmap_hardening_all binmap scan -ohardening_all.dat ${CMAKE_SOURCE_DIR}/tests/hardening-all)
    add_test(binmap_hardening_none binmap scan -ohardening_none.dat ${CMAKE_SOURCE_DIR}/tests/hardening-none)
    add_test(binmap_python_interface_hardening_all python -c "from blobmap import BlobMap as BM ; g = BM('hardening_all.dat').last() ; assert g['${CMAKE_SOURCE_DIR}/tests/hardening-all'].hardening_features == {'fortified', 'stack-protected', 'immediate-binding', 'read-only-relocations', 'pie'}")
    add_test(binmap_python_interface_hardening_none python -c "from blobmap import BlobMap as BM ; g = BM('hardening_none.dat').last() ; assert not g['${CMAKE_SOURCE_DIR}/tests/hardening-none'].hardening_features")
    add_test(binmap_hardening_all_pe binmap scan -ohardening_all_pe.dat ${CMAKE_SOURCE_DIR}/tests/pe-hardening-all.exe)
    add_test(binmap_hardening_none_pe binmap scan -ohardening_none_pe.dat ${CMAKE_SOURCE_DIR}/tests/pe-hardening-none.exe)
    add_test(binmap_python_interface_hardening_all_pe python -c "from blobmap import BlobMap as BM ; g = BM('hardening_all_pe.dat').last() ; assert g['${CMAKE_SOURCE_DIR}/tests/pe-hardening-all.exe'].hardening_features == { 'pe-stack-protected', 'pe-safe-seh', 'pe-dynamic-base', 'pe-high-entropy-va', 'pe-force-integrity', 'pe-nx-compat', 'pe-appcontainer', 'pe-guard-cf'}")
    add_test(binmap_python_interface_hardening_none_pe python -c "from blobmap import BlobMap as BM ; g = BM('hardening_none_pe.dat').last() ; assert not g['${CMAKE_SOURCE_DIR}/tests/pe-hardening-none.exe'].hardening_features")

    # test python interface
    add_test(binmap_python_interface_blobmap_len python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; print len(g)")
    add_test(binmap_python_interface_blobmap_iterkeys python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; print len(list(g.keys()))")
    add_test(binmap_python_interface_blobmap_itervalues python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; print len(list(g.values()))")
    add_test(binmap_python_interface_blobmap_iter python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; print len(list(g))")
    add_test(binmap_python_interface_blobmap_iteritems python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; print len(list(g.items()))")
    add_test(binmap_python_interface_blobmap_last python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat') ; print g.last()")

    add_test(binmap_python_interface_blobmapview_len python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print len(g)")
    add_test(binmap_python_interface_blobmapview_iter python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print set(map(lambda x:x.name, g))")
    add_test(binmap_python_interface_blobmapview_keys python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print map(str, g.keys())")
    add_test(binmap_python_interface_blobmapview_values python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print map(str, g.values())")
    add_test(binmap_python_interface_blobmapview_items python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print list(g.items())")
    add_test(binmap_python_interface_blobmapview_successors python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; it = g.keys() ; print map(str, g.successors(next(it)))")
    add_test(binmap_python_interface_blobmapview_predecessors python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; it = g.keys() ; print map(str, g.predecessors(next(it)))")
    add_test(binmap_python_interface_blobmapview_filter0 python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print map(str, g.filter(lambda k, v, g: v.name.startswith('lib')))")
    add_test(binmap_python_interface_filter1 python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print map(str, g.filter(lambda k, v, g: v.name.startswith('lib') and len(g.successors(k)) == 1))")
    add_test(binmap_python_interface_project_name python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print g.project(lambda x: x.name).dot('test.dot')")
    add_test(binmap_python_interface_project_hash python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; print g.project(lambda x: x.hash).dot('test.dot')")
    add_test(binmap_python_interface_diff python -c "import blobmap ; g = blobmap.BlobMap('blobs.dat').last() ; q = blobmap.BlobMap('pyblobs.dat').last() ; d = q.diff(g)")
    add_test(binmap_python_interface_diff_prog_new_prog python -c "from blobmap import BlobMap as BM ; b = BM('mynewprog.dat') ; g1, g0 = [b[k] for k in b.keys()][-2:] ; d = g0.diff(g1) ; assert '${CMAKE_BINARY_DIR}/libotherlib.so' in d.added")
    add_test(binmap_python_interface_diff_prog_new_prog_updated python -c "from blobmap import BlobMap as BM ; b = BM('mynewprog.dat') ; g0, g1 = [b[k] for k in b.keys()][-2:] ; d = g0.diff(g1) ; assert not d.updated")
    add_test(binmap_python_interface_json python -c "from blobmap import BlobMap as BM ; b = BM('mynewprog.dat') ; g0, g1 = [b[k] for k in b.keys()][-2:] ; js = g0.json() ; import json ; json.loads(js)")

    # test version CLI
    add_test(binmap_version binmap --version)
    set_tests_properties(binmap_version PROPERTIES PASS_REGULAR_EXPRESSION "[0-9].[0-9]")
endif()
