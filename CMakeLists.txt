## cmake build script for cgsi GSOAP
## @author Devresse Adrien

project (cgsi-gsoap)
cmake_minimum_required (VERSION 2.6)

# build type
set(CMAKE_BUILD_TYPE "RelWithDebInfo"
    CACHE STRING "build type")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")
# load module
include(DefineInstallationPaths REQUIRED)
include(ReleaseDebugAutoFlags REQUIRED)

find_package(PkgConfig REQUIRED)

#enable testing
INCLUDE(CTest)


set(OUTPUT_NAME_DAVIX "cgsi-gsoap")
set(VERSION_MAJOR 1)
set(VERSION_MINOR 3)
set(VERSION_PATCH 7)
set(VERSION_STRING ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})


# libs checks
find_package(gSOAP REQUIRED)
find_package(VOMS REQUIRED)
find_package(Globus_COMMON REQUIRED)
find_package(Globus_GSSAPI_GSI REQUIRED)
find_package(Globus_GSS_ASSIST REQUIRED)
find_package(Globus_GSI_CERT_UTILS REQUIRED)
find_package(Globus_GSI_CREDENTIAL REQUIRED)

## general def
add_definitions(-D_GNU_SOURCE)
add_definitions(-D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64)

install(FILES README readme.html
    DESTINATION ${DOC_INSTALL_DIR}/)
install(FILES RELEASE-NOTES
		DESTINATION ${DOC_INSTALL_DIR}/)
install(FILES LICENSE
		DESTINATION ${DOC_INSTALL_DIR}/)

add_subdirectory (src)
