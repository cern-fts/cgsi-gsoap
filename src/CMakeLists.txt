## default set of build


## defaults sources
SET(src_core_csgsi "cgsi_plugin.c")
SET(src_core_cgsi_header "cgsi_plugin.h")
SET(src_core_csgsi_cpp "${CMAKE_CURRENT_BINARY_DIR}/cgsi_plugin.cpp")

# create cpp one
configure_file(
    ${src_core_csgsi} ${src_core_csgsi_cpp}
    COPYONLY
)

# C
# globus
include_directories( " . " " /usr/include/voms "
    ${GSOAP_INCLUDES_DIR}
    ${VOMS_INCLUDE_DIRS}
    ${GLOBUS_GSSAPI_GSI_INCLUDE_DIRS}
    ${GLOBUS_GSS_ASSIST_INCLUDE_DIRS}
)
add_definitions(${GSOAP_DEFINITIONS} ${GLOBUS_GSSAPI_GSI_DEFINITIONS} ${GLOBUS_GSS_ASSIST_DEFINITIONS})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_library(cgsi_plugin STATIC ${src_core_csgsi})
else ()
    add_library(cgsi_plugin SHARED ${src_core_csgsi})
endif ()

target_link_libraries(cgsi_plugin
    ${GLOBUS_COMMON_LIBRARIES}
    ${GLOBUS_GSSAPI_GSI_LIBRARIES}
    ${GLOBUS_GSS_ASSIST_LIBRARIES}
    ${GLOBUS_GSI_CERT_UTILS_LIBRARIES}
    ${GLOBUS_GSI_CREDENTIAL_LIBRARIES}
    "c"
)

set_target_properties(cgsi_plugin PROPERTIES
    VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
    SOVERSION ${VERSION_MAJOR}
    CLEAN_DIRECT_OUTPUT 1
    OUTPUT_NAME "cgsi_plugin"						
)

# voms
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_library(cgsi_plugin_voms STATIC ${src_core_csgsi})
else ()
    add_library(cgsi_plugin_voms SHARED ${src_core_csgsi})
endif ()

target_link_libraries(cgsi_plugin_voms
    ${GLOBUS_GSSAPI_GSI_LIBRARIES}
    ${GLOBUS_GSS_ASSIST_LIBRARIES}
    ${VOMS_LIBRARIES}
    "c"
)

set_target_properties(cgsi_plugin_voms PROPERTIES
    VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
	SOVERSION ${VERSION_MAJOR}
	CLEAN_DIRECT_OUTPUT 1
	COMPILE_FLAGS " -DUSE_VOMS " 
	OUTPUT_NAME "cgsi_plugin_voms"						
)


## C++
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_library(cgsi_plugin_cpp STATIC ${src_core_csgsi_cpp})
else ()
    add_library(cgsi_plugin_cpp SHARED ${src_core_csgsi_cpp})
endif ()

target_link_libraries(cgsi_plugin_cpp
    ${GLOBUS_COMMON_LIBRARIES}
    ${GLOBUS_GSSAPI_GSI_LIBRARIES}
    ${GLOBUS_GSS_ASSIST_LIBRARIES}
    ${GLOBUS_GSI_CERT_UTILS_LIBRARIES}
    ${GLOBUS_GSI_CREDENTIAL_LIBRARIES}
    "c"
)

set_target_properties(cgsi_plugin_cpp PROPERTIES
    VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
    SOVERSION ${VERSION_MAJOR}
    CLEAN_DIRECT_OUTPUT 1
    OUTPUT_NAME "cgsi_plugin_cpp"						
)

# voms
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_library(cgsi_plugin_voms_cpp STATIC ${src_core_csgsi_cpp})
else ()
    add_library(cgsi_plugin_voms_cpp SHARED ${src_core_csgsi_cpp})
endif ()

target_link_libraries(cgsi_plugin_voms_cpp
    ${VOMS_LIBRARIES}
    ${GLOBUS_GSSAPI_GSI_LIBRARIES}
    ${GLOBUS_GSS_ASSIST_LIBRARIES}
    "c"
)

set_target_properties(cgsi_plugin_voms_cpp PROPERTIES
	VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
	SOVERSION ${VERSION_MAJOR}
	CLEAN_DIRECT_OUTPUT 1
	COMPILE_FLAGS " -DUSE_VOMS " 
	OUTPUT_NAME "cgsi_plugin_voms_cpp"						
)

install(TARGETS cgsi_plugin cgsi_plugin_voms cgsi_plugin_cpp cgsi_plugin_voms_cpp
		RUNTIME       DESTINATION ${BIN_INSTALL_DIR}
		LIBRARY       DESTINATION ${LIB_INSTALL_DIR}
        ARCHIVE       DESTINATION ${LIB_INSTALL_DIR}
)

install(FILES 	"cgsi_plugin.h"
		DESTINATION ${INCLUDE_INSTALL_DIR}/)
