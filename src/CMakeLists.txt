## default set of build

	


## defaults sources
SET(src_core_csgsi "cgsi_plugin.c")
SET(src_core_cgsi_header "cgsi_plugin.h")
SET(src_core_csgsi_cpp "${CMAKE_CURRENT_BINARY_DIR}/cgsi_plugin.cpp")

# create cpp one
configure_file(${src_core_csgsi} ${src_core_csgsi_cpp}
                 COPYONLY )
configure_file(${src_core_cgsi_header} ${src_core_cgsi_header_cpp}
COPYONLY )

# C
# globus
include_directories( " . " " /usr/include/voms " ${GSOAP_PKG_INCLUDES_DIR} ${VOMS_PKG_INCLUDE_DIRS} ${GLOBUS_ASSIST_PKG_INCLUDE_DIRS} )
add_definitions( ${GSOAP_PKG_CFLAGS} ${GLOBUS_ASSIST_PKG_CFLAGS} )
add_library(cgsi_plugin  SHARED ${src_core_csgsi}  )

target_link_libraries(cgsi_plugin ${GLOBUS_GSSAPI_GSI_PKG_LIBRARIES} ${GLOBUS_ASSIST_PKG_LIBRARIES} "c" )

set_target_properties(cgsi_plugin	 	PROPERTIES
								VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
								SOVERSION ${VERSION_MAJOR}
								CLEAN_DIRECT_OUTPUT 1
								OUTPUT_NAME "cgsi_plugin"						
)

# voms
add_library(cgsi_plugin_voms  SHARED ${src_core_csgsi}  )

target_link_libraries(cgsi_plugin_voms ${GLOBUS_GSSAPI_GSI_PKG_LIBRARIES} ${VOMS_PKG_LIBRARIES}  ${GLOBUS_ASSIST_PKG_LIBRARIES} "c" )

set_target_properties(cgsi_plugin_voms	 	PROPERTIES
								VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
								SOVERSION ${VERSION_MAJOR}
								CLEAN_DIRECT_OUTPUT 1
								COMPILE_FLAGS " -DUSE_VOMS ${VOMS_PKG_CFLAGS}"
								OUTPUT_NAME "cgsi_plugin_voms"						
)


## C++
# globus
include_directories( "-I." "-I/usr/include/voms" ${GSOAP_PKG_INCLUDES_DIR} ${VOMS_PKG_INCLUDE_DIRS} ${GLOBUS_ASSIST_PKG_INCLUDE_DIRS} )
add_definitions( ${GSOAP_PKG_CFLAGS} ${VOMS_PKG_CFLAGS} ${GLOBUS_ASSIST_PKG_CFLAGS} )
add_library(cgsi_plugi_cpp  SHARED ${src_core_csgsi_cpp}  )

target_link_libraries(cgsi_plugi_cpp ${GLOBUS_GSSAPI_GSI_PKG_LIBRARIES} ${GLOBUS_ASSIST_PKG_LIBRARIES} "c" )

set_target_properties(cgsi_plugi_cpp	 	PROPERTIES
								VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
								SOVERSION ${VERSION_MAJOR}
								CLEAN_DIRECT_OUTPUT 1
								OUTPUT_NAME "cgsi_plugin_cpp"						
)

# voms
add_library(cgsi_plugin_voms_cpp  SHARED ${src_core_csgsi_cpp}  )

target_link_libraries(cgsi_plugin_voms_cpp ${VOMS_PKG_LIBRARIES} ${GLOBUS_GSSAPI_GSI_PKG_LIBRARIES} ${GLOBUS_ASSIST_PKG_LIBRARIES} "c" )

set_target_properties(cgsi_plugin_voms_cpp	 	PROPERTIES
								VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
								SOVERSION ${VERSION_MAJOR}
								CLEAN_DIRECT_OUTPUT 1
								COMPILE_FLAGS " -DUSE_VOMS ${VOMS_PKG_CFLAGS}"
								OUTPUT_NAME "cgsi_plugin_voms_cpp"						
)




install(TARGETS cgsi_plugin cgsi_plugin_voms cgsi_plugi_cpp cgsi_plugin_voms_cpp
		RUNTIME       DESTINATION ${BIN_INSTALL_DIR}
		LIBRARY       DESTINATION ${LIB_INSTALL_DIR} )

install(FILES 	"cgsi_plugin.h"
		DESTINATION ${INCLUDE_INSTALL_DIR}/)
			
			
