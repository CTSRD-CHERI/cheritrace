# List of single-file tests.
set(TOOLS
	tracedump.cc)

foreach(TOOL_SOURCE ${TOOLS})
	get_filename_component(TOOL ${TOOL_SOURCE} NAME_WE)
	add_executable(cheri-${TOOL} ${TOOL_SOURCE})
	set_target_properties(cheri-${TOOL} PROPERTIES
		INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}"
	)
	target_link_libraries(cheri-${TOOL} cheritrace)
	install (TARGETS cheri-${TOOL} DESTINATION bin)
endforeach()


