# List of single-file tests.
set(TOOLS
	tracedump.cc)

foreach(TOOL_SOURCE ${TOOLS})
	get_filename_component(TOOL ${TOOL_SOURCE} NAME_WE)
	add_executable(${TOOL} ${TOOL_SOURCE})
	set_target_properties(${TOOL} PROPERTIES
		INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}"
	)
	target_link_libraries(${TOOL} cheritrace)
endforeach()


