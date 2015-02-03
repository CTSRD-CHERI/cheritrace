# List of single-file tests.
set(TESTS
	debug.cc
	disassemble.cc
	object.cc
	regvalues.cc
	shared_debug.cc
	shared_object.cc
	simple.cc)

foreach(TEST_SOURCE ${TESTS})
	get_filename_component(TEST ${TEST_SOURCE} NAME_WE)
	add_executable(${TEST} ${TEST_SOURCE})
	add_test(${TEST} ${TEST})
	set_target_properties(${TEST} PROPERTIES
		INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}"
		COMPILE_FLAGS "-DSOURCE_PATH='\"${CMAKE_SOURCE_DIR}/Tests\"'"
		)
	set_property(TEST ${TEST} PROPERTY
		ENVIRONMENT "DYLD_LIBRARY_PATH=${PROJECT_BINARY_DIR};DYLD_LIBRARY_PATH=${PROJECT_BINARY_DIR}"
	)
	target_link_libraries(${TEST} cheritrace)
endforeach()


