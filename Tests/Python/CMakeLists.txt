
if (PYTHON_BINDINGS)
   find_package(PythonInterp REQUIRED)
   add_test(NAME py_binding_test COMMAND ${PYTHON_EXECUTABLE} -m pytest ${CMAKE_CURRENT_SOURCE_DIR}/simple.py) # TO DO add py.test checkers
   set_property(TEST py_binding_test PROPERTY ENVIRONMENT
     "LD_LIBRARY_PATH=${PROJECT_BINARY_DIR}"
     "DYLD_LIBRARY_PATH=${PROJECT_BINARY_DIR}"
     "CTEST_SOURCE_PATH=${CMAKE_SOURCE_DIR}/Tests"
     "PYTHONPATH=${PYTHONPATH}:${PROJECT_BINARY_DIR}/Python")
endif (PYTHON_BINDINGS)


# # List of single-file tests.
# set(TESTS
# 	address_map.cc
# 	debug.cc
# 	disassemble.cc
# 	disassemble_object.cc
# 	filter.cc
# 	object.cc
# 	regvalues.cc
# 	scan.cc
# 	shared_debug.cc
# 	shared_object.cc
# 	simple.cc
# 	simple_v2.cc
# 	disassemble_v2.cc)

# foreach(TEST_SOURCE ${TESTS})
# 	get_filename_component(TEST ${TEST_SOURCE} NAME_WE)
# 	add_executable(${TEST} ${TEST_SOURCE})
# 	add_test(${TEST} ${TEST})
# 	set_target_properties(${TEST} PROPERTIES
# 		INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}"
# 		COMPILE_FLAGS "-DSOURCE_PATH='\"${CMAKE_SOURCE_DIR}/Tests\"' -UNDEBUG"
# 		)
# 	set_property(TEST ${TEST} PROPERTY
# 		ENVIRONMENT "LD_LIBRARY_PATH=${PROJECT_BINARY_DIR};DYLD_LIBRARY_PATH=${PROJECT_BINARY_DIR}"
# 	)
# 	target_link_libraries(${TEST} cheritrace)
# endforeach()


