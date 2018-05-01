
macro (add_python_test name)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${name}" "${CMAKE_CURRENT_BINARY_DIR}/${name}" COPYONLY)
  set(test_name "py_${name}_test")
  add_test(NAME ${test_name} COMMAND ${PYTHON_EXECUTABLE} -m pytest -s "${CMAKE_CURRENT_BINARY_DIR}/${name}")
  set_property(TEST ${test_name} PROPERTY ENVIRONMENT
    "LD_LIBRARY_PATH=${PROJECT_BINARY_DIR}"
    "DYLD_LIBRARY_PATH=${PROJECT_BINARY_DIR}"
    "CTEST_SOURCE_PATH=${CMAKE_SOURCE_DIR}/Tests"
    "PYTHONPATH=${PYTHONPATH}:${PROJECT_BINARY_DIR}/Python")

endmacro (add_python_test)

if (PYTHON_BINDINGS)
  find_package(PythonInterp REQUIRED)
  add_python_test(simple.py)
  add_python_test(instr_parser.py)
  add_python_test(instr_writer.py)
  add_python_test(exception.py)
  add_python_test(notifier.py)
endif (PYTHON_BINDINGS)


