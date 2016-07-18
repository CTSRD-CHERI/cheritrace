
file(GLOB pycheritrace_SWIG_IF "cheritrace.i")
file(GLOB pycheritrace_CXX_SRCS "pycheritrace.cc")
file(GLOB pycheritrace_PY_SRCS "pycheritrace.py")

option(PYTHON_BINDINGS "Build python bindings" ON)

if (PYTHON_BINDINGS)
   # find python and swig
   find_package(PythonLibs REQUIRED)
   find_package(PythonInterp REQUIRED)
   find_package(SWIG REQUIRED)
   include(${SWIG_USE_FILE})
   
   if (PYTHON_VERSION_MAJOR EQUAL 3)
      set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} "-modern" "-py3")	 
   endif ()

   set_source_files_properties(${pycheritrace_SWIG_IF} PROPERTIES
   	CPLUSPLUS ON)
   set_source_files_properties(${swig_generated_file_fullname} PROPERTIES
   	COMPILE_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} ${LLVM_VERSION}")

   include_directories(${PYTHON_INCLUDE_DIRS})
   include_directories(${CMAKE_CURRENT_SOURCE_DIR})
   swig_add_module(pycheritrace python ${pycheritrace_SWIG_IF})
   swig_link_libraries(pycheritrace ${LLVM_LDFLAGS} ${LLVM_LIBS_FLAGS}
   	${LLVM_SYSTEMLIBS} ${LIBLZMA_LIBRARIES} cheritrace)
   add_dependencies(${SWIG_MODULE_pycheritrace_REAL_NAME} cheritrace)
   
   # we should use python distutils only for installation since distutils
   # is not aware of the object files build by cmake and rebuilds them
   # if build_ext is used
   set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
   set(SETUP_PY "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
   configure_file(${SETUP_PY_IN} ${SETUP_PY})
   install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install)")
   
endif (PYTHON_BINDINGS)
