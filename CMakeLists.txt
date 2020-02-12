cmake_minimum_required(VERSION 2.8)

project(cheritrace)

set(cheritrace_VERSION 0.1)

file(GLOB cheritrace_CXX_SRCS "*.cc")
file(GLOB cheritrace_HDRS "*.hh")
set(LLVM_LIBS
	Mips debuginfodwarf mc mcparser mcdisassembler object
)

# Define the cheritrace program that we will build
add_library(cheritrace SHARED ${cheritrace_CXX_SRCS})
add_library(cheritrace-static STATIC ${cheritrace_CXX_SRCS})

set_target_properties(cheritrace-static PROPERTIES
	POSITION_INDEPENDENT_CODE true
	OUTPUT_NAME cheritrace)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-zero-length-array")

find_program(LLVM_CONFIG NAMES llvm-config DOC "Path to llvm-config utility")
if (${LLVM_CONFIG} STREQUAL "LLVM_CONFIG-NOTFOUND")
	message(SEND_ERROR "llvm-config not found, please manually set path with -DLLVM_CONFIG")
endif()
message(STATUS "Using llvm-config: ${LLVM_CONFIG}")

# Define LLVM version macros so that we can support multiple versions in the source.
execute_process(COMMAND ${LLVM_CONFIG} --version
  OUTPUT_VARIABLE LLVM_VER
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --cxxflags
  OUTPUT_VARIABLE LLVM_CXXFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --libs ${LLVM_LIBS}
  OUTPUT_VARIABLE LLVM_LIBS_FLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --ldflags
  OUTPUT_VARIABLE LLVM_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --system-libs
  OUTPUT_VARIABLE LLVM_SYSTEMLIBS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX REPLACE "([0-9]*).([0-9]*).*" "-DLLVM_MAJOR=\\1 -DLLVM_MINOR=\\2"  LLVM_VERSION "${LLVM_VER}")
string(REGEX REPLACE "-l/usr/lib/libexecinfo.so" "-lexecinfo" LLVM_SYSTEMLIBS "${LLVM_SYSTEMLIBS}")
# Ensure that all system-libs are prefixed by -l
string(REGEX REPLACE "-l" "" LLVM_SYSTEMLIBS "${LLVM_SYSTEMLIBS}")
string(REGEX REPLACE " " ";" LLVM_SYSTEMLIBS "${LLVM_SYSTEMLIBS}")
list(TRANSFORM LLVM_SYSTEMLIBS PREPEND "-l")
set(LLVM_SYSTEMLIBS_NORMALIZED ${LLVM_SYSTEMLIBS})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
string(REPLACE "-DNDEBUG" ""  LLVM_CXXFLAGS "${LLVM_CXXFLAGS}")
endif ()

FIND_PACKAGE(LibLZMA REQUIRED)

include_directories(SYSTEM ${LibLZMA_INCLUDE_DIRS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} ${LLVM_VERSION} ${BOOST_CXX_FLAGS}")
target_link_libraries(cheritrace
  ${LLVM_LDFLAGS}
  ${LLVM_LIBS_FLAGS}
  ${LLVM_SYSTEMLIBS_NORMALIZED}
  ${LIBLZMA_LIBRARIES})
set(CMAKE_SKIP_RPATH true)


option(BUILD_DOCUMENTATION "Use Doxygen to create the HTML based API documentation" OFF)
if(BUILD_DOCUMENTATION)
	FIND_PACKAGE(Doxygen)
	if (NOT DOXYGEN_FOUND)
		message(FATAL_ERROR
			"Doxygen is needed to build the documentation. Please install it correctly")
	endif()
	#-- Configure the Template Doxyfile for our specific project
	configure_file(Doxyfile.in
	               ${PROJECT_BINARY_DIR}/Doxyfile @ONLY IMMEDIATE)
	#-- Add a custom target to run Doxygen when ever the project is built
	add_custom_target (Docs ALL
	                   COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile
	                   SOURCES ${PROJECT_BINARY_DIR}/Doxyfile)
endif()

set(TESTS TRUE CACHE BOOL "Enable building the tests")

if (TESTS)
	enable_testing()
	add_subdirectory(Tests)
endif ()

add_subdirectory(Tools)

option(PYTHON_BINDINGS "Build python bindings" ON)
if (PYTHON_BINDINGS)
  add_subdirectory(Python)
endif ()

if (NOT CMAKE_INSTALL_LIBDIR)
	set(CMAKE_INSTALL_LIBDIR lib)
endif ()

set(INSTALL_TARGETS cheritrace)
list(APPEND INSTALL_TARGETS cheritrace-static)
install(TARGETS ${INSTALL_TARGETS}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${cheritrace_HDRS}
	DESTINATION "include/cheritrace")

