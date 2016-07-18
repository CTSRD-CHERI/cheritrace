// swig interface definition for the cheritrace library

%module pycheritrace
%include "std_string.i";
 //%include "std_array.i"
%include "std_shared_ptr.i"
%include "stdint.i"

%{
#define SWIG_FILE_WITH_INIT
#include "../streamtrace.hh"
#include "../disassembler.hh"
%}

#define __attribute__(x)
#define static_assert(x,y)
%shared_ptr(cheri::streamtrace::trace)
%shared_ptr(cheri::streamtrace::trace_view)
%include "../streamtrace.hh";
%include "../disassembler.hh"

