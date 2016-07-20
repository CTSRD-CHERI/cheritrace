// swig interface definition for the cheritrace library

%module(directors="1") pycheritrace

%include "std_string.i";
%include "std_array.i"
%include "std_shared_ptr.i"
%include "stdint.i"
%include "std_bitset.i"

%{
#define SWIG_FILE_WITH_INIT
#include "../disassembler.hh"
#include "callback.hh"
#include <functional>
%}

// unsupported by SWIG
#define __attribute__(x)
#define static_assert(x,y)

// wrap STL types
%shared_ptr(cheri::streamtrace::trace)
%shared_ptr(cheri::streamtrace::trace_view)
%template (GprArray) std::array<unsigned long long, 31>;
%template (CapArray) std::array<struct cheri::streamtrace::capability_register, 32>;
%template (GprBitset) std::bitset<31>;
%template (CapBitset) std::bitset<32>;

/* %typemap(in) (cheri::streamtrace::trace::scanner) { */
/*   printf("TYPEMAP\n"); */
/*   if (!SwigPyObject_Check($input) || */
/*       strcmp($input->ob_type->tp_name, "Scanner") != 0) { */
/*     PyErr_SetString(PyExc_TypeError, "Object is not an istance of Scanner."); */
/*     $1 = NULL; */
/*   } */
/*   SwigPyObject *sobj = (SwigPyObject *)$input; */
/*   cheri::streamtrace::Scanner *v = (cheri::streamtrace::Scanner *)sobj->ptr; */
/*   auto bound_cbk = std::bind(&cheri::streamtrace::Scanner::c_scanner, */
/* 			     v, */
/* 			     std::placeholders::_1, */
/* 			     std::placeholders::_2); */
/*   $1 = cheri::streamtrace::trace::scanner(bound_cbk); */
/* } */

// SWIG does not yet support std::function
// scanner and filter callbacks are handled via custom director classes
%ignore cheri::streamtrace::Scanner::c_scanner;
%ignore cheri::streamtrace::DetailedScanner::c_scanner;
%ignore cheri::streamtrace::Filter::c_scanner;
%ignore cheri::streamtrace::trace::scan;

%feature("director") cheri::streamtrace::Scanner;
%feature("director") cheri::streamtrace::DetailedScanner;
%feature("director") cheri::streamtrace::Filter;

//%nodefaultctor cheri::streamtrace::Scanner;
%include "../streamtrace.hh";
%include "../disassembler.hh";
%include "callback.hh"

%extend cheri::streamtrace::trace {

    void scan_trace(cheri::streamtrace::Scanner* scn) {
      auto bound_cbk = std::bind(&cheri::streamtrace::Scanner::c_scanner,
				 scn,
				 std::placeholders::_1,
				 std::placeholders::_2);
      $self->scan(cheri::streamtrace::trace::scanner(bound_cbk));
    }

    void scan_trace(cheri::streamtrace::Scanner* scn, uint64_t start, uint64_t end, int opts=0) {
      auto bound_cbk = std::bind(&cheri::streamtrace::Scanner::c_scanner,
				 scn,
				 std::placeholders::_1,
				 std::placeholders::_2);
      $self->scan(cheri::streamtrace::trace::scanner(bound_cbk), start, end, opts);
    }

    void scan_trace(cheri::streamtrace::DetailedScanner* scn, uint64_t start, uint64_t end, int opts=0) {
      auto bound_cbk = std::bind(&cheri::streamtrace::DetailedScanner::c_scanner,
				 scn,
				 std::placeholders::_1,
				 std::placeholders::_2,
				 std::placeholders::_3);
      $self->scan(cheri::streamtrace::trace::detailed_scanner(bound_cbk), start, end, opts);
    }

    std::shared_ptr<trace_view> filter_trace(cheri::streamtrace::Filter* filter) {
      auto bound_cbk = std::bind(&cheri::streamtrace::Filter::c_filter,
				 filter,
				 std::placeholders::_1);
      return $self->filter(cheri::streamtrace::trace::filter_predicate(bound_cbk));
    }
}
