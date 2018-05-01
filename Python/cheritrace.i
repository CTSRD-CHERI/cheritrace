// swig interface definition for the cheritrace library

/* %module(threads="1") pycheritrace */
%module pycheritrace

%include "std_string.i";
%include "std_array.i"
%include "std_vector.i"
%include "std_shared_ptr.i"
%include "stdint.i"
%include "exception.i"

%include "std_bitset.i"

%{
#define SWIG_FILE_WITH_INIT
#include "../disassembler.hh"
#include "../streamtrace.hh"
#include <functional>
%}

// unsupported by SWIG
#define __attribute__(x)
#define static_assert(x,y)

// wrap STL types
%shared_ptr(cheri::streamtrace::trace)
%shared_ptr(cheri::streamtrace::trace_view)
%shared_ptr(cheri::streamtrace::trace_writer)
%template (GprArray) std::array<unsigned long long, 31>;
%template (CapArray) std::array<cheri::streamtrace::capability_register, 32>;
%template (GprBitset) std::bitset<31>;
%template (CapBitset) std::bitset<32>;
%template (OperandVector) std::vector<cheri::disassembler::operand_info>;
%template (StringVector) std::vector<std::string>;
/** Workaround missing support of nested unions (see accessors below) */
%ignore cheri::streamtrace::debug_trace_entry::reg_value;

/* Expose the MipsRegisterNames string array */
%{
	const std::vector<std::string> mips_register_names(
		std::begin(cheri::disassembler::MipsRegisterNames),
		std::end(cheri::disassembler::MipsRegisterNames));
%}
%immutable;
const std::vector<std::string> mips_register_names;
%mutable;

/*
 * Convert from python function to C function pointer for trace::scanner
 * trace::detailed_scanner, trace::filter and trace::notifier
 * XXX maybe typemap is not the perfect place to do that, SWIG seems to advise
 * using helper functions.
 */
%typemap (in)
cheri::streamtrace::trace::scanner
{
	if (!PyCallable_Check($input)) {
		SWIG_exception(SWIG_TypeError, "Object not callable");
	}
	$1 = [$input](cheri::streamtrace::debug_trace_entry entry, uint64_t idx) {
		PyObject *trace_entry;
		PyObject *args;
		PyObject *result;
		int c_result;
		cheri::streamtrace::debug_trace_entry *entry_copy =
			new cheri::streamtrace::debug_trace_entry(entry);

		/*
		 * Third argument (flags) delegates ownership of the copy object
		 * to swig so it will properly free() it based on the python object refcount.
		 */
		trace_entry = SWIG_NewPointerObj(SWIG_as_voidptr(entry_copy),
						 SWIGTYPE_p_cheri__streamtrace__debug_trace_entry,
						 1);
		args = Py_BuildValue("(OK)", trace_entry, idx);
		result = PyObject_Call($input, args, NULL);
		if (!result) {
			/* stop scanning if there is an exception */
			c_result = 1;
		}
		else {
			/* do not strictly check for a PyBool,
			 * it is more pythonic to accept anything
			 */
			c_result = PyObject_IsTrue(result);
			Py_DECREF(result);
		}
		Py_DECREF(args);
		Py_DECREF(trace_entry);
		return (bool)c_result;
	};
}

%typemap (out) void
{
	PyObject *error;
	error = PyErr_Occurred();
	if (error) {
		SWIG_fail;
	}
	$result = SWIG_Py_Void();
}


%typemap (in) cheri::streamtrace::trace::filter_predicate
{
	if (!PyCallable_Check($input)) {
		SWIG_exception(SWIG_TypeError, "Object not callable");
	}
	$1 = [$input](const cheri::streamtrace::debug_trace_entry &entry)
		{
			PyObject *trace_entry;
			PyObject *args;
			PyObject *result;
			int c_result = 0;
			cheri::streamtrace::debug_trace_entry *entry_copy =
				new cheri::streamtrace::debug_trace_entry(entry);

			/*
			 * Third argument (flags) delegates ownership of the copy object
			 * to swig so it will properly free() it based on the python object refcount.
			 */
			trace_entry = SWIG_NewPointerObj(SWIG_as_voidptr(entry_copy),
							 SWIGTYPE_p_cheri__streamtrace__debug_trace_entry,
							 1);
			args = Py_BuildValue("(O)", trace_entry);
			result = PyObject_Call($input, args, NULL);
			if (!result) {
				c_result = 1;
			}
			else {
				/* do not strictly check for a PyBool,
				 * it is more pythonic to accept anything
				 */
				c_result = PyObject_IsTrue(result);
				Py_DECREF(result);
			}
			Py_DECREF(args);
			Py_DECREF(trace_entry);
			return (bool)c_result;
		};
}

%typemap (in) cheri::streamtrace::trace::detailed_scanner
{
	if (!PyCallable_Check($input))
		SWIG_exception(SWIG_TypeError, "Object not callable");

	$1 = [$input](const cheri::streamtrace::debug_trace_entry &entry,
		      const cheri::streamtrace::register_set &regset,
		      uint64_t idx)
		{
			PyObject *trace_entry;
			PyObject *register_set;
			PyObject *args;
			PyObject *result;
			int c_result;
			cheri::streamtrace::register_set *regset_copy =
				new cheri::streamtrace::register_set(regset);
			cheri::streamtrace::debug_trace_entry *entry_copy =
				new cheri::streamtrace::debug_trace_entry(entry);

			/*
			 * Third argument (flags) delegates ownership of the copy object
			 * to swig so it will properly free() it based on the python object refcount.
			 */
			trace_entry = SWIG_NewPointerObj(SWIG_as_voidptr(entry_copy),
							 SWIGTYPE_p_cheri__streamtrace__debug_trace_entry,
							 1);
			register_set = SWIG_NewPointerObj(SWIG_as_voidptr(regset_copy),
							  SWIGTYPE_p_cheri__streamtrace__register_set,
							  1);
			args = Py_BuildValue("(OOK)", trace_entry, register_set, idx);
			result = PyObject_Call($input, args, NULL);
			if (!result) {
				c_result = 1;
			}
			else {
				/* do not strictly check for a PyBool,
				 * it is more pythonic to accept anything
				 */
				c_result = PyObject_IsTrue(result);
				Py_DECREF(result);
			}
			Py_DECREF(args);
			Py_DECREF(register_set);
			Py_DECREF(trace_entry);
			return (bool)c_result;
		};
}

%fragment("PyCheritrace_GetArgcount", "header")
{
	int PyCheritrace_GetArgcount(PyObject *callable)
	{
		PyObject *code, *argcount, *run, *func;
		int c_argcount = 0;

		if (PyCallable_Check(callable)) {
			code = PyObject_GetAttrString(callable, "__code__");
			if (!code) {
				PyErr_Clear();
				/* may be a callable class */
				run = PyObject_GetAttrString(callable, "__call__");
				if (!run)
					return 0;
				func = PyObject_GetAttrString(run, "__func__");
				Py_DECREF(run);
				if (!func)
					return 0;
				code = PyObject_GetAttrString(func, "__code__");
				Py_DECREF(func);
				if (!code)
					return 0;
				c_argcount = -1; /* account for self */
			}
			argcount = PyObject_GetAttrString(code, "co_argcount");
			if (!argcount) {
				Py_DECREF(code);
				return 0;
			}
			c_argcount += PyInt_AsLong(argcount);
			Py_DECREF(argcount);
			return c_argcount;
		}
		return 0;
	}
}

%typemap(typecheck,
	 precedence=SWIG_TYPECHECK_INTEGER,
	 fragment="PyCheritrace_GetArgcount")
cheri::streamtrace::trace::scanner
{
	$1 = PyCheritrace_GetArgcount($input) == 2;
}

%typemap(typecheck,
	 precedence=SWIG_TYPECHECK_INTEGER,
	 fragment="PyCheritrace_GetArgcount")
cheri::streamtrace::trace::detailed_scanner
{
	$1 = PyCheritrace_GetArgcount($input) == 3;
}

%typemap(typecheck,
	 precedence=SWIG_TYPECHECK_INTEGER,
	 fragment="PyCheritrace_GetArgcount")
cheri::streamtrace::trace::filter_predicate
{
	$1 = PyCheritrace_GetArgcount($input) == 1;
}

/**
 * trace::open notifier handling
 */
%typemap (in) cheri::streamtrace::trace::notifier
{
	/* XXX currently disabled due to a crash */
	/* $1 = nullptr; */
	if (!PyCallable_Check($input))
		SWIG_exception(SWIG_TypeError, "Object not callable");
	$1 = [$input](cheri::streamtrace::trace *trace, uint64_t entries, bool done) {
	  PyObject *py_trace;
	  PyObject *args;
	  PyObject *result;
	  int c_result;
	  PyGILState_STATE gil_state = PyGILState_Ensure();
	  /*
	   * Third argument (flags) stop delegation of ownership of the copy object
	   * to swig so it will not free() it based on the python object refcount.
	   */
	  py_trace = SWIG_NewPointerObj(trace, SWIGTYPE_p_cheri__streamtrace__trace, 0);
	  args = Py_BuildValue("(OKO)", py_trace, entries, done ? Py_True : Py_False);
	  result = PyObject_Call($input, args, NULL);
	  if (!result) {
	    /* stop scanning if there is an exception */
	    c_result = 1;
	  }
	  else {
	    /* do not strictly check for a PyBool,
	     * it is more pythonic to accept anything
	     */
	    c_result = PyObject_IsTrue(result);
	    Py_DECREF(result);
	  }
	  Py_DECREF(args);
	  Py_DECREF(py_trace);
	  PyGILState_Release(gil_state);
	  return (bool)c_result;
	};
}

/* the notifier can be a callable or None */
%typemap (typecheck, precedence=SWIG_TYPECHECK_INTEGER) cheri::streamtrace::trace::notifier
{
	$1 = PyCallable_Check($input) || $input == Py_None;
}


%include "../streamtrace.hh";
%include "../disassembler.hh";
