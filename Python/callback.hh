/*-
 * Copyright (c) 2016 Alfredo Mazzinghi
 *
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249
 * ("MRC2"), as part of the DARPA MRC research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#include "../streamtrace.hh"

namespace cheri
{
namespace streamtrace
{

/**
 * Proxy classes to dispatch callbacks from cheritrace and
 * the SWIG target languages (see SWIG directors).
 * The c_scanner method is bound to the director object and
 * given to the trace::scan method, the c_scanner in turns invokes
 * Scanner::run which should be implemented by the callback class
 * in the target language.
 *
 * XXX: The three proxy classes may be merged in a template
 */

struct Scanner
{
	Scanner();
	virtual ~Scanner() = 0;
	virtual bool run(debug_trace_entry e, uint64_t idx) = 0;
	bool c_scanner(debug_trace_entry e, uint64_t idx);
};

struct DetailedScanner
{
	DetailedScanner();
	virtual ~DetailedScanner() = 0;
	virtual bool run(const debug_trace_entry& e, const register_set& r, uint64_t idx) = 0;
	bool c_scanner(const debug_trace_entry& e, const register_set& r, uint64_t idx);
};

struct Filter
{
	Filter();
	virtual ~Filter() = 0;
	virtual bool run(const debug_trace_entry& e) = 0;
	bool c_filter(const debug_trace_entry& e);
};

}
}
