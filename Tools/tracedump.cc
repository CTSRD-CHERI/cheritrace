#include "objectfile.hh"
#include "addressmap.hh"
#include "streamtrace.hh"
#include "disassembler.hh"

#include <getopt.h>
#include <signal.h>
#include <string>
#include <iostream>
#include <vector>
#include <limits>
#include <unordered_map>
#include <cinttypes>

using namespace cheri;
using cheri::streamtrace::debug_trace_entry;
using cheri::streamtrace::register_set;

namespace {
class OptionBase
{
protected:
	static std::vector<struct option> longopts;
	static std::vector<std::string> help;
	static std::unordered_map<char, OptionBase*> opts;
	static std::string shortopts;
	virtual void parse(const char *) = 0;
public:
	static void usage(const char *tool)
	{
		std::cerr << "Usage: " << tool << " {arguments}\n\nArguments:\n";
		for (auto &msg : help)
		{
			std::cerr << msg;
		}
		std::cerr << '\n';
	}
	virtual ~OptionBase() {}
	OptionBase(const char *longopt,
	           char shortopt,
	           int option,
	           const char *helpstr,
	           const char *optarg_name=0)
	{
		if (longopts.empty())
		{
			longopts.push_back({nullptr, 0, nullptr, 0});
		}
		longopts.insert(--(longopts.end()), {longopt, option, nullptr, shortopt});
		std::string helpmsg = "\n\t-";
		helpmsg += shortopt;
		if (optarg_name)
		{
			helpmsg += " {";
			helpmsg += optarg_name;
			helpmsg += "}";
		}
		helpmsg += "\n\t--";
		helpmsg += longopt;
		if (optarg_name)
		{
			helpmsg += " {";
			helpmsg += optarg_name;
			helpmsg += "}";
		}
		helpmsg += "\n\t\t";
		helpmsg += helpstr;
		help.push_back(helpmsg);
		shortopts += shortopt;
		if (option != no_argument)
		{
			shortopts += ':';
		}
		opts[shortopt] = this;
	}
	static bool handle_options(int argc, char **argv)
	{
		int ch;
		while ((ch = getopt_long(argc, argv, shortopts.c_str(), longopts.data(), NULL)) != -1)
		{
			auto it = opts.find(ch);
			if (it == opts.end())
			{
				usage(argv[0]);
				return false;
			}
			it->second->parse(optarg);
		}
		return true;
	}
};
std::vector<struct option> OptionBase::longopts;
std::vector<std::string> OptionBase::help;
std::unordered_map<char, OptionBase*> OptionBase::opts;
std::string OptionBase::shortopts;

template<class T>
class OptionValue : OptionBase
{
	protected:
	T Value;
	public:
	using OptionBase::OptionBase;
	operator const T&() const
	{
		return Value;
	}
	operator const T*() const
	{
		return &Value;
	}
	const T* operator->() const
	{
		return &Value;
	}
	bool operator==(const T &other) const
	{
		return Value == other;
	}
};

template<class T>
class Option : public OptionValue<T>
{
	bool isValid;
	void parse_impl(const char*);
	public:
	using OptionValue<T>::OptionValue;
	void parse(const char * val) override
	{
		isValid = true;
		parse_impl(val);
	}
	operator bool() const
	{
		return isValid;
	}
	bool operator !() const
	{
		return !isValid;
	}
	T valueOr(T&& def)
	{
		return isValid ? OptionValue<T>::Value : def;
	}
	void operator=(const T &val)
	{
		isValid = true;
		OptionValue<T>::Value = val;
	}
};
template<class T> void Option<T>::parse_impl(const char*val)
{
	OptionValue<T>::Value = val;
}
template<> void Option<int>::parse_impl(const char*val)
{
	Value = strtol(val, nullptr, 0);
}
template<> void Option<unsigned long long>::parse_impl(const char*val)
{
	Value = strtoull(val, nullptr, 0);
}
template<> void Option<long long>::parse_impl(const char*val)
{
	Value = strtoll(val, nullptr, 0);
}
template<> void Option<bool>::parse_impl(const char*val)
{
	Value = true;
}

template<> void Option<std::vector<std::string>>::parse(const char*val)
{
	Value.push_back(val);
}

Option<std::string> traceFile("trace",
	't',
	required_argument,
	"The trace file to parse",
	"trace file");
Option<unsigned long long> start("start",
	's',
	required_argument,
	"The index in the trace file to parse",
	"index");
Option<unsigned long long> end("end",
	'e',
	required_argument,
	"The index in the trace file to parse",
	"index");
Option<unsigned long long> regdump("regdump",
	'r',
	required_argument,
	"Print a register dump every index trace entries",
	"index");

void print_capability_register(const streamtrace::capability_register &cap)
{
	printf("v:%1d u:%1d perms:0x%8.8" PRIx16 " type:0x%8.8" PRIx32
	       " offset:0x%16.16" PRIx64 " base:0x%16.16" PRIx64 " length:0x%16.16"
	       PRIx64, (int)cap.valid, (int)cap.unsealed, cap.permissions,
	       cap.type, cap.offset, cap.base, cap.length);
}

inline void print_register(const debug_trace_entry &e)
{
	if (e.gpr_number() != -1)
	{
		printf("0x%16.16" PRIx64, e.reg_value.gp);
	}
	else if (e.capreg_number() != -1)
	{
		print_capability_register(e.reg_value.cap);
	}
}


static sig_atomic_t sig_info = 0;
static void sig_info_handler(int info)
{
	sig_info = 1;
}

} // Anonymous namespace

int main(int argc, char **argv)
{
#ifdef SIGINFO
	signal(SIGINFO, sig_info_handler);
#else
	// Use SIGUSR1 on systems that don't have SIGINFO (e.g. Linux)
	signal(SIGUSR1, sig_info_handler);
#endif
	OptionBase::handle_options(argc, argv);
	if (!traceFile)
	{
		OptionBase::usage(argv[0]);
		return EXIT_FAILURE;
	}
	auto trace = streamtrace::trace::open(traceFile);
	if (!trace)
	{
		std::cerr << "Failed to open trace file " << *traceFile << '\n';
		return EXIT_FAILURE;
	}
	if (regdump && (*regdump == 0))
	{
		regdump = 1;
	}
	uint64_t first = start.valueOr(0LL);
	uint64_t last = end.valueOr(trace->size());
	disassembler::disassembler dis;
	streamtrace::trace::detailed_scanner detail =
		[&](const debug_trace_entry &e, const register_set &r, uint64_t idx)
		{
			auto disassembly = dis.disassemble(e.inst);
			printf("%" PRIu64 "\t{%hhu}\t0x%.16" PRIx64 "\t%s", idx, e.asid,
					e.pc, disassembly.name.c_str());
			putchar('\n');
			if (e.is_load)
			{
				int regnum = e.register_number();
				putchar('\t');
				if (regnum != -1)
				{
					printf("$%s ← ", disassembler::MipsRegisterNames[regnum]);
				}
				print_register(e);
				printf(" ← Address 0x%16.16" PRIx64, e.memory_address);
				putchar('\n');
			}
			else if (e.is_store)
			{
				printf("\tAddress 0x%16.16" PRIx64 " ← ", e.memory_address);
				print_register(e);
				putchar('\n');
			}
			else
			{
				int regnum = e.register_number();
				if (regnum != -1)
				{
					printf("\t$%s ← ", disassembler::MipsRegisterNames[regnum]);
					print_register(e);
					putchar('\n');
				}
			}
			if (regdump && (idx % *regdump == 0))
			{
				printf("Register dump:\n");
				for (int i=0 ; i<31 ; i++)
				{
					printf("\t$%s\t", disassembler::MipsRegisterNames[i+1]);
					if (r.valid_gprs[i])
					{
						printf("0x%.16" PRIx64 "\n", r.gpr[i]);
					}
					else
					{
						printf("???\n");
					}
				}
				for (int i=0 ; i<32 ; i++)
				{
					printf("\t$c%d\t", i);
					if (r.valid_caps[i])
					{
						print_capability_register(r.cap_reg[i]);
					}
					else
					{
						printf("???");
					}
					putchar('\n');
				}
			}
			if (sig_info)
			{
				sig_info = 0;
				uint64_t i = idx - first;
				uint64_t total = last - first;
				fprintf(stderr, "[%2.2f%%] Trace entry %" PRIu64 " of %" PRIu64 "\n",
						(double)i/total*100, i, total);

			}
			return false;
		};
	trace->scan(detail, first, last);
}
