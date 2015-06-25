#include <vector>
#include <fstream>
#include <regex>
#include "addressmap.hh"

#include <iostream>

namespace {

/**
 * Concrete class that implements the address map interface.
 */
struct concrete_addressmap : cheri::addressmap
{
	std::vector<range> ranges;
	range mapping_for_address(uint64_t addr) override
	{
		for (auto &r : ranges)
		{
			if ((r.start <= addr) && (addr <= r.end))
			{
				return r;
			}
		}
		range empty;
		return empty;
	}
};
} // anonymous namespace 

std::shared_ptr<cheri::addressmap> cheri::addressmap::open_procstat(std::string path)
{
	std::ifstream file(path, std::ios::in);
	if (!file.is_open())
	{
		return nullptr;
	}
	// FIXME: file fails to open
	std::shared_ptr<concrete_addressmap> ret = std::make_shared<concrete_addressmap>();
	std::string line;
	// Regular expression for matching a line in a procstat entry.
	std::regex re("\\s*\\d+\\s+0x([0-9a-f]+)\\s+0x([0-9a-f]+)\\s+([r-])([w-])([x-])\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\S+\\s+\\S+\\s*(\\S*)",
			std::regex_constants::ECMAScript);
	auto end = std::sregex_iterator();
	while (std::getline(file, line))
	{
		if (line.find("  PID") != std::string::npos)
		{
			continue;
		}
		auto begin = std::sregex_iterator(line.begin(), line.end(), re);
		for (auto i=begin ; i!=end ; ++i)
		{
			if (i->size() != 7)
			{
				continue;
			}
			auto &m = *i;
			range r;
			r.start = std::stoll(m[1].str(), 0, 16);
			r.end = std::stoll(m[2].str(), 0, 16);
			r.is_readable = (m[3].str() == "r");
			r.is_writeable = (m[4].str() == "w");
			r.is_executable = (m[5].str() == "x");
			r.file_name = m[6].str();
			ret->ranges.push_back(r);
		}
	}
	// Add the kernel range at the end
	range r;
	r.start = 0xffffffff00000000ULL;
	r.end = 0xffffffffffffffffULL;
	r.file_name = "kernel";
	r.is_readable = true;
	r.is_writeable = false;
	r.is_executable = true;
	ret->ranges.push_back(r);
	return ret;
}

cheri::addressmap::~addressmap() {}
