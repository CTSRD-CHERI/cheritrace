#pragma once
#include <string>

namespace cheri {

/**
 * Class representing an address map.
 */
struct addressmap
{
	/**
	 * A single mapping.  
	 */
	struct range
	{
		/**
		 * The start of this address range.
		 */
		uint64_t start = 0;
		/**
		 * The end of this range;
		 */
		uint64_t end = 0;
		/**
		 * The name of the mapped file.
		 */
		std::string file_name;
		/**
		 * Is this file mapped with read permissions?
		 */
		bool is_readable : 1;
		/**
		 * Is this file mapped with write permissions?
		 */
		bool is_writeable : 1;
		/**
		 * Is this file mapped with execute permissions?
		 */
		bool is_executable : 1;
	};
	/**
	 * Construct a new address map by parsing a procstat file.
	 */
	static std::shared_ptr<addressmap> open_procstat(std::string path);
	/**
	 * For a given address, return the file that is mapping it.  If the
	 * specified address is not within any address range then it will return a
	 * zero-length address range.
	 */
	virtual range mapping_for_address(uint64_t) = 0;
	/**
	 * Virtual destructor.
	 */
	virtual ~addressmap();
};


} // namespace cheri
