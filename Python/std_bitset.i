//
// std::bitset
//

// -----------------------------------------------------------------------------
// std::bitset
//
// Integrate the std::bitset in SWIG interfaces as much as possible
//
//
//
// -----------------------------------------------------------------------------

%include "exception.i"
%include "std_basic_string.i"

%{
#include <exception>
%}

// exported classes

namespace std {

  template<size_t N>
    class bitset {
    
  public:

    // constructors
    bitset() noexcept;
    bitset(unsigned long long val) noexcept;

    template<class _CharT, class _Traits, class Alloc>
      explicit bitset(const basic_string<_CharT, _Traits, Alloc>& str,
		      typename basic_string<_CharT, _Traits, Alloc>::size_type pos = 0,
		      typename basic_string<_CharT, _Traits, Alloc>::size_type n =
		      basic_string<_CharT, _Traits, Alloc>::npos,
		      _CharT zero = _CharT('0'), _CharT one = _CharT('1'));
    template<class _CharT>
      explicit bitset (const _CharT* str,
		      typename basic_string<_CharT>::size_type n =
		       basic_string<_CharT>::npos,
		      _CharT zero = _CharT('0'), _CharT one = _CharT('1'));

    size_t count() const noexcept;
    size_t size() noexcept;
    bool test(size_t pos) const;
    bool any() const noexcept;
    bool none() const noexcept;
    bool all() const noexcept;

    bitset& set() noexcept;
    bitset& set(size_t pos, bool val = true);
    bitset& reset() noexcept;
    bitset& reset(size_t pos);
    bitset& flip() noexcept;
    bitset& flip(size_t pos);

    template<class _CharT = char,
      class _Traits = char_traits<_CharT>,
      class Alloc = allocator<_CharT>>
      basic_string<_CharT,_Traits,Alloc> to_string(_CharT zero = _CharT('0'),
						   _CharT one = _CharT('1')) const;
    
    %extend {
      bool __getitem__(size_t i) {
	return (*($self))[i];
      }

      void __setitem__(size_t i, bool val) {
	(*($self))[i] = val;
      }

      size_t __len__() {
    	return N;
      }
    }

    %exception __getitem__(size_t) {
      try {
	$action
      }
      catch(std::out_of_range& e) {
	SWIG_exception(SWIG_IndexError, "Index out of bounds");
      }
    }

    %exception __setitem__(size_t, bool) {
      try {
	$action
      }
      catch(std::out_of_range& e) {
	SWIG_exception(SWIG_IndexError, "Index out of bounds");
      }
    }

  };
}
