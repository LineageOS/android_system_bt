#include <array>

#include "packet/bit_inserter.h"
#include "packet/iterator.h"

namespace bluetooth {
namespace packet {
// Checks a custom type has all the necessary static functions with the correct signatures.
template <typename T>
class CustomTypeChecker {
 public:
  template <class C, void (*)(const C&, BitInserter&)>
  struct SerializeChecker {};

  template <class C, size_t (*)(const C&)>
  struct SizeChecker {};

  template <class C, Iterator<true> (*)(std::vector<C>& vec, Iterator<true> it)>
  struct ParseChecker {};

  template <class C, Iterator<false> (*)(std::vector<C>& vec, Iterator<false> it)>
  struct ParseCheckerBigEndian {};

  template <class C>
  static int Test(SerializeChecker<C, &C::Serialize>*, SizeChecker<C, &C::Size>*, ParseChecker<C, &C::Parse>*);

  template <class C>
  static int Test(SerializeChecker<C, &C::Serialize>*, SizeChecker<C, &C::Size>*, ParseCheckerBigEndian<C, &C::Parse>*);

  template <class C>
  static char Test(...);

  static constexpr bool value = (sizeof(Test<T>(0, 0, 0)) == sizeof(int));
};
}  // namespace packet
}  // namespace bluetooth
