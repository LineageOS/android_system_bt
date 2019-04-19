#include <optional>

namespace bluetooth {
namespace packet {
namespace parser {

// Checks for Initialize(), AddByte(), and GetChecksum().
// T and TRET are the checksum class Type and the checksum return type
// C and CRET are the substituted types for T and TRET
template <typename T, typename TRET>
class ChecksumTypeChecker {
 public:
  template <class C, void (*)(C&)>
  struct InitializeChecker {};

  template <class C, void (*)(C&, uint8_t byte)>
  struct AddByteChecker {};

  template <class C, typename CRET, CRET (*)(const C&)>
  struct GetChecksumChecker {};

  // If all the methods are defined, this one matches
  template <class C, typename CRET>
  static int Test(InitializeChecker<C, &C::Initialize>*, AddByteChecker<C, &C::AddByte>*,
                  GetChecksumChecker<C, CRET, &C::GetChecksum>*);

  // This one matches everything else
  template <class C, typename CRET>
  static char Test(...);

  // This checks which template was matched
  static constexpr bool value = (sizeof(Test<T, TRET>(0, 0, 0)) == sizeof(int));
};
}  // namespace parser
}  // namespace packet
}  // namespace bluetooth
