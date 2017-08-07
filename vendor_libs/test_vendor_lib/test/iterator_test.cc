#include "hci_packet.h"
#include "l2cap_test_packets.h"

#include <gtest/gtest.h>
#include <memory>

using std::unique_ptr;
using std::vector;
namespace test_vendor_lib {

class TestPacket : public HciPacket {
 public:
  static std::shared_ptr<TestPacket> make_new_packet(vector<uint8_t> v) {
    return std::shared_ptr<TestPacket>(new TestPacket(v));
  }
  size_t get_length() { return test_vector_.size(); }
  uint8_t& get_at_index(size_t index) { return test_vector_[index]; }

 private:
  TestPacket(vector<uint8_t> v) { test_vector_ = v; }
  vector<uint8_t> test_vector_;
};

class IteratorTest : public ::testing::Test {
 public:
  IteratorTest() = default;
  ~IteratorTest() = default;

  void SetUp() { packet = TestPacket::make_new_packet(complete_l2cap_packet); }

  void TearDown() { packet.reset(); }

  std::shared_ptr<TestPacket> packet;
};

TEST_F(IteratorTest, plusEqTest) {
  Iterator plus_eq = packet->get_begin();
  for (size_t i = 0; i < complete_l2cap_packet.size(); i += 2) {
    ASSERT_EQ(complete_l2cap_packet[i], *plus_eq)
        << "+= test: Dereferenced iterator does not equal expected at index "
        << i;
    plus_eq += 2;
  }
}

TEST_F(IteratorTest, preIncrementTest) {
  Iterator plus_plus = packet->get_begin();
  for (size_t i = 0; i < complete_l2cap_packet.size(); i++) {
    ASSERT_EQ(complete_l2cap_packet[i + 1], *(++plus_plus))
        << "Pre-increment test: Dereferenced iterator does not equal expected "
        << "at index " << i;
  }
}

TEST_F(IteratorTest, postIncrementTest) {
  Iterator plus_plus = packet->get_begin();
  for (size_t i = 0; i < complete_l2cap_packet.size(); i++) {
    ASSERT_EQ(complete_l2cap_packet[i], *(plus_plus++))
        << "Post-increment test: Dereferenced iterator does not equal expected "
        << "at index " << i;
  }
}

TEST_F(IteratorTest, additionTest) {
  Iterator plus = packet->get_begin();
  for (size_t i = 0; i < complete_l2cap_packet.size(); i++) {
    ASSERT_EQ(complete_l2cap_packet[i], *plus)
        << "+ test: Dereferenced iterator does not equal expected at index "
        << i;
    plus = plus + static_cast<size_t>(1);
  }
}

TEST_F(IteratorTest, minusEqTest) {
  Iterator minus_eq = packet->get_end();
  minus_eq -= 1;
  for (size_t i = complete_l2cap_packet.size() - 1; i > 0; i -= 2) {
    ASSERT_EQ(complete_l2cap_packet[i], *minus_eq)
        << "-= test: Dereferenced iterator does not equal expected at index "
        << i;
    minus_eq -= 2;
  }
}

TEST_F(IteratorTest, preDecrementTest) {
  Iterator minus_minus = packet->get_end();
  for (size_t i = complete_l2cap_packet.size(); i > 0; i--) {
    ASSERT_EQ(complete_l2cap_packet[i - 1], *(--minus_minus))
        << "Pre-decrement test: Dereferenced iterator does not equal expected "
        << "at index " << i;
  }
}

TEST_F(IteratorTest, postDecrementTest) {
  Iterator minus_minus = packet->get_end();
  minus_minus--;
  for (size_t i = complete_l2cap_packet.size() - 1; i > 0; i--) {
    ASSERT_EQ(complete_l2cap_packet[i], *(minus_minus--))
        << "Post-decrement test: Dereferenced iterator does not equal expected "
        << "at index " << i;
  }
}

TEST_F(IteratorTest, subtractionTest) {
  Iterator minus = packet->get_end();
  minus = minus - static_cast<size_t>(1);
  for (size_t i = complete_l2cap_packet.size() - 1; i > 0; i--) {
    ASSERT_EQ(complete_l2cap_packet[i], *minus)
        << "- test: Dereferenced iterator does not equal expected at index "
        << i;
    minus = minus - static_cast<size_t>(1);
  }
}

TEST_F(IteratorTest, plusEqBoundsTest) {
  Iterator plus_eq = packet->get_end();
  plus_eq--;
  for (size_t i = 0; i < 100; i++) {
    plus_eq += i;
    ASSERT_EQ(packet->get_end(), plus_eq)
        << "+= test: Iterator exceeded the upper bound set by get_length()";
  }
}

TEST_F(IteratorTest, preIncrementBoundsTest) {
  Iterator plus_plus = packet->get_end();
  plus_plus--;
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(packet->get_end(), ++plus_plus)
        << "Pre-increment test: Iterator exceeded the upper bound set "
           "by get_length()";
  }
}

TEST_F(IteratorTest, postIncrementBoundsTest) {
  Iterator plus_plus = packet->get_end();
  plus_plus--;
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(packet->get_end(), plus_plus++)
        << "Post-increment test: Iterator exceeded the upper bound set "
           "by get_length()";
  }
}

TEST_F(IteratorTest, additionBoundsTest) {
  Iterator plus = packet->get_end();
  plus--;
  for (size_t i = 0; i < 100; i++) {
    plus = plus + static_cast<size_t>(i);
    ASSERT_EQ(packet->get_end(), plus)
        << "+ test: Iterator exceeded the upper bound set by get_length()";
  }
}

TEST_F(IteratorTest, minusEqBoundsTest) {
  Iterator minus_eq = packet->get_begin();
  for (size_t i = 0; i < 100; i++) {
    minus_eq -= i;
    ASSERT_EQ(complete_l2cap_packet[0], *minus_eq)
        << "-= test: Iterator is less than the lower bound set by "
           "packet->get_begin()";
  }
}

TEST_F(IteratorTest, preDecrementBoundsTest) {
  Iterator minus_minus = packet->get_begin();
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(complete_l2cap_packet[0], *(--minus_minus))
        << "Pre-decrement test: Iterator is less than the lower bound set by "
           "packet->get_begin()";
  }
}

TEST_F(IteratorTest, postDecrementBoundsTest) {
  Iterator minus_minus = packet->get_begin();
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(complete_l2cap_packet[0], *(minus_minus--))
        << "Post-decrement test: Iterator is less than the lower bound set by "
           "packet->get_begin()";
  }
}

TEST_F(IteratorTest, subtractionBoundsTest) {
  Iterator minus = packet->get_begin();
  for (size_t i = 0; i < 100; i++) {
    minus = minus - static_cast<size_t>(i);
    ASSERT_EQ(complete_l2cap_packet[0], *minus)
        << "- test: Iterator is less than the lower bound set "
           "by packet->get_begin()";
  }
}
};  // namespace test_vendor_lib
