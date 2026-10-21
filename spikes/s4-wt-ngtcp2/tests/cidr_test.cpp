#include "cidr.hpp"

#include <gtest/gtest.h>

TEST(Cidr, Basic) {
  EXPECT_TRUE(glassy::in_cidrs("127.0.0.1", {"127.0.0.0/8"}));
  EXPECT_TRUE(glassy::in_cidrs("10.0.200.1", {"10.0.0.0/16"}));
  EXPECT_FALSE(glassy::in_cidrs("10.1.2.3", {"10.0.0.0/16"}));
}

TEST(Cidr, RejectsGarbage) {
  EXPECT_FALSE(glassy::in_cidrs("not-an-ip", {"0.0.0.0/0"}));
  EXPECT_FALSE(glassy::in_cidrs("10.0.0.1", {"10.0.0.0/40"}));
}
