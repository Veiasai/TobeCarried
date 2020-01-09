
#include <string>
#include <vector>
#include <sys/syscall.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../rule.h"
#include "../parameter.h"

namespace SAIL { namespace Test {

using namespace rule;
using namespace core;

class RuleFixture: public ::testing::Test {
public:
   RuleFixture() { 
    
   } 

   void SetUp( ) { 
       // code here will execute just before the test ensues 
       
   }

   void TearDown( ) { 
       // code here will be called just after the test completes
       // ok to through exceptions from here if need be
   }
};

TEST_F(RuleFixture, match_bytes_in_open_filename)
{
    int ID = 1;
    const std::string name = "equal";
    RuleImpl rule(ID, SYS_open, name);
    std::vector<unsigned char> bytes;
    std::string fileName = "/proc";
    char fileNameBuf[] = "/proc";
    bytes.insert(bytes.end(), fileName.begin(), fileName.end());

    rule.matchBytes(ParameterIndex::First, bytes);
    Parameters sp;
    sp.resize(7);
    sp[ParameterIndex::First] = Parameter(bytes.size(), reinterpret_cast<long>(fileNameBuf));
    RuleCheckMsg msg = rule.check(sp);

    EXPECT_EQ(msg.approval, false);
    EXPECT_EQ(msg.ruleID, ID);

    fileNameBuf[1] = 'x';

    RuleCheckMsg msg2 = rule.check(sp);

    EXPECT_EQ(msg2.approval, true);
    EXPECT_EQ(msg2.ruleID, ID);
}


}}