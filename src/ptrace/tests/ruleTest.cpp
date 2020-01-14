
#include <string>
#include <vector>
#include <sys/syscall.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mock.h"
#include "../rule.h"
#include "../parameter.h"

namespace SAIL { namespace Test {

using namespace rule;
using namespace core;

class RuleFixture: public ::testing::Test {
public:
    std::shared_ptr<MockCustomPtrace> cp;
    std::shared_ptr<MockUtils> up;
    std::shared_ptr<MockRuleManager> rulemgr;
    std::shared_ptr<MockReport> report;

    RuleFixture() { 
        cp = std::make_shared<MockCustomPtrace>();
        up = std::make_shared<MockUtils>();
        rulemgr = std::make_shared<MockRuleManager>();
        report = std::make_shared<MockReport>();
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
    RuleImpl rule(ID, SYS_open, name, up);
    std::vector<unsigned char> bytes;
    std::string fileName = "/proc";
    char fileNameBuf[] = "/proc";
    bytes.insert(bytes.end(), fileName.begin(), fileName.end());

    rule.matchBytes(ParameterIndex::First, bytes);
    Parameters sp;
    sp.resize(7);
    sp[ParameterIndex::First] = Parameter(ParameterType::pointer, bytes.size(), reinterpret_cast<long>(fileNameBuf));
    
    EXPECT_CALL(*up, formatBytes(bytes, _)).Times(1);
    EXPECT_CALL(*up, formatBytes(fileName, _)).Times(1);
    RuleCheckMsg msg = rule.check(sp);
    EXPECT_EQ(msg.approval, false);
    EXPECT_EQ(msg.ruleID, ID);

    fileNameBuf[1] = 'x';
    EXPECT_CALL(*up, formatBytes(bytes, _)).Times(0);
    EXPECT_CALL(*up, formatBytes(fileName, _)).Times(0);
    RuleCheckMsg msg2 = rule.check(sp);

    EXPECT_EQ(msg2.approval, true);
    EXPECT_EQ(msg2.ruleID, ID);
}


}}