
#include <string>
#include <memory>
#include <sys/syscall.h>

#include "mock.h"

namespace SAIL { namespace Test {

using namespace testing;
using namespace utils;
using namespace core;
using namespace rule;

class TraceeFixture: public ::testing::Test {
public:
    std::shared_ptr<MockCustomPtrace> cp;
    std::shared_ptr<MockUtils> up;
    std::shared_ptr<RuleManager> rulemgr;
    std::shared_ptr<Report> report;

public: 
   TraceeFixture() { 
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

TEST_F (TraceeFixture, Clone) { 
    TraceeImpl traceeImpl(10, up, cp, rulemgr, report);

    struct user_regs_struct call_regs;
    EXPECT_CALL(*cp, peekUser(10, _))
      .WillOnce(Return(SYS_clone));
    EXPECT_CALL(*cp, getRegs(10, _))
      .WillOnce(Return(0));

    traceeImpl.trap();

    struct user_regs_struct ret_regs;
    ret_regs.rax = 100; // return tid

    EXPECT_CALL(*cp, peekUser(10, _))
      .WillOnce(Return(SYS_clone));
    EXPECT_CALL(*cp, getRegs(10, _))
      .WillOnce(DoAll(SetArgPointee<1>(ret_regs) ,Return(0)));
    EXPECT_CALL(*cp, attach(100))
      .WillOnce(Return(0));

    traceeImpl.trap();
}


}}