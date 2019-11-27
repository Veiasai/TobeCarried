
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
    std::shared_ptr<MockRuleManager> rulemgr;
    std::shared_ptr<MockReport> report;

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


}}