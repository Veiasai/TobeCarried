#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../tracee.h"
#include "../utils.h"


namespace SAIL { namespace Test {

using namespace testing;
using namespace utils;
using namespace core;
using namespace rule;

class MockCustomPtrace : public CustomPtrace
{
public:
    MOCK_METHOD(long, peekUser, (int tid, long addr), (override));
    MOCK_METHOD(long, getRegs, (int tid, user_regs_struct * regs), (override));
    MOCK_METHOD(long, peekData, (int tid, long addr), (override));
    MOCK_METHOD(long, attach, (int tid), (override));
};

class MockUtils : public Utils
{
public:
    MOCK_METHOD(int, readStrFrom, (int tid, const char * p, char * buf, size_t s), (override));
    MOCK_METHOD(int, readBytesFrom, (int tid, const char * p, char * buf, size_t s), (override));
    MOCK_METHOD(int, getFilenameByFd, (int tid, int fd, std::string &filename), (override));
};

class MockRuleManager : public RuleManager
{
public:
    MOCK_METHOD(std::vector<core::RuleCheckMsg>, check, (int syscallNumber, const core::SyscallParameter &sp), (override));
};

class MockReport : public Report
{
public:
    MOCK_METHOD(int, write, (const long tid, const long callID, const core::RuleCheckMsg &rcmsg), (override));
    MOCK_METHOD(int, flush, (), (override));
    MOCK_METHOD(size_t, size, (), (override));
};

} // namespace Test
} // namespace SAIL