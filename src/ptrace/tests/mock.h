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
    MOCK_METHOD(int, getFilenamesByProc, (int tid,std::set<std::string> &fileset), (override));
    MOCK_METHOD(int, strset2file, (const std::string &filename, const std::set<std::string> &fileset), (override));
};

class MockRuleManager : public RuleManager
{
public:
    MOCK_METHOD(void, beforeTrap, (long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs), (override));
    MOCK_METHOD(void, afterTrap, (long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs), (override));
    MOCK_METHOD(void, event, (long tid, int status), (override));
    MOCK_METHOD(void, end, (), (override));
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