#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../tracee.h"
#include "../utils.h"


namespace SAIL { namespace Test {

using namespace testing;
using namespace utils;
using namespace core;

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
};

}}