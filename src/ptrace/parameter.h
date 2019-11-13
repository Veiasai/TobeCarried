#pragma once

#include <vector>

namespace SAIL { namespace core {

enum ParameterIndex
{
    First = 1,
    Second,
    Third,
    Fourth,
    Fifth,
    Sixth,
    Ret,
};

enum ParameterType
{
    pointer,
    nonpointer,
};

struct Parameter
{
    ParameterType type;
    long size;
    union 
    {
        void * p;
        long value;
    } value;
};

struct SyscallParameter
{
    std::vector<Parameter> parameters;
};

struct RuleCheckMsg
{
    bool approval;
    int ruleID;
    std::string msg;
};


}}


