#pragma once

#include <vector>

namespace SAIL { namespace core {

enum ParameterIndex
{
    First,
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
    union value
    {
        void * p;
        long value;
    };
};

struct SyscallParameter
{
    std::vector<Parameter> parameters;
};


}}


