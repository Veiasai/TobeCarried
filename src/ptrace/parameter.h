#pragma once

#include <vector>

namespace SAIL { namespace core {

enum ParameterIndex
{
    Ret,
    First,
    Second,
    Third,
    Fourth,
    Fifth,
    Sixth,
    
};

enum ParameterType
{
    pointer,
    nonpointer,
};

struct Parameter
{
    ParameterType type;
    long size;  // size of object pointed
    union 
    {
        void * p;
        long value;
    } value;

    Parameter(ParameterType ftype, long fsize, void *fp, long fvalue) {
        if (ftype == pointer) {
            type = pointer;
            size = fsize;
            value.p = fp;
        }
        else {
            type = nonpointer;
            value.value = fvalue;
        }
    }
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


