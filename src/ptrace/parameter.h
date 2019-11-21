#pragma once

#include <vector>
#include <stdio.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

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
    null,
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

    Parameter() {
        type = ParameterType::null;
    }

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


