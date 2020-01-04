#pragma once

#include <vector>
#include <stdio.h>
#include <sys/user.h>
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

struct RuleCheckMsg
{
    bool approval;
    int ruleID;
    std::string msg;
};

struct Systemcall {
    struct user_regs_struct call_regs;
    struct user_regs_struct ret_regs;
    Systemcall() {};
};

struct WarnInfo {
    // a WarnInfo is related to one specific systemcall
    // callID is that systemcall's index in history
    int callID;

    // TODO: add explanation to this warning
    // e.g. vector<int> breakRules;  show the rules that be breaked;  
};

using Parameters = std::vector<Parameter>;
using Histories = std::vector<std::pair<Systemcall, Parameters>>;
using RuleCheckMsgs = std::vector<RuleCheckMsg>;


}}


