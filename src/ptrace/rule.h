#pragma once

#include <string>
#include <vector>

#include "parameter.h"

namespace SAIL { namespace rule {

struct RuleCheckMsg
{
    bool approval;
    int ruleID;
    std::string msg;
};

enum RuleLevel
{
    record,
    standard,
    dangerous,
};

struct RuleInfo
{
    int target_syscall;
    int ruleID;
    std::string name;
    RuleLevel level;
};

class Rule
{
public:
    virtual ~Rule() {};
    virtual RuleCheckMsg check(const core::SyscallParameter & sp) = 0;
    virtual RuleInfo info() = 0;
    virtual int matchRe(core::ParameterIndex idx, const std::string & re) = 0; // usually should be a pointer
    virtual int matchBytes(core::ParameterIndex idx, const std::vector<char> & vc) = 0; // usually should be a pointer
    virtual int equal(core::ParameterIndex idx, long value) = 0;
    virtual int notEqual(core::ParameterIndex idx, long value) = 0;
    virtual int greater(core::ParameterIndex idx, long value) = 0;
    virtual int notGreater(core::ParameterIndex idx, long value) = 0;
};

class RuleImpl : public Rule
{
private:
    int ID;
    int target_syscall;
    std::string name;
    RuleLevel level;
public:
    RuleImpl(int ID, int target_syscall, const std::string & name, RuleLevel level);
    virtual ~RuleImpl() {};
    virtual RuleCheckMsg check(const core::SyscallParameter & sp) override;
    virtual RuleInfo info() override;
    virtual int matchRe(core::ParameterIndex idx, const std::string & re) override; // usually should be a pointer
    virtual int matchBytes(core::ParameterIndex idx, const std::vector<char> & vc) override; // usually should be a pointer
    virtual int equal(core::ParameterIndex idx, long value) override;
    virtual int notEqual(core::ParameterIndex idx, long value) override;
    virtual int greater(core::ParameterIndex idx, long value) override;
    virtual int notGreater(core::ParameterIndex idx, long value) override;
};

}}