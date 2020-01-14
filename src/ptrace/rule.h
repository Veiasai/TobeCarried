#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

#include "utils.h"
#include "parameter.h"

namespace SAIL { namespace rule {

struct RuleInfo
{
    int target_syscall;
    int ruleID;
    std::string name;
};

struct CheckInfo
{
    bool approval;
    std::string msg;
};

class Rule
{
public:
    virtual ~Rule() {};
    virtual core::RuleCheckMsg check(const core::Parameters & sp) = 0;
    virtual RuleInfo info() = 0;
    virtual int matchRe(core::ParameterIndex idx, const std::string & re) = 0; // usually should be a pointer
    virtual int matchBytes(core::ParameterIndex idx, const std::vector<unsigned char> & vc) = 0; // usually should be a pointer
    virtual int equal(core::ParameterIndex idx, long value) = 0;
    virtual int notEqual(core::ParameterIndex idx, long value) = 0;
    virtual int greater(core::ParameterIndex idx, long value) = 0;
    virtual int notGreater(core::ParameterIndex idx, long value) = 0;
    virtual int less(core::ParameterIndex idx, long value) = 0;
    virtual int notLess(core::ParameterIndex idx, long value) = 0;
};

class RuleImpl : public Rule
{
private:
    int ID;
    int target_syscall;
    std::string name;
    std::shared_ptr<utils::Utils> up;
    std::vector<std::function<CheckInfo(const core::Parameters & sp)>> rulevalues;
public:
    RuleImpl(int ID, int target_syscall, const std::string & name, std::shared_ptr<utils::Utils> up);
    virtual ~RuleImpl() {};
    virtual core::RuleCheckMsg check(const core::Parameters & sp) override;
    virtual RuleInfo info() override;
    virtual int matchRe(core::ParameterIndex idx, const std::string & re) override; // usually should be a pointer
    virtual int matchBytes(core::ParameterIndex idx, const std::vector<unsigned char> & vc) override; // usually should be a pointer
    virtual int equal(core::ParameterIndex idx, long value) override;
    virtual int notEqual(core::ParameterIndex idx, long value) override;
    virtual int greater(core::ParameterIndex idx, long value) override;
    virtual int notGreater(core::ParameterIndex idx, long value) override;
    virtual int less(core::ParameterIndex idx, long value) override;
    virtual int notLess(core::ParameterIndex idx, long value) override;
};

}}