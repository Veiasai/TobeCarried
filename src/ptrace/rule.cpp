#include "rule.h"

namespace SAIL { namespace rule {

RuleImpl::RuleImpl(int ID, int target_syscall, const std::string & name, RuleLevel level) 
    : ID(ID), target_syscall(target_syscall), name(name), level(level) 
{

};

RuleCheckMsg RuleImpl::check(const core::SyscallParameter & sp) {
    return RuleCheckMsg();
};

RuleInfo RuleImpl::info() {
    return RuleInfo();
};

int RuleImpl::matchRe(core::ParameterIndex idx, const std::string & re)
{

};

int RuleImpl::matchBytes(core::ParameterIndex idx, const std::vector<char> & vc)
{

};

int RuleImpl::equal(core::ParameterIndex idx, long value)
{

};

int RuleImpl::notEqual(core::ParameterIndex idx, long value)
{

};

int RuleImpl::greater(core::ParameterIndex idx, long value)
{

};

int RuleImpl::notGreater(core::ParameterIndex idx, long value)
{

};

}}