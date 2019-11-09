#include "rule.h"
#include <regex>

namespace SAIL
{
namespace rule
{

RuleImpl::RuleImpl(int ID, int target_syscall, const std::string &name, RuleLevel level)
    : ID(ID), target_syscall(target_syscall), name(name), level(level){};

RuleCheckMsg RuleImpl::check(const core::SyscallParameter &sp)
{
    RuleCheckMsg rcm = {false, ID, ""};

    for (auto f : rulevalues)
    {
        if (f(sp))
        {
            rcm.approval = true;
            rcm.msg = "matched";
            return rcm;
        }
    }
    return rcm;
};

RuleInfo RuleImpl::info()
{
    RuleInfo info = {target_syscall, ID, name, level};
    return info;
};

int RuleImpl::matchRe(core::ParameterIndex idx, const std::string &re)
{
    const std::regex pattern(re);

    rulevalues.emplace_back([idx, pattern](const core::SyscallParameter &sp) -> int {
        std::regex pattern;
        return std::regex_match((char *)(sp.parameters[idx - 1].value.p), pattern) ? 1 : 0;
    });
    return 0;
};

int RuleImpl::matchBytes(core::ParameterIndex idx, const std::vector<char> &vc)
{
    rulevalues.emplace_back([idx, vc](const core::SyscallParameter &sp) -> int {
        char *str = (char *)sp.parameters[idx - 1].value.p;
        long spsize = sp.parameters[idx - 1].size;
        int matched = 0;

        if (vc.size() > spsize)
        {
            return 0;
        }
        else
        {
            for (long i = 0; i <= spsize - vc.size(); i++)
            {
                for (long j = 0; j < vc.size(); j++)
                {
                    if (str[i + j] != vc[j])
                        break;

                    if (j == vc.size() - 1)
                        matched = 1;
                }

                if (matched)
                    break;
            }
        }
        return matched;
    });
};

int RuleImpl::equal(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::SyscallParameter &sp) -> int {
        return (sp.parameters[idx - 1].value.value == value) ? 1 : 0;
    });
    return 0;
};

int RuleImpl::notEqual(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::SyscallParameter &sp) -> int {
        return (sp.parameters[idx - 1].value.value != value) ? 1 : 0;
    });
    return 0;
};

int RuleImpl::greater(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::SyscallParameter &sp) -> int {
        return (sp.parameters[idx - 1].value.value > value) ? 1 : 0;
    });
    return 0;
};

int RuleImpl::notGreater(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::SyscallParameter &sp) -> int {
        return (sp.parameters[idx - 1].value.value <= value) ? 1 : 0;
    });
    return 0;
};

} // namespace rule
} // namespace SAIL