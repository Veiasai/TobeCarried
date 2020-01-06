#include <regex>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "rule.h"

namespace SAIL
{
namespace rule
{

RuleImpl::RuleImpl(int ID, int target_syscall, const std::string &name)
    : ID(ID), target_syscall(target_syscall), name(name) {};

core::RuleCheckMsg RuleImpl::check(const core::Parameters &sp)
{
    core::RuleCheckMsg rcm = {true, ID, ""};
    spdlog::debug("rule {}:  ret {}, p1 {}, p2 {}, p3 {}, p4 {}, p5 {}, p6 {}", 
        ID, 
        sp[core::ParameterIndex::Ret].type,
        sp[core::ParameterIndex::First].type,
        sp[core::ParameterIndex::Second].type,
        sp[core::ParameterIndex::Third].type,
        sp[core::ParameterIndex::Fourth].type,
        sp[core::ParameterIndex::Fifth].type,
        sp[core::ParameterIndex::Sixth].type);

    for (const auto &rulevalue : rulevalues)
    {
        if (rulevalue(sp))
        {
            rcm.approval = false;

            // TODO: msg vary
            rcm.msg = "matched";
            return rcm;
        }
    }
    return rcm;
};

RuleInfo RuleImpl::info()
{
    RuleInfo info = {target_syscall, ID, name};
    return info;
};

int RuleImpl::matchRe(core::ParameterIndex idx, const std::string &re)
{
    const std::regex pattern(re);

    rulevalues.emplace_back([idx, pattern](const core::Parameters &sp) -> bool {
        return std::regex_match((char *)(sp[idx].value), pattern);
    });
    return 0;
};

int RuleImpl::matchBytes(core::ParameterIndex idx, const std::vector<unsigned char> &vc)
{
    rulevalues.emplace_back([idx, vc](const core::Parameters &sp) -> bool {
        char *str = (char *)sp[idx].value;
        long spsize = sp[idx].size;
        bool matched = false;

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
                        matched = true;
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
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> bool {
        return (sp[idx].value == value);
    });
    return 0;
};

int RuleImpl::notEqual(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> bool {
        return (sp[idx].value != value);
    });
    return 0;
};

int RuleImpl::greater(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> bool {
        return (sp[idx].value > value);
    });
    return 0;
};

int RuleImpl::notGreater(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> bool {
        return (sp[idx].value <= value);
    });
    return 0;
};

} // namespace rule
} // namespace SAIL