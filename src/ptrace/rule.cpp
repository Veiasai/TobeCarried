#include <regex>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "rule.h"

namespace SAIL
{
namespace rule
{

RuleImpl::RuleImpl(int ID, int target_syscall, const std::string &name, std::shared_ptr<utils::Utils> up)
    : ID(ID), target_syscall(target_syscall), name(name), up(up) {};

core::RuleCheckMsg RuleImpl::check(const core::Parameters &sp)
{
    core::RuleCheckMsg rcm = {true, ID, name, ""};

    for (const auto &rulevalue : rulevalues)
    {
        CheckInfo checkinfo = rulevalue(sp);
        if (!checkinfo.approval)
        {
            rcm.approval = false;
            rcm.msg = checkinfo.msg;
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

    rulevalues.emplace_back([idx, pattern, re](const core::Parameters &sp) -> CheckInfo {
        if (std::regex_match((char *)(sp[idx].value), pattern)) {
            return CheckInfo({false, "Match! Config: " + re + ", Actual: " + (char *)(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

int RuleImpl::matchBytes(core::ParameterIndex idx, const std::vector<unsigned char> &vc)
{
    std::shared_ptr<utils::Utils> up = this->up;
    rulevalues.emplace_back([idx, vc, up](const core::Parameters &sp) -> CheckInfo {
        char *str = (char *)sp[idx].value;
        long spsize = sp[idx].size;
        bool matched = false;

        if (vc.size() > spsize)
        {
            return CheckInfo({true, ""});
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
        if (matched)
        {
            std::string configBytes;
            std::string actualBytes;
            up->formatBytes(vc, configBytes);
            up->formatBytes(str, actualBytes);
            return CheckInfo({false, "Match! Config: " + configBytes + ", Actual: " + actualBytes});
        }
        return CheckInfo({true, ""});
    });
};

int RuleImpl::equal(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> CheckInfo {
        if (sp[idx].value == value) {
            return CheckInfo({false, "Equal! Config: ==" + std::to_string(value) + ", Actual: " + std::to_string(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

int RuleImpl::notEqual(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> CheckInfo {
        if (sp[idx].value != value) {
            return CheckInfo({false, "NotEqual! Config: !=" + std::to_string(value) + ", Actual: " + std::to_string(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

int RuleImpl::greater(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> CheckInfo {
        if (sp[idx].value > value) {
            return CheckInfo({false, "Greater! Config: >" + std::to_string(value) + ", Actual: " + std::to_string(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

int RuleImpl::notGreater(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> CheckInfo {
        if (sp[idx].value <= value) {
            return CheckInfo({false, "NotGreater! Config: <=" + std::to_string(value) + ", Actual: " + std::to_string(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

int RuleImpl::less(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> CheckInfo {
        if (sp[idx].value < value) {
            return CheckInfo({false, "Less! Config: <" + std::to_string(value) + ", Actual: " + std::to_string(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

int RuleImpl::notLess(core::ParameterIndex idx, long value)
{
    rulevalues.emplace_back([idx, value](const core::Parameters &sp) -> CheckInfo {
        if (sp[idx].value >= value) {
            return CheckInfo({false, "NotLess! Config: >=" + std::to_string(value) + ", Actual: " + std::to_string(sp[idx].value)});
        }
        return CheckInfo({true, ""});
    });
    return 0;
};

} // namespace rule
} // namespace SAIL