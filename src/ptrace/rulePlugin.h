#pragma once

#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include <memory>

#include "utils.h"
#include "rule.h"
#include "parameter.h"

namespace SAIL { namespace rule {

/*
* RulePlugin is for designing complicate rule like file whitelist.
* It can have private state and leverage other tech (/proc)
*/

class RulePlugin
{
public:
    virtual ~RulePlugin() {};
    virtual void beforeTrap(long tid,
        const core::Histories & history,
        core::RuleCheckMsgs & ruleCheckMsgs) = 0;
    virtual void afterTrap(long tid,
        const core::Histories & history,
        core::RuleCheckMsgs & ruleCheckMsgs) = 0;
    virtual void event(long tid, int status) = 0;
    virtual void end() = 0;
    // TODO: more time points
};

}}