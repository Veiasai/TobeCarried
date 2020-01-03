#pragma once

#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include <memory>

#include "utils.h"
#include "rule.h"


namespace SAIL { namespace rule {

/*
* RulePlugin is for designing complicate rule like file whitelist.
* It can have private state and leverage other tech (/proc)
*/

class RulePlugin
{
public:
    RulePlugin(const std::string & name, std::shared_ptr<utils::Utils> up, const YAML::Node& config);
    virtual ~RulePlugin() {};
    virtual std::vector<core::RuleCheckMsg> check(int syscallNumber, const core::SyscallParameter & sp) = 0;

    // TODO: more time points
};

}}