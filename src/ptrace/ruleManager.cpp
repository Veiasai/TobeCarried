#include "ruleManager.h"

#include <iostream>

namespace SAIL
{
namespace rule
{

YamlRuleManager::YamlRuleManager(const YAML::Node &yaml)
{
    const YAML::Node whitelist = yaml["whitelist"];
    const YAML::Node blacklist = yaml["blacklist"];

    ruleMatch(whitelist, this->whitelist_rules);
    ruleMatch(blacklist, this->blacklist_rules);
};

int YamlRuleManager::ruleMatch(const YAML::Node &yaml, std::map<int, std::vector<std::unique_ptr<Rule>>> &rules)
{
    for (auto ruleNode = yaml.begin(); ruleNode != yaml.end(); ruleNode++)
    {
        int sysnum = (*ruleNode)["sysnum"].as<int>();
        int id = (*ruleNode)["id"].as<int>();
        SAIL::rule::RuleLevel level = (SAIL::rule::RuleLevel)((*ruleNode)["level"].as<int>());
        std::string name = (*ruleNode)["name"].as<std::string>();
        const YAML::Node specs = (*ruleNode)["specs"];
        // TODO: config level
        std::unique_ptr<Rule> rule = std::make_unique<RuleImpl>(id, sysnum, name, level);
        for (auto spec = specs.begin(); spec != specs.end(); spec++)
        {
            std::string action = (*spec)["action"].as<std::string>();
            core::ParameterIndex idx = (core::ParameterIndex)(*spec)["paraIndex"].as<int>();

            if (action == "matchRe")
            {
                rule->matchRe(idx, (*spec)["value"].as<std::string>());
            }
            else if (action == "matchBytes")
            {
                std::vector<int> values = (*spec)["value"].as<std::vector<int>>();
                std::vector<unsigned char> bytes;
                for (auto e : values)
                    bytes.push_back((unsigned char)(e));

                rule->matchBytes(idx, bytes);
            }
            else if (action == "equal")
            {
                rule->equal(idx, (*spec)["value"].as<long>());
            }
            else if (action == "notEqual")
            {
                rule->notEqual(idx, (*spec)["value"].as<long>());
            }
            else if (action == "greater")
            {
                rule->greater(idx, (*spec)["value"].as<long>());
            }
            else if (action == "notGreater")
            {
                rule->notGreater(idx, (*spec)["value"].as<long>());
            }
            // TODO: more actions
        }
        // add the rule to the map
        rules[sysnum].emplace_back(std::move(rule));
    }
}

std::vector<core::RuleCheckMsg> YamlRuleManager::check(int syscall, const core::SyscallParameter &sp)
{
    std::vector<core::RuleCheckMsg> res;
    for (auto &rule : whitelist_rules[syscall])
        res.push_back(rule->check(sp));

    for (auto &rule : blacklist_rules[syscall])
        res.push_back(rule->check(sp));

    return res;
};

} // namespace rule
} // namespace SAIL