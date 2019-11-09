#include "ruleManager.h"

#include <yaml-cpp/yaml.h>
#include <iostream>

namespace SAIL
{
namespace rule
{

YamlRuleManger::YamlRuleManger(const YAML::Node &yaml)
{
    for (auto ruleNode = yaml.begin(); ruleNode != yaml.end(); ruleNode++)
    {
        int num = (*ruleNode)["sysnum"].as<int>();
        int id = (*ruleNode)["id"].as<int>();
        SAIL::rule::RuleLevel level = (SAIL::rule::RuleLevel)((*ruleNode)["level"].as<int>());
        std::string name = (*ruleNode)["name"].as<std::string>();
        const YAML::Node specs = (*ruleNode)["specs"];
        // TODO: config level
        std::unique_ptr<Rule> rule = std::make_unique<RuleImpl>(id, num, name, level);
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
                // how to input bytes?
                // rule->matchBytes(idx, )
                std::vector<int> nums = (*spec)["value"].as<std::vector<int>>();
                std::vector<char> bytes;
                for (auto e : nums)
                    bytes.push_back((char)(e));

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
        //  add the rule to the map
        rules[num].emplace_back(std::move(rule));
    }
};

std::vector<RuleCheckMsg> YamlRuleManger::check(int syscall, const core::SyscallParameter &sp)
{
    std::vector<RuleCheckMsg> res;
    for (auto &rule : rules[syscall])
    {
        res.push_back(rule->check(sp));
    }
};

} // namespace rule
} // namespace SAIL