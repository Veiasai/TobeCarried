#include "ruleManager.h"

#include <yaml-cpp/yaml.h>

namespace SAIL { namespace rule {

YamlRuleManger::YamlRuleManger(const YAML::Node & yaml)
{
    for(auto ruleNode = yaml.begin(); ruleNode != yaml.end();ruleNode++)
    {
        int num = (*ruleNode)["sysnum"].as<int>();
        int id = (*ruleNode)["id"].as<int>();
        std::string name = (*ruleNode)["name"].as<std::string>();
        const YAML::Node specs = (*ruleNode)["specs"];
        // TODO: config level
        std::unique_ptr<Rule> rule = std::make_unique<RuleImpl>(id, num, name, RuleLevel::record);
        for (auto spec = specs.begin(); spec != specs.end(); spec++)
        {
            std::string action = (*spec)[0].as<std::string>();
            core::ParameterIndex idx = (core::ParameterIndex)(*spec)[1].as<int>();
            if (action == "matchRe"){
                rule->matchRe(idx, (*spec)[1].as<std::string>());
            }
            else if (action == "matchBytes"){
                // how to input bytes?
                // rule->matchBytes(idx, )
            }
            else if (action == "equal"){
                rule->equal(idx, (*spec)[1].as<long>());
            }
            // TODO: more actions
        }
    }
};

std::vector<RuleCheckMsg> YamlRuleManger::check(int syscall, const core::SyscallParameter & sp)
{
    std::vector<RuleCheckMsg> res;
    for (auto & rule : rules[syscall])
    {
        res.push_back(rule->check(sp));
    }
};

}}