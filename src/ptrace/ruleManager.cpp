#include "ruleManager.h"

#include <iostream>

#include "fileWhitelist.h"
#include "networkMonitor.h"

namespace SAIL
{
namespace rule
{

YamlRuleManager::YamlRuleManager(const YAML::Node &yaml)
{
    const YAML::Node rules = yaml["rules"];
    const YAML::Node plugins = yaml["plugins"];

    ruleInit(rules);
    pluginInit(plugins);
};

void YamlRuleManager::ruleInit(const YAML::Node &yaml)
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

void YamlRuleManager::pluginInit(const YAML::Node &yaml)
{
    // TODO
    plugins["FileWhitelist"] = std::make_unique<FileWhitelist>(yaml["filewhitelist"]);
    plugins["Network"] = std::make_unique<NetworkMonitor>(yaml["network"]);
}


void YamlRuleManager::beforeTrap(long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs)
{
    for (auto & plugin : plugins)
    {
        plugin.second->beforeTrap(tid, history, ruleCheckMsgs);
    }
}

void YamlRuleManager::afterTrap(long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs)
{
    // TODO: refactor the rules as a default plugin
    for (auto &rule : rules[history.back().first.call_regs.orig_rax])
        ruleCheckMsgs.push_back(rule->check(history.back().second));

    for (auto & plugin : plugins)
    {
        plugin.second->afterTrap(tid, history, ruleCheckMsgs);
    }
}

void YamlRuleManager::event(long tid, int status)
{

}

void YamlRuleManager::end()
{
    for (auto & plugin : plugins)
    {
        plugin.second->end();
    }
}

} // namespace rule
} // namespace SAIL