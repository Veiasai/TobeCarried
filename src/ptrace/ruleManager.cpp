#include "ruleManager.h"

#include <iostream>
#include "spdlog/spdlog.h"

#include "fileWhitelist.h"
#include "networkMonitor.h"

namespace SAIL
{
namespace rule
{

YamlRuleManager::YamlRuleManager(const YAML::Node &yaml, 
    std::shared_ptr<utils::Utils> up,
    std::shared_ptr<core::Report> report)
    : up(up), report(report)
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
        long sysnum = 0;
        std::string sysname;
        if ((*ruleNode)["sysnum"].IsDefined())
        {
            sysnum = (*ruleNode)["sysnum"].as<long>();
            int ret = this->up->sysnum2str(sysnum, sysname);
            if (ret != 0)
            {
                throw std::logic_error("undefined sysnum");
            }
        }
        else if ((*ruleNode)["sysname"].IsDefined())
        {
            sysname = (*ruleNode)["sysname"].as<std::string>();
            int ret = this->up->sysname2num(sysname, sysnum);
            if (ret != 0)
            {
                throw std::logic_error("undefined sysname");
            }
        }
        else
        {
            throw std::logic_error("invalid rule format: miss sysnum or sysname");
        }
        
        int id = (*ruleNode)["id"].as<int>();
        std::string name = (*ruleNode)["name"].as<std::string>();
        const YAML::Node specs = (*ruleNode)["specs"];

        std::unique_ptr<Rule> rule = std::make_unique<RuleImpl>(id, sysnum, name, up);

        spdlog::debug("Load Rule id: {} name: {} sysnum: {} sysname: {}", id, name, sysnum, sysname);
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
            else if (action == "less")
            {
                rule->less(idx, (*spec)["value"].as<long>());
            }
            else if (action == "notLess")
            {
                rule->notLess(idx, (*spec)["value"].as<long>());
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
    try {
        plugins["FileWhitelist"] = std::make_unique<FileWhitelist>(yaml["filewhitelist"], this->up, this->report);
    }
    catch (std::exception & e) {}
    try {
        plugins["Network"] = std::make_unique<NetworkMonitor>(yaml["network"], this->up, this->report);
    }
    catch (std::exception & e) {}
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