#include "whitelist.h"
#include "spdlog/spdlog.h"

namespace SAIL
{
namespace rule
{

FileWhitelist::FileWhitelist(const YAML::Node & config)
{

    std::vector<std::string> whitelist = config.as<std::vector<std::string>>();

    for (auto rule : whitelist)
    {
        // spdlog::debug("whitelist item: {}", rule);
        std::regex pattern(rule);
        this->whitelist_patterns.emplace_back(pattern);
    }
}

void FileWhitelist::beforeTrap(long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs)
{
    
}

void FileWhitelist::afterTrap(long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs)
{

}

void FileWhitelist::event(long tid, int status)
{

}

void FileWhitelist::end()
{
    std::set<std::string> result;

    for (auto it = files.begin(); it != files.end(); it++)
    {
        bool flag = false;
        // spdlog::debug("whitelist file: {}", (*it));
        for (auto rule : whitelist_patterns)
        {
            if (std::regex_match((*it), rule))
            {
                spdlog::debug("whitelist file: {} {}", (*it),"true");
                flag = true;
                break;
            }
        }

        if (flag)
            result.insert("[Pass] " + (*it));
        else
            result.insert("[Fail] " + (*it));
    }
}


} // namespace core
} // namespace SAIL
