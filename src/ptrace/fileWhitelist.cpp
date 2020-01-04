#include <sstream>

#include "fileWhitelist.h"
#include "spdlog/spdlog.h"

namespace SAIL
{
namespace rule
{

FileWhitelist::FileWhitelist(const YAML::Node & config,
    std::shared_ptr<utils::Utils> up,
    std::shared_ptr<core::Report> report)
    : up(up), report(report)
{
    std::vector<std::string> whitelist = config.as<std::vector<std::string>>();

    for (const auto & rule : whitelist)
    {
        spdlog::debug("whitelist item: {}", rule);
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
    this->up->getFilenamesByProc(tid, files);
}

void FileWhitelist::event(long tid, int status)
{

}

void FileWhitelist::end()
{
    // TODO: tid?
    report->write(0, "filewhitelist check");
    for (auto it = files.begin(); it != files.end(); it++)
    {
        bool flag = false;
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
            report->write(0, "[Pass] " + (*it));
        else
            report->write(0, "[Fail] " + (*it));
    }
}


} // namespace core
} // namespace SAIL
