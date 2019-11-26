#include "whitelist.h"
#include "spdlog/spdlog.h"
#include <yaml-cpp/yaml.h>

namespace SAIL
{
namespace core
{

WhitelistImpl::WhitelistImpl(const std::string &fname)
{
    this->filename = fname;
    YAML::Node whitelist_config = YAML::LoadFile(filename);

    std::vector<std::string> whitelist = whitelist_config["whitelist"].as<std::vector<std::string>>();

    for (auto rule : whitelist)
    {
        // spdlog::debug("whitelist item: {}", rule);
        std::regex pattern(rule);
        this->whitelist_patterns.emplace_back(pattern);
    }
}

std::set<std::string> WhitelistImpl::Check(const std::set<std::string> &files)
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

    return result;
}

} // namespace core
} // namespace SAIL
