#pragma once

#include <string>
#include <vector>
#include <set>
#include <regex>

namespace SAIL
{
namespace core
{

class Whitelist
{
public:
    virtual ~Whitelist(){};
    virtual std::set<std::string> Check(const std::set<std::string> &files) = 0;
};

class WhitelistImpl : public Whitelist
{
private:
    std::string filename;
    std::vector<std::regex> whitelist_patterns;

public:
    WhitelistImpl(const std::string &fname);
    virtual ~WhitelistImpl() = default;
    virtual std::set<std::string> Check(const std::set<std::string> &files) override;
};

} // namespace core
} // namespace SAIL