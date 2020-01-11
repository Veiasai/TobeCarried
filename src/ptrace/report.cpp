#include <iostream>
#include <assert.h>
#include <sstream>

#include "report.h"
#include "spdlog/spdlog.h"

// TODO: exception handle
namespace SAIL
{
namespace core
{
ReportImpl::ReportImpl(const std::string & filename)
{
    this->filename = filename;
    this->fs = std::fstream();
    fs.open(filename.c_str(), std::ios::app);
    assert(fs.is_open());
    if (!fs.is_open())
    {
        spdlog::error("Report failed to open {}!", filename.c_str());
    }
};

ReportImpl::ReportImpl(const std::string & filename, const std::string & analFilename) : ReportImpl(filename)
{
    this->analFilename = analFilename;
    this->analFs = std::fstream();
    this->analFs.open(this->analFilename.c_str(), std::ios::app);
    assert(this->analFs.is_open());
    if (!this->analFs.is_open()) {
        spdlog::error("Analysis failed to open {}!", this->analFilename.c_str());
    }

    // init analysis yaml
    this->analEmitter << YAML::BeginMap;
    this->analEmitter << YAML::Key << "plugins";
    this->analEmitter << YAML::Value << YAML::BeginMap;
};

size_t ReportImpl::size()
{
    fs.flush();
    return fs.tellp();
}

int ReportImpl::write(const long tid, const core::RuleCheckMsg &rcmsg)
{
    // TODO: separated files?
    std::string approval = (rcmsg.approval) ? "Pass" : "Fail";

    fs << "[" << approval << "]" << "\tTreadID: " << tid << "\tRuleId: " << rcmsg.ruleID << "\tRuleName: " << rcmsg.ruleName;
    
    if (!approval.compare("Fail"))
        fs << "\tMessage: " << rcmsg.msg << std::endl;
    else
        fs << std::endl;

    return 0;
}

int ReportImpl::write(const long tid, const std::string & customOutput)
{
    // TODO: separated files?
    fs << customOutput << std::endl;
    return 0;
}

int ReportImpl::analyze(const std::string &key, const YAML::Node &node)
{
    // YAML::Node is a value that can happen at the right side of a map entry
    // so the node itself cannot be an entry, which means key is needed for complete entry
    if (!this->analFilename.empty() && !node.IsNull())
        this->analEmitter << YAML::Key << key << YAML::Value << node;
    return 0;
}

int ReportImpl::flush()
{
    fs.flush();

    if (!this->analFilename.empty()) {
        this->analEmitter << YAML::EndMap;
        this->analEmitter << YAML::EndMap;
        this->analFs << this->analEmitter.c_str();
        this->analFs.flush();
    }

    return 0;
}

ReportImpl::~ReportImpl()
{

}

} // namespace core
} // namespace SAIL
