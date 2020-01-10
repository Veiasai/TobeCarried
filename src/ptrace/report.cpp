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

size_t ReportImpl::size()
{
    fs.flush();
    return fs.tellp();
}

int ReportImpl::write(const long tid, const core::RuleCheckMsg &rcmsg)
{
    // TODO: separated files?
    std::string approval = (rcmsg.approval) ? "Pass" : "Warning";

    fs << "[" << approval << "]" << " TreadID: " << tid << ", RuleId: " << rcmsg.ruleID << ", RuleName: " << rcmsg.ruleName  << std::endl;
    
    if(!approval.compare("Warning"))
        fs << "Message: " << rcmsg.msg << std::endl;

    return 0;
}

int ReportImpl::write(const long tid, const std::string & customOutput)
{
    // TODO: separated files?
    fs << customOutput << std::endl;
    return 0;
}

int ReportImpl::flush()
{
    fs.flush();
    return 0;
}

ReportImpl::~ReportImpl()
{

}

} // namespace core
} // namespace SAIL
