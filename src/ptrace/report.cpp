#include <iostream>
#include <assert.h>

#include "report.h"
#include "spdlog/spdlog.h"

namespace SAIL
{
namespace core
{
ReportImpl::ReportImpl(const std::string & filename)
{
    this->filename = filename;
    this->fs = std::make_unique<std::fstream>();
    fs->open(filename.c_str(), std::ios::app);
    assert(fs->is_open());
    if (!fs->is_open())
    {
        spdlog::error("Report failed to open {}!", filename.c_str());
    }
};

size_t ReportImpl::size()
{
    fs->flush();
    return fs->tellp();
}

int ReportImpl::write(const long tid, const long callID, const core::RuleCheckMsg &rcmsg)
{
    std::string approval = (rcmsg.approval) ? "pass" : "warning";

    (*fs) << tid << "," << callID << "," << rcmsg.ruleID << "," << approval << "," << rcmsg.msg << std::endl;

    return 0;
}

int ReportImpl::flush()
{
    fs->flush();

    return 0;
}

ReportImpl::~ReportImpl()
{
    fs->close();
}

} // namespace core
} // namespace SAIL