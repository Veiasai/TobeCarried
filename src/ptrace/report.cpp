#include "report.h"
#include <iostream>

namespace SAIL
{
namespace core
{
ReportImpl::ReportImpl(std::string filename)
{
    this->filename = filename;
    this->fs = std::make_unique<std::fstream>();
    fs->open(filename.c_str(), std::ios::app);
    if (!fs->is_open())
    {
        std::cerr << "Report error open!" << std::endl;
        fs->clear();
    }
};

size_t ReportImpl::size()
{
    return this->size;
}

int ReportImpl::write(const core::RuleCheckMsg &rcmsg)
{
    std::string approval = (rcmsg.approval) ? "pass" : "warning";

    std::string reportLine = std::to_string(rcmsg.ruleID) + " " + approval + " " + rcmsg.msg + "\n";

    (*fs) << reportLine;

    // update size
    fs->seekp(0, fs->end);
    this->size = fs->tellp();

    return 1;
}

ReportImpl::~ReportImpl()
{
    fs->close();
}

} // namespace core
} // namespace SAIL
