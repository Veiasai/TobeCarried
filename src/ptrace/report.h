#pragma once

#include <string>
#include <fstream>
#include <memory>

#include "parameter.h"

namespace SAIL
{
namespace core
{

class Report
{
public:
    virtual ~Report(){};
    virtual int write(const long tid, const long callID, const core::RuleCheckMsg &rcmsg) = 0;
    virtual int flush() = 0;
    virtual size_t size() = 0;
};

class ReportImpl : public Report
{
private:
    std::string filename;
    std::unique_ptr<std::fstream> fs;

public:
    ReportImpl(const std::string & filename);
    virtual ~ReportImpl();
    virtual int write(const long tid, const long callID, const core::RuleCheckMsg &rcmsg) override;
    virtual int flush() override;
    virtual size_t size() override;
};

} // namespace core
} // namespace SAIL