#pragma once

#include <string>
#include <fstream>
#include <memory>
#include <yaml-cpp/yaml.h>

#include "parameter.h"

namespace SAIL
{
namespace core
{

class Report
{
public:
    virtual ~Report(){};
    virtual int write(const long tid, const core::RuleCheckMsg &rcmsg) = 0;
    virtual int write(const long tid, const std::string & customOutput) = 0;
    virtual int analyze(const std::string &key, const YAML::Node &node) = 0;
    virtual int flush() = 0;
    virtual size_t size() = 0;
};

class ReportImpl : public Report
{
private:
    std::string filename;
    std::fstream fs;
    std::string analFilename;
    std::fstream analFs;
    YAML::Emitter analEmitter;

public:
    ReportImpl(const std::string & filename);
    ReportImpl(const std::string & filename, const std::string & analysis);
    virtual ~ReportImpl();
    virtual int write(const long tid, const core::RuleCheckMsg &rcmsg) override;
    virtual int write(const long tid, const std::string & customOutput) override;
    virtual int analyze(const std::string &key, const YAML::Node &node) override;
    virtual int flush() override;
    virtual size_t size() override;
};

} // namespace core
} // namespace SAIL