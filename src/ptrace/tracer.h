#pragma once
#include <map>
#include <set>
#include <memory>
#include "tracee.h"
#include "report.h"

namespace SAIL { namespace core {

class Tracer
{
private:
    std::map<int, std::unique_ptr<Tracee>> tracees;
    std::shared_ptr<utils::Utils> up;
    std::shared_ptr<utils::CustomPtrace> cp;
    std::shared_ptr<rule::RuleManager> rulemgr;
    std::shared_ptr<Report> report;
    long brokenThreads;
public:
    Tracer(std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report);
    ~Tracer();
    void run();
};

}}