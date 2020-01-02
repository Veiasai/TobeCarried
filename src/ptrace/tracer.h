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
    // for whitelist
    std::shared_ptr<Whitelist> whitelist;
    long brokenThreads;
    bool interrupt;
public:
    Tracer(std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report, std::shared_ptr<Whitelist> whitelist, int rootTracee);
    ~Tracer();
    void run();
    void end();
};

}}