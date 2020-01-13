#pragma once

#include <vector>
#include <memory>
#include <map>
#include <set>

#include "utils.h"
#include "ruleManager.h"
#include "report.h"

namespace SAIL { namespace core {
    
const size_t MAX_FILENAME_SIZE = 256;
const int MAX_READ_SIZE = 1 << 16;  // cannot be too much, otherwise segmentation fault will rise when defining localBuf


class Tracee
{
public:
    virtual ~Tracee() {};
    virtual void trap() = 0;
    virtual const Histories & getHistory() = 0;
    virtual const RuleCheckMsgs & getRuleCheckMsg() = 0;
    virtual void end() = 0;
};

class TraceeImpl : public Tracee
{
private:
    long tid;
    long callID;    //  auto-increment ID for every call
    volatile bool iscalling;
    Histories history;
    RuleCheckMsgs ruleCheckMsgs;
    std::shared_ptr<utils::Utils> up;
    std::shared_ptr<utils::CustomPtrace> cp;
    std::shared_ptr<rule::RuleManager> rulemgr;
    std::shared_ptr<Report> report;

    void extractParameter(long sysnum);
    long paraReg(ParameterIndex index);
public:
    TraceeImpl(int tid, std::shared_ptr<utils::Utils> up,
        std::shared_ptr<utils::CustomPtrace> cp,
        std::shared_ptr<rule::RuleManager> rulemgr,
        std::shared_ptr<Report> report);
    virtual ~TraceeImpl() {};
    virtual void trap() override;
    virtual const Histories & getHistory() override;
    virtual const RuleCheckMsgs & getRuleCheckMsg() override;
    virtual void end() override;
};

}}

