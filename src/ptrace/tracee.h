#pragma once

#include <sys/user.h>
#include <vector>
#include <memory>
#include <map>

#include "utils.h"
#include "ruleManager.h"
#include "report.h"

namespace SAIL { namespace core {
    
const int MAX_FILENAME_SIZE = 256;
const int MAX_READ_SIZE = 1 << 16;  // cannot be too much, otherwise segmentation fault will rise when defining localBuf

struct Systemcall {
    struct user_regs_struct call_regs;
    struct user_regs_struct ret_regs;
    Systemcall() {};
};

struct WarnInfo {
    // a WarnInfo is related to one specific systemcall
    // callID is that systemcall's index in history
    int callID;

    // TODO: add explanation to this warning
    // e.g. vector<int> breakRules;  show the rules that be breaked;  
};

class Tracee
{
public:
    virtual ~Tracee() {};
    virtual void trap() = 0;
    virtual const std::vector<Systemcall> & getHistory() = 0;
    virtual const std::vector<std::vector<RuleCheckMsg>> & getRuleCheckMsg() = 0;
};

class TraceeImpl : public Tracee
{
private:
    long tid;
    long callID;    //  auto-increment ID for every call
    volatile bool iscalling;
    std::vector<Systemcall> history;
    std::vector<std::vector<RuleCheckMsg>> ruleCheckMsg;
    std::shared_ptr<utils::Utils> up;
    std::shared_ptr<utils::CustomPtrace> cp;
    std::shared_ptr<rule::RuleManager> rulemgr;
    std::shared_ptr<Report> report;
    std::map<int, char *> fdToFilename;

    // for buffering filename to insert into fdToFilename
    char tmpFilename[MAX_FILENAME_SIZE];
    // for buffering syscall id to check whether syscall returns
    long lastSyscallID;
    SyscallParameter syscallParams;

    // file
    void open();
    void read();
    void write();

    // net
    void connect();
    void recvfrom();
    void sendto();

    // clone
    void clone();
public:
    TraceeImpl(int tid, std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report);
    virtual ~TraceeImpl() {};
    virtual void trap();
    virtual const std::vector<Systemcall> & getHistory();
    virtual const std::vector<std::vector<RuleCheckMsg>> & getRuleCheckMsg();
};

}}

