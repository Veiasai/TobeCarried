#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/fmt/bin_to_hex.h"

#include "tracer.h"

using namespace std;

namespace SAIL { namespace core {

Tracer::Tracer(std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, 
    std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report, std::shared_ptr<Whitelist> whitelist, int rootTracee) 
    : up(up), cp(cp), rulemgr(rulemgr), report(report), whitelist(whitelist)
{
    brokenThreads = 0;
    tracees[rootTracee] = std::make_unique<TraceeImpl>(rootTracee, up, cp, rulemgr, report, whitelist);
}

Tracer::~Tracer()
{
}

void Tracer::run(/* args */)
{
    int status;
    
    while(1) {
        int tid = wait(&status);
        spdlog::info("------------------------------");
        if (WIFEXITED(status)) {
            brokenThreads++;
            spdlog::info("[tid: tracer] Thread {} has exited", tid);
            if (tracees.size() == brokenThreads) {
                spdlog::info("[tid: tracer] Finish the analysis");
                break;
            }
        }
        spdlog::info("[tid: tracer] Thread {} traps with signal {:x}", tid, status);

        if (status >> 16 != 0) {
            // event happened
            long msg;
            ptrace(PTRACE_GETEVENTMSG, tid, 0, (long) &msg);
            spdlog::info("PTRACE_GETEVENTMSG {}", msg);
            if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
                int newid = static_cast<int>(msg);
                if (tracees.find(newid) == tracees.end())
                    tracees[newid] = std::make_unique<TraceeImpl>(newid, up, cp, rulemgr, report, whitelist);
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, newid, NULL, NULL);
                continue;
            }
            else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                continue;
            }
        }

        // parent thread enters into clone -> event detected -> parent thread returns from clone, this order is deterministic
        // but child thread returning from clone could happen at any time after parent thread enters into clone
        // so when child thread returning happens before event detected, new tracee will be created here
        // when child thread returning happend after evnet detected, new tracee will created at event detected time
        // but even in the former condition, newly cloned thread can still be attached to watch list automatically
        if (tracees.find(tid) == tracees.end()) {
            tracees[tid] = std::make_unique<TraceeImpl>(tid, up, cp, rulemgr, report, whitelist);
        }

        try {
            if (WSTOPSIG(status) == SIGTRAP)
            {
                tracees[tid]->trap();
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            else if (WSTOPSIG(status) == SIGSTOP)
            {
                // wake up process
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            else if (WSTOPSIG(status) == SIGSEGV)
            {
                brokenThreads++;
            }
            else if (WSTOPSIG(status) == SIGABRT)
            {
                brokenThreads++;
            }
            else
            {
                assert(0);
            }
            
        } catch(exception & e){
            spdlog::error("[tid: tracer] Thread {} has been broken. Msg: {}", tid, e.what());
        }
        if (tracees.size() == brokenThreads) {
            spdlog::info("[tid: tracer] Finish the analysis");
            break;
        }
    }

    for (const auto & tracee : tracees){
        tracee.second->end();
    }
}

}}