#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/fmt/bin_to_hex.h"
#include <stdarg.h>

#include "tracer.h"

using namespace std;

namespace SAIL { namespace core {

static bool isEvent(int status, int event)
{
    return (status >> 8) == (SIGTRAP | event << 8);
}

static bool hasEvent(int status)
{
    return status >> 16 != 0;
}

Tracer::Tracer(std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, 
    std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report, std::shared_ptr<Whitelist> whitelist, int rootTracee) 
    : up(up), cp(cp), rulemgr(rulemgr), report(report), whitelist(whitelist)
{
    brokenThreads = 0;
    tracees[rootTracee] = std::make_unique<TraceeImpl>(rootTracee, up, cp, rulemgr, report, whitelist);
    interrupt = false;
}

Tracer::~Tracer()
{
}

void Tracer::run()
{
    int status;
    
    for(;;) 
    {
        if (interrupt)
        {
            spdlog::info("[tid: tracer] Received CTRL+C, Exit");
            break;
        }
        if (tracees.size() == brokenThreads)
        {
            spdlog::info("[tid: tracer] All threads have exited, finished the analysis");
            break;
        }
        int tid = wait(&status);
        spdlog::info("------------------------------");
        spdlog::info("[tid: tracer] Thread {} traps with signal {:x}", tid, status);
        if (WIFEXITED(status))
        {
            brokenThreads++;
            spdlog::info("[tid: tracer] Thread {} has exited", tid);
            continue;
        }

        if (hasEvent(status))
        {
            // event happened
            long msg;
            ptrace(PTRACE_GETEVENTMSG, tid, 0, (long) &msg);
            spdlog::info("PTRACE_GETEVENTMSG {}", msg);
            if (isEvent(status, PTRACE_EVENT_FORK) || isEvent(status, PTRACE_EVENT_CLONE)) {
                int newid = static_cast<int>(msg);
                if (tracees.find(newid) == tracees.end())
                    tracees[newid] = std::make_unique<TraceeImpl>(newid, up, cp, rulemgr, report, whitelist);
                // ptrace(PTRACE_SYSCALL, newid, NULL, NULL);
            }
            ptrace(PTRACE_SYSCALL, tid, NULL, NULL);

            this->rulemgr->event(tid, status);
            continue;
        }

        // parent thread enters into clone -> event detected -> parent thread returns from clone, this order is deterministic
        // but child thread returning from clone could happen at any time after parent thread enters into clone
        // so when child thread returning happens before event detected, new tracee will be created here
        // when child thread returning happend after evnet detected, new tracee will created at event detected time
        // but even in the former condition, newly cloned thread can still be attached to watch list automatically
        if (tracees.find(tid) == tracees.end())
        {
            tracees[tid] = std::make_unique<TraceeImpl>(tid, up, cp, rulemgr, report, whitelist);
        }

        try {
            if (WSTOPSIG(status) == SIGTRAP)
            {
                tracees[tid]->trap();
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            else if (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGCHLD || WSTOPSIG(status) == SIGCONT || WSTOPSIG(status) == SIGUSR1 || WSTOPSIG(status) == SIGWINCH)
            {
                // wake up process
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            else if (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGABRT || WSTOPSIG(status) == SIGINT)
            {
                brokenThreads++;
            }
            else
            {
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
        } catch(exception & e){
            spdlog::error("[tid: tracer] Thread {} has been broken. Msg: {}", tid, e.what());
        }
    }

    for (const auto & tracee : tracees)
    {
        tracee.second->end();
    }
}

void Tracer::end()
{
    interrupt = true;

    // for (const auto & tracee : tracees)
    // {
    //     tracee.second->end();
    // }
}

}}