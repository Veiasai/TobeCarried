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
    std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report) 
    : up(up), cp(cp), rulemgr(rulemgr), report(report)
{
    brokenThreads = 0;
}

Tracer::~Tracer()
{
}

void Tracer::run(/* args */)
{
    int status;
    
    while(1) {
        int tid = wait(&status);
        if(WIFEXITED(status)) {
            brokenThreads++;
            spdlog::info("[tid: tracer] Thread {} has exited", tid);
            if (tracees.size() == brokenThreads){
                spdlog::info("[tid: tracer] Finish the analysis");
                return;
            }
        }
        spdlog::info("[tid: tracer] Thread {} traps", tid);
        spdlog::info("[tid: tracer] signal: {}", WSTOPSIG(status));
        spdlog::info("[tid: tracer] before status: {:x}", status);

        if (status >> 16 != 0){
            long msg;
            ptrace(PTRACE_GETEVENTMSG, tid, 0, (long) &msg);
            spdlog::info("PTRACE_GETEVENTMSG {}", msg);
            if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
                int newid = static_cast<int>(msg);
                tracees[newid] = std::make_unique<TraceeImpl>(newid, up, cp, rulemgr, report);
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, newid, NULL, NULL);
                continue;
            }
            else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                continue;
            }
        }

        if (tracees.find(tid) == tracees.end()) {
            spdlog::error("[tid: tracer] unexpected Thread {}", tid);
            tracees[tid] = std::make_unique<TraceeImpl>(tid, up, cp, rulemgr, report);
        }
        try {
            if (WSTOPSIG(status) == SIGTRAP)
            {
                tracees[tid]->trap();
            }
            else if (WSTOPSIG(status) == SIGSTOP)
            {
                spdlog::info("[tid: tracer] status == SIGSTOP");
            }
            
            // wake up child process
            ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
        } catch(exception & e){
            brokenThreads++;
            spdlog::info("[tid: tracer] Thread {} has been broken. Msg: {}", tid, e.what());
            if (tracees.size() == brokenThreads){
                spdlog::info("[tid: tracer] Finish the analysis");
                for (const auto & tracee : tracees){
                    tracee.second->end();
                }
                return;
            }
        }
    }
}

}}