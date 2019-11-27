#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

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
        if(WIFEXITED(status))
            break;
        spdlog::info("[tid: tracer] Thread {} traps", tid);
        spdlog::info("[tid: tracer] signal: {}", WSTOPSIG(status));

        spdlog::info("[tid: tracer] before status: {}", status);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            //当一个线程创建另一个线程返回时，收到的信号
            pid_t new_pid;
            
            if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_CLONE << 8))
            {
                if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &new_pid )
                        != -1)
                {
                    spdlog::debug("thread {} created\n", new_pid);

                }

            }
        }

        if (tracees.find(tid) == tracees.end()) {
            spdlog::info("[tid: tracer] Add Thread {} to tracees", tid);
            tracees[tid] = std::make_unique<TraceeImpl>(tid, up, cp, rulemgr, report);
        }
        try {  
            tracees[tid]->trap();
            
            // wake up child process
            ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
        } catch(exception & e){
            brokenThreads++;
            spdlog::info("[tid: tracer] Thread {} has been broken. Msg: {}", tid, e.what());
            if (tracees.size() == brokenThreads){
                spdlog::info("[tid: tracer] Finish the analysis");
                return;
            }
        }
    }
}

}}