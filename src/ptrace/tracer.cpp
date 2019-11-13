#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "tracer.h"

using namespace std;

namespace SAIL { namespace core {

Tracer::Tracer(std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, std::shared_ptr<rule::RuleManager> rulemgr) : up(up), cp(cp), rulemgr(rulemgr)
{
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

        if (tracees.find(tid) == tracees.end()) {
            spdlog::info("[tid: tracer] Add Thread {} to tracees", tid);
            tracees[tid] = std::make_unique<TraceeImpl>(tid, up, cp, rulemgr);
        }
        tracees[tid]->trap();

        // wake up child parent
        ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
    }
}

}}