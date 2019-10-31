#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "tracer.h"

using namespace std;

Tracer::Tracer(/* args */)
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
        spdlog::info("Thread {} traps", tid);

        if (tracees.find(tid) == tracees.end()){
            spdlog::info("Add Thread {} to tracees", tid);
            tracees[tid] = std::make_unique<Tracee>(tid);
        }
        tracees[tid]->trap();

        // wake up child parent
        ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
    }
}