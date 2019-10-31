#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "tracee.h"

Tracee::Tracee(int tid) : tid(tid)
{
}

Tracee::~Tracee()
{
}

void Tracee::trap()
{  
    struct user_regs_struct regs;
    long orig_rax = ptrace(PTRACE_PEEKUSER, this->tid, 8*ORIG_RAX, NULL);
    // detect syscall: clone
    spdlog::info("syscall {} in tid {}", orig_rax, this->tid);
    if (orig_rax == SYS_clone) {
        ptrace(PTRACE_GETREGS, this->tid, NULL, &regs);
        if (this->iscalling) {
            this->iscalling = false;
            spdlog::info("SYS_clone call start in tid %d", this->tid);
        } else {
            this->iscalling = true;
            if (regs.rax != 0) {
                // return in parent thread (return value in child thread is 0)
                ptrace(PTRACE_ATTACH, regs.rax, NULL, NULL);
            }
            spdlog::info("SYS_clone call return %lld in tid %d", regs.rax, this->tid);
        }                                  
    }
}