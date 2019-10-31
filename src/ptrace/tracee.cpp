#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "tracee.h"
#include "utils.h"

Tracee::Tracee(int tid) : tid(tid)
{
    this->iscalling = true;
}

Tracee::~Tracee()
{
}

void Tracee::trap()
{  
    long orig_rax = ptrace(PTRACE_PEEKUSER, this->tid, 8*ORIG_RAX, NULL);
    spdlog::info("syscall {} in tid {}", orig_rax, this->tid);

    if (this->iscalling) {
        this->history.emplace_back();
        ptrace(PTRACE_GETREGS, this->tid, NULL, &this->history.back().call_regs);
    } else {
        ptrace(PTRACE_GETREGS, this->tid, NULL, &this->history.back().ret_regs);
    }

    switch (orig_rax)
    {
        case SYS_clone: 
            clone(); break;
        case SYS_open:
            open(); break;
        case SYS_read:
            read(); break;
        case SYS_write:
            write(); break;
        case SYS_connect:
            connect(); break;
        case SYS_recvfrom:
            recvfrom(); break;
        case SYS_sendto:
            sendto(); break;
        default:
            break;
    }

    this->iscalling = !this->iscalling;
}

// file
void Tracee::open()
{
    if (this->iscalling){
        const char * filename = (char *)this->history.back().call_regs.rdi;
        char buf[256];
        int r = readStrFrom(this->tid, filename, buf, 255);

        spdlog::debug("Open: filename: {}", buf);
    } else {

    }
}
void Tracee::read()
{

}
void Tracee::write()
{

}

// net
void Tracee::connect()
{

}
void Tracee::recvfrom()
{

}
void Tracee::sendto()
{

}

// clone
void Tracee::clone()
{
    if (this->iscalling) {
        spdlog::info("SYS_clone call in tid %d", this->tid);
    } else {
        long rax = this->history.back().ret_regs.rax;
        if (rax != 0) {
            // return in parent thread (return value in child thread is 0)
            ptrace(PTRACE_ATTACH, rax, NULL, NULL);
        }
        spdlog::info("SYS_clone call return %lld in tid %d", rax, this->tid);
    }
}