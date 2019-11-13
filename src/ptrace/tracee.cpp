#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "tracee.h"
#include "utils.h"

namespace {
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
}  // macro SS is defined in <sys/reg.h> but at the same time is used by yaml-cpp

namespace SAIL { namespace core {

TraceeImpl::TraceeImpl(int tid, std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, std::shared_ptr<rule::RuleManager> rulemgr) : tid(tid), up(up), cp(cp), rulemgr(rulemgr)
{
    this->iscalling = true;
    this->lastSyscallID = -1;  // -1 means the first syscall
}

void TraceeImpl::trap()
{  
    // grab syscall id
    long orig_rax = cp->peekUser(this->tid, 8 * ORIG_RAX);
    spdlog::info("[tid: {}] syscall {}", this->tid, orig_rax);

    if (this->iscalling && orig_rax == lastSyscallID) {
        // prevent that some syscalls don't return
        this->iscalling = false;
    }
    else if (!this->iscalling) {
        this->iscalling = true;
    }
    this->lastSyscallID = orig_rax;

    if (this->iscalling) {
        this->history.emplace_back();
        cp->getRegs(this->tid, &this->history.back().call_regs);
    } else {
        cp->getRegs(this->tid, &this->history.back().ret_regs);
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

}

// file
void TraceeImpl::open()
{
    if (this->iscalling) {
        const char *filename = (char *)this->history.back().call_regs.rdi;
        int r = up->readStrFrom(this->tid, filename, tmpFilename, MAX_FILENAME_SIZE);

        spdlog::debug("[tid: {}] Open: filename: {}", tid, tmpFilename);
    } else {
        const unsigned long long int fd = this->history.back().ret_regs.rax;
        fdToFilename[fd] = tmpFilename;
    }
}
void TraceeImpl::read()
{
    if (this->iscalling) {
        const int fd = (int)this->history.back().call_regs.rdi;
        const char *filename = fdToFilename[fd];

        spdlog::debug("[tid: {}] Read: filename: {}", tid, filename);
    }
}
void TraceeImpl::write()
{
    if (this->iscalling) {
        const int fd = (int)this->history.back().call_regs.rdi;
        const char *filename = fdToFilename[fd];

        spdlog::debug("[tid: {}] Write: filename: {}", tid, filename);
    }
}

// net
void TraceeImpl::connect()
{

}
void TraceeImpl::recvfrom()
{

}
void TraceeImpl::sendto()
{

}

// clone
void TraceeImpl::clone()
{
    if (this->iscalling) {
        spdlog::info("SYS_clone call in tid %d", this->tid);
    } else {
        long rax = this->history.back().ret_regs.rax;
        if (rax != 0) {
            // return in parent thread (return value in child thread is 0)
            cp->attach(rax);
        }
        spdlog::info("SYS_clone call return %lld in tid %d", rax, this->tid);
    }
}

const std::vector<Systemcall> & TraceeImpl::getHistory()
{
    return this->history;
}

const std::vector<WarnInfo> & TraceeImpl::getReport()
{
    return this->report;
}

}}