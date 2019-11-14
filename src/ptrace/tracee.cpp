#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "tracee.h"
#include "utils.h"
#include <stdexcept>

namespace {
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
}  // macro SS is defined in <sys/reg.h> but at the same time is used by yaml-cpp

namespace SAIL { namespace core {

TraceeImpl::TraceeImpl(int tid, std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp, 
    std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report) 
    : tid(tid), up(up), cp(cp), rulemgr(rulemgr), report(report)
{
    this->iscalling = true;
    this->lastSyscallID = -1; // -1 means the first syscall
    this->fdToFilename[0] = (char *)"standard-input";
    this->fdToFilename[1] = (char *)"standard-output";
    this->fdToFilename[2] = (char *)"standard-error";
    memset(tmpFilename, 0, MAX_FILENAME_SIZE);
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
        case -1:
            throw std::logic_error("orig_rax get -1"); break;
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

    // check
    if (!this->iscalling) {
        std::vector<RuleCheckMsg> cnt = this->rulemgr->check(orig_rax, this->syscallParams);
        for (auto & checkMsg : cnt){   
            report->write(this->tid, this->callID, checkMsg);
        }
        this->callID++;
        report->flush();
        this->ruleCheckMsg.emplace_back(std::move(cnt));
    }
}

// file
void TraceeImpl::open()
{
    // fd 0, 1, 2 never be opened, handle specially in constructor
    if (this->iscalling) {
        // filename is address in target program memory space
        // need to grab it to tracee memory space
        // when encountering pointer, caution needed
        const char *filename = (char *)this->history.back().call_regs.rdi;
        assert(filename);
        memset(tmpFilename, 0, MAX_FILENAME_SIZE);
        this->up->readStrFrom(this->tid, filename, tmpFilename, MAX_FILENAME_SIZE);

        spdlog::debug("[tid: {}] Open: filename: {}", tid, tmpFilename);
    } else {
        const unsigned long long int fd = this->history.back().ret_regs.rax;
        fdToFilename[fd] = tmpFilename;
        spdlog::debug("[tid: {}] Open: fd: {}", tid, fd);

        this->syscallParams.parameters.push_back(Parameter(nonpointer, 0, NULL, fd));
        this->syscallParams.parameters.push_back(Parameter(pointer, MAX_FILENAME_SIZE, tmpFilename, 0));
        const int flags = (int)this->history.back().call_regs.rsi;
        this->syscallParams.parameters.push_back(Parameter(nonpointer, 0, NULL, flags));
    }
}
void TraceeImpl::read()
{
    if (this->iscalling) {
        const int fd = (int)this->history.back().call_regs.rdi;
        const char *filename = fdToFilename[fd];
        assert(filename);
        spdlog::debug("[tid: {}] Read: filename: {}", tid, filename);
        spdlog::debug("[tid: {}] Read: fd: {}", tid, fd);
    }
    else {
        const ssize_t size = this->history.back().ret_regs.rax;
        const int fd = (int)this->history.back().call_regs.rdi;
        const char *filename = fdToFilename[fd];
        const char *buf = (char *)this->history.back().call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        this->up->readBytesFrom(this->tid, buf, localBuf, size);

        spdlog::debug("[tid: {}] Read: filename: {} content: {}", tid, filename, localBuf);
    }
}
void TraceeImpl::write()
{
    if (this->iscalling) {
        const int fd = (int)this->history.back().call_regs.rdi;
        const char *filename = fdToFilename[fd];
        assert(filename);
        spdlog::debug("[tid: {}] Write: filename: {}", tid, filename);
        spdlog::debug("[tid: {}] Write: fd: {}", tid, fd);
    }
    else {
        const ssize_t size = this->history.back().ret_regs.rax;
        const int fd = (int)this->history.back().call_regs.rdi;
        const char *filename = fdToFilename[fd];
        const char *buf = (char *)this->history.back().call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        this->up->readBytesFrom(this->tid, buf, localBuf, size);

        spdlog::debug("[tid: {}] Read: filename: {} content: {}", tid, filename, localBuf);
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

const std::vector<std::vector<RuleCheckMsg>> & TraceeImpl::getRuleCheckMsg()
{
    return this->ruleCheckMsg;
}

}}