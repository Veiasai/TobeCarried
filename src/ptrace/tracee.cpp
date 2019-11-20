#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "tracee.h"
#include "utils.h"
#include <stdexcept>
#include <algorithm>

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
    this->callID = 0;
    this->lastSyscallID = -1; // -1 means the first syscall
    this->syscallParams.parameters.resize(7);
    memset(this->localFilename, 0, MAX_FILENAME_SIZE);
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
        case SYS_openat:
            // TODO
        default:
            return;
    }

    // check
    if (!this->iscalling) {
        spdlog::debug("[tid: {}] Start Check SYSCALL {}", tid, orig_rax);
        std::vector<RuleCheckMsg> cnt = this->rulemgr->check(orig_rax, this->syscallParams);
        spdlog::debug("[tid: {}] Finish Check SYSCALL {}, checkMsgSize {}", tid, orig_rax, cnt.size());
        for (auto & checkMsg : cnt){
            //TODO log
            // spdlog::debug("[tid: {}] Report CheckMsg {}", tid, checkMsg);
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
        
        this->up->readStrFrom(this->tid, filename, this->localFilename, MAX_FILENAME_SIZE);
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(pointer, MAX_FILENAME_SIZE, this->localFilename, 0);
        
        const int flags = (int)this->history.back().call_regs.rsi;
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(nonpointer, 0, NULL, flags);

        spdlog::debug("[tid: {}] Open: filename: {}", tid, this->localFilename);
    } else {
        const unsigned long long int fd = this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, fd);
    }
}
void TraceeImpl::read()
{
    if (this->iscalling) {
        const int fd = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, fd);
        spdlog::debug("[tid: {}] Read Call: fd: {}", tid, fd);

        std::string filename;
        int r = this->up->getFilenameByFd(this->tid, fd, filename);
        if (r == 0) {
            spdlog::debug("[tid: {}] Read Call: filename: {}", tid, filename);
        }
    }
    else {
        // rax can be -1, but std::min required two args with the same type
        const size_t size = this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, size);
        
        const char *buf = (char *)this->history.back().call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        this->up->readBytesFrom(this->tid, buf, localBuf, std::min(size, MAX_READ_SIZE) - 1);
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(pointer, size, localBuf, 0);

        spdlog::debug("[tid: {}] Read Ret: content: {}", tid, localBuf);
    }
}
void TraceeImpl::write()
{
    if (this->iscalling) {
        const int fd = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, fd);
        spdlog::debug("[tid: {}] Write Call: fd: {}", tid, fd);

        std::string filename;
        int r = this->up->getFilenameByFd(this->tid, fd, filename);
        if (r == 0) {
            spdlog::debug("[tid: {}] Write Call: filename: {}", tid, filename);
        }
    }
    else {
        const size_t size = this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, size);

        const char *buf = (char *)this->history.back().call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        this->up->readBytesFrom(this->tid, buf, localBuf, std::min(size, MAX_READ_SIZE) - 1);
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(pointer, size, localBuf, 0);

        spdlog::debug("[tid: {}] Write Ret: content: {}", tid, localBuf);
        // size of pointer: actual size or required count ?
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