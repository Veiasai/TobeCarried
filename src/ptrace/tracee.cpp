#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "tracee.h"
#include "utils.h"
#include "errno.h"
#include <stdexcept>
#include <algorithm>
#include "syscall_assist.h"

namespace
{
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
} // namespace

namespace SAIL
{
namespace core
{

TraceeImpl::TraceeImpl(int tid, std::shared_ptr<utils::Utils> up, std::shared_ptr<utils::CustomPtrace> cp,
                       std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report)
    : tid(tid), up(up), cp(cp), rulemgr(rulemgr), report(report)
{
    this->iscalling = true;
    this->callID = 0;
}

void TraceeImpl::trap()
{
    // grab syscall id
    long orig_rax = cp->peekUser(this->tid, 8 * ORIG_RAX);
    // syscall number to name
    std::string syscallName = SAIL::SYSCALL::syscall_assist.at(orig_rax);
    spdlog::info("[tid: {}] [syscall: {}] calling {}", this->tid, syscallName, this->iscalling ? "in" : "out");

    if (this->iscalling)
    {
        this->history.emplace_back();
        cp->getRegs(this->tid, &this->history.back().first.call_regs);
        this->rulemgr->beforeTrap(this->tid, this->history, this->ruleCheckMsgs);
    }
    else
    {
        cp->getRegs(this->tid, &this->history.back().first.ret_regs);
        extractParameter(orig_rax);
        // TODO: parameter log
        this->rulemgr->afterTrap(this->tid, this->history, this->ruleCheckMsgs);
        this->callID++;
    }

    this->iscalling = !this->iscalling;
}

void TraceeImpl::extractParameter(long sysnum)
{
    this->history.back().second = syscall_call_para_table[sysnum];
    int index = 0;
    for (auto & para : this->history.back().second)
    {
        switch (para.type)
        {
        case ParameterType::lvalue:
            para.value = paraReg(ParameterIndex(index));
            break;
        case ParameterType::pointer:
        {
            para.size = paraReg(ParameterIndex(para.size));
            char * buf = new char[para.size];
            this->up->readBytesFrom(this->tid, reinterpret_cast<const char *>(paraReg(ParameterIndex(index))), buf, para.size);
            para.value = reinterpret_cast<long>(buf);
            break;
        }
        case ParameterType::str:
        {
            char * buf = new char[para.size];
            this->up->readStrFrom(this->tid, reinterpret_cast<const char *>(paraReg(ParameterIndex(index))), buf, para.size);
            para.value = reinterpret_cast<long>(buf);
            break;
        }
        case ParameterType::structp:
        {
            char * buf = new char[para.size];
            this->up->readBytesFrom(this->tid, reinterpret_cast<const char *>(paraReg(ParameterIndex(index))), buf, para.size);
            para.value = reinterpret_cast<long>(buf);
            break;
        }
        case ParameterType::pArray:
        {
            // TODO
        }
        case ParameterType::null:
            assert(0);
            break;
        default:
            break;
        }
        index++;
    }
}

long TraceeImpl::paraReg(ParameterIndex index)
{
    switch (index)
    {
    case ParameterIndex::Ret:
        return this->history.back().first.ret_regs.rax;
    case ParameterIndex::First:
        return this->history.back().first.call_regs.rdi;
    case ParameterIndex::Second:
        return this->history.back().first.call_regs.rsi;
    case ParameterIndex::Third:
        return this->history.back().first.call_regs.rdx;
    case ParameterIndex::Fourth:
        return this->history.back().first.call_regs.rcx;
    case ParameterIndex::Fifth:
        return this->history.back().first.call_regs.r8;
    case ParameterIndex::Sixth:
        return this->history.back().first.call_regs.r9;
    default:
        break;
    }
}

const Histories &TraceeImpl::getHistory()
{
    return this->history;
}

const RuleCheckMsgs &TraceeImpl::getRuleCheckMsg()
{
    return this->ruleCheckMsgs;
}

void TraceeImpl::end()
{
    spdlog::info("Tracee {} invoked end", this->tid);
    for (const auto & ruleCheckMsg : ruleCheckMsgs)
    {
        this->report->write(this->tid, ruleCheckMsg);
    }
    spdlog::info("Tracee {} finished end", this->tid);
}

} // namespace core
} // namespace SAIL