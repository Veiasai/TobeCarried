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
    std::string syscallName;
    int ret = this->up->sysnum2str(orig_rax, syscallName);
    assert(ret == 0);
    spdlog::info("[tid: {}] [syscall: {}] calling {}", this->tid, syscallName, this->iscalling ? "in" : "out");

    if (this->iscalling)
    {
        this->history.emplace_back();
        cp->getRegs(this->tid, &this->history.back().first.call_regs);
        this->rulemgr->beforeTrap(this->tid, this->history, this->ruleCheckMsgs);

        if (orig_rax == SYS_execve || orig_rax == SYS_execveat)
        {
            extractParameter(orig_rax);
        }
    }
    else
    {
        cp->getRegs(this->tid, &this->history.back().first.ret_regs);
        if (orig_rax != SYS_execve && orig_rax != SYS_execveat)
        {
            extractParameter(orig_rax);
        }
        else
        {
            this->history.back().second[ParameterIndex::Ret].value = paraReg(ParameterIndex::Ret);
        }
        
        this->rulemgr->afterTrap(this->tid, this->history, this->ruleCheckMsgs);
        this->callID++;
    }

    this->iscalling = !this->iscalling;
}

void TraceeImpl::extractParameter(long sysnum)
{
    spdlog::debug("Extract Parameter for {}", sysnum);
    int ret = this->up->sysnum2parav(sysnum, this->history.back().second);
    assert(ret == 0);

    if(this->history.back().second.size()==0){
        spdlog::warn("{} not defined.", sysnum);
    }

    int index = 0;
    for (auto & para : this->history.back().second)
    {
        switch (para.type)
        {
        case ParameterType::lvalue:
            para.value = paraReg(ParameterIndex(index));
            spdlog::debug("Parameter {} lvalue {}", index, para.value);
            break;
        case ParameterType::pointer:
        {
            para.size = paraReg(ParameterIndex(para.size));
            // char * buf = new char[para.size];
            para.buf.reset(new char[para.size],std::default_delete<char[]>());
            this->up->readBytesFrom(this->tid, reinterpret_cast<const char *>(paraReg(ParameterIndex(index))), para.buf.get(), para.size);
            para.value = reinterpret_cast<long>(para.buf.get());

            spdlog::debug("Parameter {} pointer", index);
            break;
        }
        case ParameterType::str:
        {
            // char * buf = new char[para.size];
            para.buf.reset(new char[para.size],std::default_delete<char[]>());
            this->up->readStrFrom(this->tid, reinterpret_cast<const char *>(paraReg(ParameterIndex(index))), para.buf.get(), para.size);
            para.value = reinterpret_cast<long>(para.buf.get());

            spdlog::debug("Parameter {} str {}", index, para.buf.get());
            break;
        }
        case ParameterType::structp:
        {
            // char * buf = new char[para.size];
            para.buf.reset(new char[para.size],std::default_delete<char[]>());
            this->up->readBytesFrom(this->tid, reinterpret_cast<const char *>(paraReg(ParameterIndex(index))), para.buf.get(), para.size);
            para.value = reinterpret_cast<long>(para.buf.get());

            spdlog::debug("Parameter {} structp", index);
            break;
        }
        case ParameterType::pArray:
        {
            // fixed size.
            spdlog::debug("Parameter {} strArray", index);
            // char ** value = new char *[24];
            char ** t_p = reinterpret_cast<char **>(paraReg(ParameterIndex(index)));
            for (int i=0;i<24;i++)
            {
                char * p = 0;
                // fetch char * . it works in tid address space. so ptrace read twice.
                this->up->readBytesFrom(this->tid, reinterpret_cast<char *>(t_p + i), reinterpret_cast<char *>(&p), 8);
                if (p == 0)
                {
                    // end of array
                    break;
                }
                // value[i] = new char[128];
                std::string vstring(128,'\0');
                this->up->readStrFrom(this->tid, p, const_cast<char*>(vstring.c_str()), 128);
                (para.value_vector).push_back(std::move(vstring)); 
                spdlog::debug("str{}: {}", i, (para.value_vector)[i].c_str());
            }

            break;
        }
        case ParameterType::null:
            assert(0);
            break;
        default:
            break;
        }
        index++;
    }
    spdlog::debug("Extract Parameter End {}", sysnum);
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