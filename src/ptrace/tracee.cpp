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
    this->lastSyscallID = -1; // -1 means the first syscall
    memset(this->localFilename, 0, MAX_FILENAME_SIZE);
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
        this->history.back().second.resize(7);
        cp->getRegs(this->tid, &this->history.back().first.call_regs);
    }
    else
    {
        cp->getRegs(this->tid, &this->history.back().first.ret_regs);
    }

    switch (orig_rax)
    {
    case -1:
        throw std::logic_error("orig_rax get -1");
        break;
    case SYS_clone:
        clone();
        break;
    case SYS_open:
        open();
        break;
    case SYS_read:
        read();
        break;
    case SYS_write:
        write();
        break;
    case SYS_socket:
        socket();
        break;
    case SYS_connect:
        connect();
        break;
    case SYS_recvfrom:
        recvfrom();
        break;
    case SYS_sendto:
        sendto();
        break;
    case SYS_openat:
        openat();
        break;
    case SYS_ioctl:
        ioctl();
        break;
    case SYS_execve:
        sysExecve();
        break;
    case SYS_uname:
        uname();
        break;
    default:
        this->iscalling = !this->iscalling;
        return;
    }

    // check
    if (!this->iscalling)
    {
        this->rulemgr->afterTrap(this->tid, this->history, this->ruleCheckMsgs);
        this->callID++;
    }
    else
    {
        this->rulemgr->beforeTrap(this->tid, this->history, this->ruleCheckMsgs);
    }
    this->iscalling = !this->iscalling;
}

// uname
void TraceeImpl::uname()
{
    // int uname(struct utsname *buf);
    // int execve(const char *filename, char *const argv[], char *const envp[]);
    if (this->iscalling)
    {
    }
    else
    {
        struct utsname *paras = (struct utsname *)(this->history.back().first.call_regs.rdi);
        char p[MAX_FILENAME_SIZE];

        struct utsname para;

        this->up->readBytesFrom(this->tid, (char *)(paras), (char *)&para, sizeof(utsname));
        std::string sysname = para.sysname;
        std::string nodename = para.nodename;

        std::string a = "{sysname:" + sysname + " nodename: " + nodename + "...}";
        char *para1 = (char *)(a.c_str());

        this->history.back().second[ParameterIndex::First] = Parameter(MAX_FILENAME_SIZE, reinterpret_cast<long>(para1));
        spdlog::debug("[tid: {}] uname: utsname: {}", tid, a);
    }
}
// execve
void TraceeImpl::sysExecve()
{
    // int execve(const char *filename, char *const argv[], char *const envp[]);
    if (this->iscalling)
    {
        const char *filename = (char *)this->history.back().first.call_regs.rdi;
        assert(filename);

        this->up->readStrFrom(this->tid, filename, this->localFilename, MAX_FILENAME_SIZE);
        this->history.back().second[ParameterIndex::First] = Parameter(MAX_FILENAME_SIZE, reinterpret_cast<long>(this->localFilename));
        spdlog::debug("[tid: {}] execve: filename: {}", tid, this->localFilename);

        char **paras = (char **)(this->history.back().first.call_regs.rsi);
        char p[MAX_FILENAME_SIZE];
        int i = 0;
        std::string argvs = "";
        for (;;)
        {
            long para;
            this->up->readBytesFrom(this->tid, (char *)(paras + i), (char *)&para, 8);
            if (para == 0)
            {
                break;
            }
            this->up->readStrFrom(this->tid, (char *)para, p, MAX_FILENAME_SIZE);

            argvs = argvs + " " + std::string(p);
            i++;
            if (i > 20)
                break;
        }

        char *passargvs = (char *)argvs.data();

        this->history.back().second[ParameterIndex::Second] = Parameter(MAX_FILENAME_SIZE, reinterpret_cast<long>(passargvs));
        spdlog::debug("[tid: {}] execve: argv: {}", tid, passargvs);
    }
    else
    {
    }
}

// file
void TraceeImpl::open()
{
    if (this->iscalling)
    {
        // filename is address in target program memory space
        // need to grab it to tracee memory space
        // when encountering pointer, caution needed
        const char *filename = (char *)this->history.back().first.call_regs.rdi;
        assert(filename);

        this->up->readStrFrom(this->tid, filename, this->localFilename, MAX_FILENAME_SIZE);
        this->history.back().second[ParameterIndex::First] = Parameter(MAX_FILENAME_SIZE, reinterpret_cast<long>(this->localFilename));

        const int flags = (int)this->history.back().first.call_regs.rsi;
        this->history.back().second[ParameterIndex::Second] = Parameter(flags);

        spdlog::debug("[tid: {}] Open: filename: {}", tid, this->localFilename);
    }
    else
    {
        const unsigned long long fd = this->history.back().first.ret_regs.rax;
        this->history.back().second[ParameterIndex::Ret] = Parameter(fd);
    }
}
void TraceeImpl::openat()
{
    /*
    int openat(int dirfd, const char *pathname, int flags);
    int openat(int dirfd, const char *pathname, int flags, mode_t mode);

    The openat() system call operates in exactly the same way as open(2), except for the differences described in this manual page.
    If the pathname given in pathname is relative, then it is interpreted relative to the directory referred to by the file descriptor dirfd (rather than relative to the current working directory of the calling process, as is done by open(2) for a relative pathname).
    */

    if (this->iscalling)
    {
        const int dirfd = (int)this->history.back().first.call_regs.rdi;
        this->history.back().second[ParameterIndex::First] = Parameter(dirfd);

        const char *pathname = (char *)this->history.back().first.call_regs.rsi;
        this->up->readStrFrom(this->tid, pathname, this->localFilename, MAX_FILENAME_SIZE);
        this->history.back().second[ParameterIndex::Second] = Parameter(MAX_FILENAME_SIZE, reinterpret_cast<long>(this->localFilename));

        const int flags = (int)this->history.back().first.call_regs.rdx;
        this->history.back().second[ParameterIndex::Third] = Parameter(flags);
        spdlog::debug("[tid: {}] Openat: dirfd: {}  filename: {}", tid, dirfd, this->localFilename);
    }
    else
    {
        const int ret = (int)this->history.back().first.ret_regs.rax;
        this->history.back().second[ParameterIndex::Ret] = Parameter(ret);
    }
}
void TraceeImpl::ioctl()
{
    /*
    int ioctl(int fd,unsigned long cmd,...);
    fd:文件描述符
    cmd:控制命令
    ...:可选参数:插入*argp，具体内容依赖于cmd
    */
    if (this->iscalling)
    {
        const int fd = (int)this->history.back().first.call_regs.rdi;
        spdlog::debug("[tid: {}] ioctl Call: fd: {}", tid, fd);
        this->history.back().second[ParameterIndex::First] = Parameter(fd);

        const unsigned long int cmd = (unsigned long int)this->history.back().first.call_regs.rsi;
        spdlog::debug("[tid: {}] ioctl Call: cmd: 0x{:x}", tid, cmd);
        this->history.back().second[ParameterIndex::Second] = Parameter(cmd);

        switch (cmd)
        {
        case FIONBIO:
            spdlog::debug("[tid: {}] ioctl Call: cmd: {}", tid, "FIONBIO");
            break;
        case SIOCGIFADDR:
            spdlog::debug("[tid: {}] ioctl Call: cmd: {}", tid, "SIOCGIFADDR");
            break;
        case SIOCGIFCONF:
            spdlog::debug("[tid: {}] ioctl Call: cmd: {}", tid, "SIOCGIFCONF");
            break;
        default:
            break;
        }
    }
    else
    {
        const int ret = (int)this->history.back().first.ret_regs.rax;
        this->history.back().second[ParameterIndex::Ret] = Parameter(ret);
    }
}
void TraceeImpl::read()
{
    if (this->iscalling)
    {
        const int fd = (int)this->history.back().first.call_regs.rdi;
        this->history.back().second[ParameterIndex::First] = Parameter(fd);
        spdlog::debug("[tid: {}] Read Call: fd: {}", tid, fd);

        std::string filename;
        int r = this->up->getFilenameByFd(this->tid, fd, filename);
        if (r == 0)
        {
            spdlog::debug("[tid: {}] Read Call: filename: {}", tid, filename);
        }
    }
    else
    {
        // rax can be -1, but std::min required two args with the same type
        const int size = this->history.back().first.ret_regs.rax;
        this->history.back().second[ParameterIndex::Ret] = Parameter(size);
        if (size < 0)
        {
            spdlog::debug("[tid: {}] Read Ret less than 0", tid);
            return;
        }
        const char *buf = (char *)this->history.back().first.call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        spdlog::debug("[tid: {}] Read Ret: size: {}", tid, size);
        this->up->readBytesFrom(this->tid, buf, localBuf, std::min(size, MAX_READ_SIZE));
        this->history.back().second[ParameterIndex::Second] = Parameter(size, reinterpret_cast<long>(localBuf));

        spdlog::debug("[tid: {}] Read Ret: content: {}", tid, localBuf);
    }
}
void TraceeImpl::write()
{
    if (this->iscalling)
    {
        const int fd = (int)this->history.back().first.call_regs.rdi;
        this->history.back().second[ParameterIndex::First] = Parameter(fd);
        spdlog::debug("[tid: {}] Write Call: fd: {}", tid, fd);

        std::string filename;
        int r = this->up->getFilenameByFd(this->tid, fd, filename);
        if (r == 0)
        {
            spdlog::debug("[tid: {}] Write Call: filename: {}", tid, filename);
        }
        // const char *buf = (char *)this->history.back().first.call_regs.rsi;
        // char localBuf[MAX_READ_SIZE];
        // this->up->readBytesFrom(this->tid, buf, localBuf, MAX_READ_SIZE);
        // spdlog::debug("[tid: {}] Write Ret: content: {}", tid, localBuf);
    }
    else
    {
        const int size = this->history.back().first.ret_regs.rax;
        this->history.back().second[ParameterIndex::Ret] = Parameter(size);
        if (size < 0)
        {
            spdlog::debug("[tid: {}] Write Ret less than 0", tid);
            return;
        }
        const char *buf = (char *)this->history.back().first.call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        spdlog::debug("[tid: {}] Write Ret: size: {}", tid, size);
        this->up->readBytesFrom(this->tid, buf, localBuf, std::min(size, MAX_READ_SIZE));
        this->history.back().second[ParameterIndex::Second] = Parameter(size, reinterpret_cast<long>(localBuf));

        spdlog::debug("[tid: {}] Write Ret: content: {}", tid, localBuf);
        // size of pointer: actual size or required count ?
    }
}

// net
void TraceeImpl::socket()
{
    if (this->iscalling)
    {
        const unsigned long domain = this->history.back().first.call_regs.rdi;
        this->history.back().second[ParameterIndex::First] = Parameter(domain);

        const unsigned long type = this->history.back().first.call_regs.rsi;
        this->history.back().second[ParameterIndex::Second] = Parameter(type);

        const unsigned long protocol = this->history.back().first.call_regs.rdx;
        this->history.back().second[ParameterIndex::Third] = Parameter(protocol);

        spdlog::debug("[tid: {}] Socket Call: arg: [{}, {}, {}]", tid, domain, type, protocol);
    }
}

void TraceeImpl::connect()
{
    if (this->iscalling)
    {
        const unsigned long sockfd = this->history.back().first.call_regs.rdi;
        const unsigned long sockaddr = this->history.back().first.call_regs.rsi;
        const unsigned long addrlen = this->history.back().first.call_regs.rdx;

        char * fp = new char[addrlen];
        this->up->readBytesFrom(this->tid, reinterpret_cast<char *>(sockaddr), fp, addrlen);
        
        this->history.back().second[ParameterIndex::First] = Parameter(sockfd);
        this->history.back().second[ParameterIndex::Second] = Parameter(addrlen, reinterpret_cast<long>(fp));
        this->history.back().second[ParameterIndex::Third] = Parameter(addrlen);

        spdlog::debug("[tid: {}] Connect Call: arg: [{}, {}, {}]", tid, sockfd, sockaddr, addrlen);
    }
}
void TraceeImpl::recvfrom()
{
    if (this->iscalling)
    {
    }
    else
    {
        const unsigned long sockfd = this->history.back().first.call_regs.rdi;
        const unsigned long buf = this->history.back().first.call_regs.rsi;
        const unsigned long len = this->history.back().first.call_regs.rdx;
        const unsigned long flags = this->history.back().first.call_regs.rcx;
        const unsigned long srcaddr = this->history.back().first.call_regs.r8;
        const unsigned long addrlen = this->history.back().first.call_regs.r9;
        
        this->history.back().second[ParameterIndex::First] = Parameter(sockfd);
        char * fp = new char[len];
        this->up->readBytesFrom(this->tid, reinterpret_cast<char *>(buf), fp, len);
        this->history.back().second[ParameterIndex::Second] = Parameter(len, reinterpret_cast<long>(fp));
        this->history.back().second[ParameterIndex::Third] = Parameter(len);
        this->history.back().second[ParameterIndex::Fourth] = Parameter(flags);

        // TODO: if the pointer is not null
        if (srcaddr == 0)
        {
            this->history.back().second[ParameterIndex::Fifth] = Parameter(0, 0);
        }
        else
        {
            
        }
        this->history.back().second[ParameterIndex::Sixth] = Parameter(addrlen);
    }
}
void TraceeImpl::sendto()
{
    if (this->iscalling)
    {
    }
    else
    {
        const unsigned long sockfd = this->history.back().first.call_regs.rdi;
        const unsigned long buf = this->history.back().first.call_regs.rsi;
        const unsigned long len = this->history.back().first.call_regs.rdx;
        const unsigned long flags = this->history.back().first.call_regs.rcx;
        const unsigned long dstaddr = this->history.back().first.call_regs.r8;
        const unsigned long addrlen = this->history.back().first.call_regs.r9;
        
        this->history.back().second[ParameterIndex::First] = Parameter(sockfd);
        char * fp = new char[len];
        this->up->readBytesFrom(this->tid, reinterpret_cast<char *>(buf), fp, len);
        this->history.back().second[ParameterIndex::Second] = Parameter(len, reinterpret_cast<long>(fp));
        this->history.back().second[ParameterIndex::Third] = Parameter(len);
        this->history.back().second[ParameterIndex::Fourth] = Parameter(flags);

        // TODO: if the pointer is not null
        if (dstaddr == 0)
        {
            this->history.back().second[ParameterIndex::Fifth] = Parameter(0, 0);
        }
        else
        {
            
        }
        this->history.back().second[ParameterIndex::Sixth] = Parameter(addrlen);
    }
}

// clone
void TraceeImpl::clone()
{
    if (this->iscalling)
    {
        spdlog::info("SYS_clone call in tid {}", this->tid);
    }
    else
    {
        long rax = this->history.back().first.ret_regs.rax;
        if (rax < 0)
        {
            spdlog::error("SYS_clone ret less than 0");
        }
        spdlog::info("SYS_clone call ret {} in tid {}", rax, this->tid);
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