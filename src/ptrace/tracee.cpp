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
                       std::shared_ptr<rule::RuleManager> rulemgr, std::shared_ptr<Report> report, std::shared_ptr<Whitelist> whitelist)
    : tid(tid), up(up), cp(cp), rulemgr(rulemgr), report(report), whitelist(whitelist)
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
    // syscall number to name
    std::string syscallName = SAIL::SYSCALL::syscall_assist.at(orig_rax);
    spdlog::info("[tid: {}] [syscall: {}] calling {}", this->tid, syscallName, this->iscalling ? "in" : "out");

    if (this->iscalling)
    {
        this->history.emplace_back();
        cp->getRegs(this->tid, &this->history.back().call_regs);
    }
    else
    {
        cp->getRegs(this->tid, &this->history.back().ret_regs);
    }
    // get all reached filenames
    this->up->getFilenamesByProc(tid, fileset);

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
        // spdlog::debug("[tid: {}] Start Check SYSCALL {}", tid, orig_rax);
        std::vector<RuleCheckMsg> cnt = this->rulemgr->check(orig_rax, this->syscallParams);
        // spdlog::debug("[tid: {}] Finish Check SYSCALL {}, checkMsgSize {}", tid, orig_rax, cnt.size());
        for (auto &checkMsg : cnt)
        {
            //TODO log
            // spdlog::debug("[tid: {}] Report CheckMsg {}", tid, checkMsg);
            report->write(this->tid, this->callID, checkMsg);
        }
        this->callID++;
        report->flush();
        this->ruleCheckMsg.emplace_back(std::move(cnt));
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
        struct utsname *paras = (struct utsname *)(this->history.back().call_regs.rdi);
        char p[MAX_FILENAME_SIZE];

        struct utsname para;

        this->up->readBytesFrom(this->tid, (char *)(paras), (char *)&para, sizeof(utsname));
        std::string sysname = para.sysname;
        std::string nodename = para.nodename;

        std::string a = "{sysname:" + sysname + " nodename: " + nodename + "...}";
        char *para1 = (char *)(a.c_str());

        this->syscallParams.parameters[ParameterIndex::First] = Parameter(pointer, MAX_FILENAME_SIZE, para1, 0);
        spdlog::debug("[tid: {}] uname: utsname: {}", tid, a);
    }
}
// execve
void TraceeImpl::sysExecve()
{
    // int execve(const char *filename, char *const argv[], char *const envp[]);
    if (this->iscalling)
    {
        const char *filename = (char *)this->history.back().call_regs.rdi;
        assert(filename);

        this->up->readStrFrom(this->tid, filename, this->localFilename, MAX_FILENAME_SIZE);
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(pointer, MAX_FILENAME_SIZE, this->localFilename, 0);
        spdlog::debug("[tid: {}] execve: filename: {}", tid, this->localFilename);

        char **paras = (char **)(this->history.back().call_regs.rsi);
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

        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(pointer, MAX_FILENAME_SIZE, passargvs, 0);
        spdlog::debug("[tid: {}] execve: argv: {}", tid, passargvs);
    }
    else
    {
    }
}

// file
void TraceeImpl::open()
{
    // fd 0, 1, 2 never be opened, handle specially in constructor
    if (this->iscalling)
    {
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
    }
    else
    {
        const unsigned long long int fd = this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, fd);
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
        const int dirfd = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, dirfd);

        const char *pathname = (char *)this->history.back().call_regs.rsi;
        this->up->readStrFrom(this->tid, pathname, this->localFilename, MAX_FILENAME_SIZE);
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(pointer, MAX_FILENAME_SIZE, this->localFilename, 0);

        const int flags = (int)this->history.back().call_regs.rdx;
        this->syscallParams.parameters[ParameterIndex::Third] = Parameter(nonpointer, 0, NULL, flags);
        spdlog::debug("[tid: {}] Openat: dirfd: {}  filename: {}", tid, dirfd, this->localFilename);
    }
    else
    {
        const int ret = (int)this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, ret);
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
        const int fd = (int)this->history.back().call_regs.rdi;
        spdlog::debug("[tid: {}] ioctl Call: fd: {}", tid, fd);
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, fd);

        const unsigned long int cmd = (unsigned long int)this->history.back().call_regs.rsi;
        spdlog::debug("[tid: {}] ioctl Call: cmd: 0x{:x}", tid, cmd);
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(nonpointer, 0, NULL, cmd);

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
        const int ret = (int)this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, ret);
    }
}
void TraceeImpl::read()
{
    if (this->iscalling)
    {
        const int fd = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, fd);
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
        const int size = this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, size);
        if (size < 0)
        {
            spdlog::debug("[tid: {}] Read Ret less than 0", tid);
            return;
        }
        const char *buf = (char *)this->history.back().call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        spdlog::debug("[tid: {}] Read Ret: size: {}", tid, size);
        this->up->readBytesFrom(this->tid, buf, localBuf, std::min(size, MAX_READ_SIZE));
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(pointer, size, localBuf, 0);

        spdlog::debug("[tid: {}] Read Ret: content: {}", tid, localBuf);
    }
}
void TraceeImpl::write()
{
    if (this->iscalling)
    {
        const int fd = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, fd);
        spdlog::debug("[tid: {}] Write Call: fd: {}", tid, fd);

        std::string filename;
        int r = this->up->getFilenameByFd(this->tid, fd, filename);
        if (r == 0)
        {
            spdlog::debug("[tid: {}] Write Call: filename: {}", tid, filename);
        }
        // const char *buf = (char *)this->history.back().call_regs.rsi;
        // char localBuf[MAX_READ_SIZE];
        // this->up->readBytesFrom(this->tid, buf, localBuf, MAX_READ_SIZE);
        // spdlog::debug("[tid: {}] Write Ret: content: {}", tid, localBuf);
    }
    else
    {
        const int size = this->history.back().ret_regs.rax;
        this->syscallParams.parameters[ParameterIndex::Ret] = Parameter(nonpointer, 0, NULL, size);
        if (size < 0)
        {
            spdlog::debug("[tid: {}] Write Ret less than 0", tid);
            return;
        }
        const char *buf = (char *)this->history.back().call_regs.rsi;
        char localBuf[MAX_READ_SIZE];
        spdlog::debug("[tid: {}] Write Ret: size: {}", tid, size);
        this->up->readBytesFrom(this->tid, buf, localBuf, std::min(size, MAX_READ_SIZE));
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(pointer, size, localBuf, 0);

        spdlog::debug("[tid: {}] Write Ret: content: {}", tid, localBuf);
        // size of pointer: actual size or required count ?
    }
}

// net
void TraceeImpl::socket()
{
    if (this->iscalling)
    {
        const int domain = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, domain);

        const int type = (int)this->history.back().call_regs.rsi;
        this->syscallParams.parameters[ParameterIndex::Second] = Parameter(nonpointer, 0, NULL, type);

        const int protocol = (int)this->history.back().call_regs.rdx;
        this->syscallParams.parameters[ParameterIndex::Third] = Parameter(nonpointer, 0, NULL, protocol);

        spdlog::debug("[tid: {}] Socket Call: arg: [{}, {}, {}]", tid, domain, type, protocol);
    }
}

void TraceeImpl::connect()
{
    if (this->iscalling)
    {
        const int sockfd = (int)this->history.back().call_regs.rdi;
        this->syscallParams.parameters[ParameterIndex::First] = Parameter(nonpointer, 0, NULL, sockfd);
        spdlog::debug("[tid: {}] Connect Call: sockfd: {}", tid, sockfd);
    }
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
    if (this->iscalling)
    {
        spdlog::info("SYS_clone call in tid {}", this->tid);
    }
    else
    {
        long rax = this->history.back().ret_regs.rax;
        if (rax < 0)
        {
            spdlog::error("SYS_clone ret less than 0");
        }
        spdlog::info("SYS_clone call ret {} in tid {}", rax, this->tid);
    }
}

const std::vector<Systemcall> &TraceeImpl::getHistory()
{
    return this->history;
}

const std::vector<std::vector<RuleCheckMsg>> &TraceeImpl::getRuleCheckMsg()
{
    return this->ruleCheckMsg;
}

void TraceeImpl::end()
{
    // output(refresh) fileset to files.txt
    std::string outfilename = "./logs/" + std::to_string(this->tid) + "_reached_files.txt";
    this->up->strset2file(outfilename, this->fileset);

    // whitelist
    std::set<std::string> whitelist_result = whitelist->Check(fileset);
    std::string outfilename2 = "./logs/" + std::to_string(this->tid) + "_reached_files_report.txt";
    this->up->strset2file(outfilename2, whitelist_result);
}

} // namespace core
} // namespace SAIL