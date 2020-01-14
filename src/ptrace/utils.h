#pragma once

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <stdlib.h>
#include <memory>
#include <set>
#include <iostream>
#include <fstream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "parameter.h"
#include "syscall_assist.h"

namespace SAIL { namespace utils {

class CustomPtrace
{
public:
    virtual ~CustomPtrace(){};
    virtual long peekUser(int tid, long addr) = 0;
    virtual long getRegs(int tid, user_regs_struct *regs) = 0;
    virtual long peekData(int tid, long addr) = 0;
    virtual long attach(int tid) = 0;
};

class CustomPtraceImpl : public CustomPtrace
{
public:
    virtual ~CustomPtraceImpl(){};
    virtual long peekUser(int tid, long addr);
    virtual long getRegs(int tid, user_regs_struct *regs);
    virtual long peekData(int tid, long addr);
    virtual long attach(int tid);
};

class Utils
{
public:
    virtual ~Utils(){};
    virtual int readStrFrom(int tid, const char *p, char *buf, size_t s) = 0;
    virtual int readBytesFrom(int tid, const char *p, char *buf, size_t s) = 0;
    virtual int getFilenameByFd(int tid, int fd, std::string &filename) = 0;
    virtual int getFilenamesByProc(int tid,std::set<std::string> &fileset) = 0;
    virtual int strset2file(const std::string &filename, const std::set<std::string> &fileset) = 0;
    virtual int handleEscape(const std::string &str, std::string &regStr) = 0;
    virtual int formatBytes(const std::vector<unsigned char> &vc, std::string &formattedBytes) = 0;
    virtual int formatBytes(const std::string &str, std::string &formattedBytes) = 0;
    virtual int sysname2num(const std::string &, long &) = 0;
    virtual int sysnum2str(long, std::string &) = 0;
    virtual int sysnum2parav(long, core::Parameters&) = 0;
};

class UtilsImpl : public Utils
{
private:
    std::shared_ptr<CustomPtrace> cp;
    const core::SystemcallParaTable & syscall_call_para_table;
    const std::map<long, std::string> & syscall_assist;
    std::map<std::string, long> syscall_assist_r;
public:
    UtilsImpl(std::shared_ptr<CustomPtrace> cp);
    virtual ~UtilsImpl(){};
    virtual int readStrFrom(int tid, const char *p, char *buf, size_t s);
    virtual int readBytesFrom(int tid, const char *p, char *buf, size_t s);
    virtual int getFilenameByFd(int tid, int fd, std::string &filename);
    virtual int getFilenamesByProc(int tid,std::set<std::string> &fileset) override;
    virtual int strset2file(const std::string &filename, const std::set<std::string> &fileset) override;
    virtual int handleEscape(const std::string &str, std::string &regStr) override;
    virtual int formatBytes(const std::vector<unsigned char> &vc, std::string &formattedBytes) override;
    virtual int formatBytes(const std::string &str, std::string &formattedBytes) override;
    virtual int sysname2num(const std::string &, long &) override;
    virtual int sysnum2str(long, std::string &) override;
    virtual int sysnum2parav(long, core::Parameters&) override;
};

} // namespace utils
} // namespace SAIL
