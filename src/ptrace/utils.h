#pragma once

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <memory>

namespace SAIL { namespace utils {

class CustomPtrace
{
public:
    virtual ~CustomPtrace() {};
    virtual long peekUser(int tid, long addr) = 0;
    virtual long getRegs(int tid, user_regs_struct * regs) = 0;
    virtual long peekData(int tid, long addr) = 0;
    virtual long attach(int tid) = 0;
};

class CustomPtraceImpl : public CustomPtrace
{
public:
    virtual ~CustomPtraceImpl() {};
    virtual long peekUser(int tid, long addr);
    virtual long getRegs(int tid, user_regs_struct * regs);
    virtual long peekData(int tid, long addr);
    virtual long attach(int tid);
};

class Utils
{
public:
    virtual ~Utils() {};
    virtual int readStrFrom(int tid, const char * p, char * buf, size_t s) = 0;
    virtual int readBytesFrom(int tid, const char * p, char * buf, size_t s) = 0;
};

class UtilsImpl : public Utils
{
private:
    std::shared_ptr<CustomPtrace> cp;
public:
    UtilsImpl(std::shared_ptr<CustomPtrace> cp);
    virtual ~UtilsImpl() {};
    virtual int readStrFrom(int tid, const char * p, char * buf, size_t s);
    virtual int readBytesFrom(int tid, const char * p, char * buf, size_t s);
};
    
}}
