#include "utils.h"

namespace SAIL { namespace utils {

UtilsImpl::UtilsImpl(std::shared_ptr<CustomPtrace> _cp) : cp(_cp)
{

}

int UtilsImpl::readStrFrom(int tid, const char * p, char * buf, size_t s)
{
    for (int i = 0; i < s; i += sizeof(long)) {
        long val = this->cp->peekData(tid, (long)p + i * sizeof(long));
        char * c = (char *)&val;
        for (int j = 0; j < 8; j++) {
            buf[i + j] = c[j];
            if (c[j] == '\0') {
                return 0;
            }
        }
    }
    return -1;
}

int UtilsImpl::readBytesFrom(int tid, const char * p, char * buf, size_t s)
{
    size_t count = 0;
    while (s - count > 8) {
        *(long *)(buf + count) = this->cp->peekData(tid, (long)p + count);
        count += 8;
    }

    if (s - count > 0) {
        long data = this->cp->peekData(tid, (long)p + count);
        char * bdata = (char *)&data;
        for (int i = 0; count + i < s; i++) {
            buf[count + i] = bdata[i];
        }
    }
    return 0;
}

int UtilsImpl::getFilenameByFd(int tid, int fd, std::string &filename)
{
    std::string command = "lsof -p " + std::to_string(tid) + " | awk '{print $4, $9}' > tmpforfd";
    int r = system(command.c_str());
    if (r != 0) {
        spdlog::error("[tid: {}] [getFilenameByFd] lsof error", tid);
        return -1;
    }
    std::fstream fs;
    fs.open("tmpforfd", std::fstream::in);
    while (!fs.eof()) {
        std::string _fd;
        std::string _name;
        fs >> _fd >> _name;
        if (_fd.substr(0, _fd.length() - 1) == std::to_string(fd)) {
            // frop r/w mode char
            filename = _name;
            fs.close();
            return 0;
        }
    }
    // don't find fd required
    spdlog::error("[tid: {}] [getFilenameByFd] fd doesn't exist", tid);
    return -1;
}

long CustomPtraceImpl::peekUser(int tid, long addr)
{
    return ptrace(PTRACE_PEEKUSER, tid, addr, NULL);
}

long CustomPtraceImpl::getRegs(int tid, user_regs_struct * regs)
{
    return ptrace(PTRACE_GETREGS, tid, NULL, regs);
}

long CustomPtraceImpl::peekData(int tid, long addr)
{
    return ptrace(PTRACE_PEEKDATA, tid, addr, NULL);
}

long CustomPtraceImpl::attach(int tid)
{
    return ptrace(PTRACE_ATTACH, tid, NULL, NULL);
}

}}