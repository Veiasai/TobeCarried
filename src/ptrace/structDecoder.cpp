#include <sys/socket.h>
#include <arpa/inet.h>
#include "spdlog/spdlog.h"

#include "structDecoder.h"
#include "parameter.h"

namespace
{
#include <sys/syscall.h>
} // namespace

namespace SAIL
{
namespace rule
{

// TBC TODO:

StructDecoder::StructDecoder(const YAML::Node &config,
                             std::shared_ptr<utils::Utils> up,
                             std::shared_ptr<core::Report> report)
    : up(up), report(report)
{
}

void StructDecoder::beforeTrap(long tid,
                               const core::Histories &history,
                               core::RuleCheckMsgs &ruleCheckMsgs)
{
}

void StructDecoder::afterTrap(long tid,
                              const core::Histories &history,
                              core::RuleCheckMsgs &ruleCheckMsgs)
{
    if (history.back().first.call_regs.orig_rax == SYS_uname)
    {
        spdlog::debug("StructDecoder: catch uname");

        const struct utsname *un =
            reinterpret_cast<struct utsname *>(
                history.back().second[core::ParameterIndex::First].value);
        spdlog::debug("StructDecoder: sysname: {}, nodename: {}, release: {}, version: {}, machine: {}", un->sysname, un->nodename, un->release, un->version, un->machine);
    }
    else if (history.back().first.call_regs.orig_rax == SYS_ioctl)
    {
        spdlog::debug("StructDecoder: catch ioctl");

        const long ioctlCmd = history.back().second[core::ParameterIndex::Second].value;
        if (ioctlCmd == SIOCGIFCONF)
            spdlog::debug("StructDecoder: request: SIOCGIFCONF");
        else if (ioctlCmd == SIOCSIFADDR)
            spdlog::debug("StructDecoder: request: SIOCSIFADDR");
    }
}

void StructDecoder::event(long tid, int status)
{
}

void StructDecoder::end()
{
}

} // namespace rule
} // namespace SAIL
