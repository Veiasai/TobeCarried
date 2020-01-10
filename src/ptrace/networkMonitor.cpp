#include <sys/socket.h>
#include <arpa/inet.h>
#include "spdlog/spdlog.h"

#include "networkMonitor.h"
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

NetworkMonitor::NetworkMonitor(const YAML::Node & config,
    std::shared_ptr<utils::Utils> up,
    std::shared_ptr<core::Report> report)
    : up(up), report(report)
{
    for (const auto & ipStr : config["ipv4"].as<std::vector<std::string>>())
    {
        int ipv4 = 0;
        int err = inet_pton(AF_INET, ipStr.c_str(), &(ipv4));
        spdlog::debug("NetworkMonitor: ipv4WhiteList {} -> {}", ipStr, ipv4);

        if (err < 0)
        {
            throw std::logic_error("NetworkMonitor plugin: Invalid ipv4 address");
        }
        this->ipv4WhiteList.insert(ipv4);
    }
}

void NetworkMonitor::beforeTrap(long tid, 
    const core::Histories & history, 
    core::RuleCheckMsgs & ruleCheckMsgs)
{
    
}

void NetworkMonitor::afterTrap(long tid, 
    const core::Histories & history, 
    core::RuleCheckMsgs & ruleCheckMsgs)
{
    if (history.back().first.call_regs.orig_rax == SYS_connect)
    {
        spdlog::debug("NetworkMonitor: catch connect");

        const struct sockaddr * sa = 
            reinterpret_cast<struct sockaddr *>(
                history.back().second[core::ParameterIndex::Second].value);
        if (sa->sa_family == AF_INET)
        {
            const struct sockaddr_in * sa_in = reinterpret_cast<const struct sockaddr_in *>(sa);
            spdlog::debug("NetworkMonitor: catch connect {}", sa_in->sin_addr.s_addr);
            this->ipv4Used.insert(sa_in->sin_addr.s_addr);
        }
    }
}

void NetworkMonitor::event(long tid, int status)
{

}

void NetworkMonitor::end()
{
    this->checkIPV4();
}

void NetworkMonitor::checkIPV4()
{
    this->report->write(0, "");
    this->report->write(0, "NetworkMonitor Check");
    char addrBuf[20];
    for (const auto ipv4 : ipv4Used)
    {
        if (ipv4WhiteList.find(ipv4) == ipv4WhiteList.end())
        {
            inet_ntop(AF_INET, &(ipv4), addrBuf, INET_ADDRSTRLEN);
            this->report->write(0, "Not permitted ipv4: " + std::string(addrBuf));
        }
    }
    this->report->write(0, "NetworkMonitor Check End");
}


} // namespace core
} // namespace SAIL
