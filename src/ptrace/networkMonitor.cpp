#include "networkMonitor.h"

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

}

void NetworkMonitor::event(long tid, int status)
{

}

void NetworkMonitor::end()
{

}


} // namespace core
} // namespace SAIL
