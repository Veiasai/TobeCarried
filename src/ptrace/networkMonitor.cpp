#include "networkMonitor.h"

namespace SAIL
{
namespace rule
{

// TBC TODO:

NetworkMonitor::NetworkMonitor(const YAML::Node & config)
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
