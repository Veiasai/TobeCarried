#include "rule.h"

namespace SAIL { namespace rule {

RuleImpl::RuleImpl() {

};

RuleCheckMsg RuleImpl::check() {

};

RuleInfo RuleImpl::info() {
    
};

int RuleImpl::matchRe(bool iscalling, ParameterIndex idx, const std::string & re)
{

}

int RuleImpl::matchBytes(bool iscalling, ParameterIndex idx, const std::vector<char> & vc)
{

}

int RuleImpl::equal(ParameterIndex idx, long value)
{

}

int RuleImpl::greater(ParameterIndex idx, long value)
{

}

int RuleImpl::notGreater(ParameterIndex idx, long value)
{

}

}}