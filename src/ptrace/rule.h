#pragma once

#include <string>

namespace SAIL { namespace rule {

struct RuleCheckMsg
{
    bool approval;
    std::string msg;
};

enum RuleLevel
{
    record,
    standard,
    dangerous,
};

struct RuleInfo
{
    int target_syscall;
    std::string name;
    RuleLevel level;
};

enum ParameterIndex
{
    First,
    Second,
    Third,
    Fourth,
    Fifth,
    Sixth,
};

class Rule
{
public:
    virtual ~Rule() {};
    virtual RuleCheckMsg check() = 0;
    virtual RuleInfo info() = 0;
    virtual int matchRe(bool iscalling, ParameterIndex idx, const std::string & re) = 0; // usually should be a pointer
    virtual int matchBytes(bool iscalling, ParameterIndex idx, const std::vector<char> & vc) = 0; // usually should be a pointer
    virtual int equal(ParameterIndex idx, long value) = 0;
    virtual int greater(ParameterIndex idx, long value) = 0;
    virtual int notGreater(ParameterIndex idx, long value) = 0;
};

class RuleImpl
{
private:
    // TODO
public:
    RuleImpl();
    virtual ~RuleImpl() {};
    virtual RuleCheckMsg check();
    virtual RuleInfo info();
    virtual int matchRe(bool iscalling, ParameterIndex idx, const std::string & re); // usually should be a pointer
    virtual int matchBytes(bool iscalling, ParameterIndex idx, const std::vector<char> & vc); // usually should be a pointer
    virtual int equal(ParameterIndex idx, long value);
    virtual int greater(ParameterIndex idx, long value);
    virtual int notGreater(ParameterIndex idx, long value);
};

}}