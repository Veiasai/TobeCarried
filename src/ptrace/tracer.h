#pragma once
#include <map>
#include <set>
#include <memory>
#include "tracee.h"

class Tracer
{
private:
    map<int, std::unique_ptr<Tracee>> tracees;
    /* data */
public:
    Tracer(/* args */);
    ~Tracer();
    void run();
};
