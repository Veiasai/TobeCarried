#pragma once
#include <vector>

using namespace std;

class Tracee
{
private:
    int tid;
    bool iscalling;
public:
    Tracee(int tid);
    ~Tracee();
    void trap();
};
