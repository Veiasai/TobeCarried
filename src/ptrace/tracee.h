#pragma once
#include <sys/user.h>
#include <vector>

using namespace std;

struct Systemcall {
    struct user_regs_struct call_regs;
    struct user_regs_struct ret_regs;
    Systemcall() {};
};

struct WarnInfo {
    // a WarnInfo is related to one specific systemcall
    // callID is that systemcall's index in history
    int callID;

    // TODO: add explanation to this warning
    // e.g. vector<int> breakRules;  show the rules that be breaked;  
};

class Tracee
{
private:
    int tid;
    volatile bool iscalling;
    vector<Systemcall> history;
    vector<WarnInfo> report;
    // file
    void open();
    void read();
    void write();

    // net
    void connect();
    void recvfrom();
    void sendto();

    // clone
    void clone();

public:
    Tracee(int tid);
    ~Tracee();
    void trap();
};
