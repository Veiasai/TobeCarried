#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <iostream>
#include <stdio.h>
#include <fcntl.h>
#include <set>
#include <map>

using namespace std;

int main(int argc,char **argv){
    if (argc != 2){
        printf("please input the target file name\n");
        return -1;
    }

    pid_t child;
    long orig_rax;
    int status;
    struct user_regs_struct regs;
    map<int, set<int>> syscall;  // map of <tid, set<syscall>>
    map<int, int> iscalling;  // map of <tid, iscalling>

    child = fork();
    if (child == 0) {
        int childLogFd = open("childLog", O_CREAT | O_RDWR | O_APPEND, 0x666);
        if (childLogFd < 0){
            printf("fail to open childlog\n");
            return -1;
        }
        dup2(childLogFd, 1);
        dup2(childLogFd, 2);
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execvp(argv[1], NULL);
    } else {
        while(1) {
            int tid_return = wait(&status);
            if(WIFEXITED(status))
                break;
            orig_rax = ptrace(PTRACE_PEEKUSER, tid_return, 8*ORIG_RAX, NULL);

            // print
            if (syscall[tid_return].find(orig_rax) == syscall[tid_return].end()) {
                syscall[tid_return].insert(orig_rax);
                printf("\nSYSCALL\n");
                for (auto it = syscall.begin(); it != syscall.end(); it++) {
                    printf("  # %d: ", it->first);
                    for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
                        printf("\t%d", *it2);
                    }
                    printf("\n");
                }
            }
            
            // detect syscall: clone
            if (orig_rax == SYS_clone) {
                ptrace(PTRACE_GETREGS, tid_return, NULL, &regs);
                if (iscalling[tid_return] != 1) {
                    iscalling[tid_return] = 1;
                    printf("SYS_clone call start in tid %d\n", tid_return);
                } else {
                    iscalling[tid_return] = 0;
                    if (regs.rax != 0) {
                        // return in parent thread (return value in child thread is 0)
                        ptrace(PTRACE_ATTACH, regs.rax, NULL, NULL);
                        iscalling[regs.rax] = 1;
                    }
                    printf("SYS_clone call return %lld in tid %d\n", regs.rax, tid_return);
                }                                  
            }

            // wake up child process
            ptrace(PTRACE_SYSCALL, tid_return, NULL, NULL);
        }
    }
    return 0;
}