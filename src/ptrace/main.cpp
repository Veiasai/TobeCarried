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

using namespace std;

int getFileName(pid_t child, unsigned long long addr, char * buffer, int len){
    for(int i=0;i<len;i++){
        long val = ptrace(PTRACE_PEEKDATA,child,addr+i*sizeof(long),NULL);
        char * c = (char *)&val;
        for (int j=0;j<8;j++){
            buffer[i*sizeof(long)+j] = c[j];
            if (c[j] == '\0'){
                return 0;
            }
        }
    }
    return -1;
}
int main(int argc,char **argv){

    if (argc != 2){
        printf("please input the target file name\n");
        return -1;
    }
    pid_t child;
    long orig_rax;
    int status;
    int iscalling=0;
    struct user_regs_struct regs;

    child = fork();
    if(child==0){
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
        while(1){
            wait(&status);
            if(WIFEXITED(status))
                break;
            orig_rax=ptrace(PTRACE_PEEKUSER,child,8*ORIG_RAX,NULL);

            if(orig_rax == SYS_open){
                ptrace(PTRACE_GETREGS,child,NULL,&regs);
                if(!iscalling){
                    iscalling =1;
                    char s[100];
                    if (getFileName(child, regs.rdi, s, 100) < 0){
                        printf("error\n");
                        continue;
                    };
                    printf("SYS_open call with %lld, %lld, %lld, %s\n",regs.rdi,regs.rsi,regs.rdx, s);
                } else{
                    printf("SYS_open call return %lld\n",regs.rax);
                    iscalling = 0;
                }                                  
            }
            ptrace(PTRACE_SYSCALL,child,NULL,NULL);
        }
    }
    return 0;
}