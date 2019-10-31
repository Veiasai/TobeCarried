#include "utils.h"
#include <sys/ptrace.h>

int readStrFrom(int tid, const char * p, char * buf, size_t s)
{
    for(int i=0;i<s;i++){
        long val = ptrace(PTRACE_PEEKDATA, tid, p+i*sizeof(long), NULL);
        char * c = (char *)&val;
        for (int j=0; j<8; j++){
            buf[i*sizeof(long)+j] = c[j];
            if (c[j] == '\0'){
                return 0;
            }
        }
    }
    return -1;
}

int readBytesFrom(int tid, const char * p, char * buf, size_t s)
{
    size_t count = 0;
    while(s - count > 8){
        *(long *)(buf + count) = ptrace(PTRACE_PEEKDATA, tid, p+count, NULL);
        count += 8;
    }

    if(s - count > 0){
        long data = ptrace(PTRACE_PEEKDATA, tid, p+count, NULL);
        char * bdata = (char *)&data;
        for (int i=0; count+i<s; i++){
            buf[count+i] = bdata[i];
        }
        
    }
    return 0;
}