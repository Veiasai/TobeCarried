#include <string>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[])
{
    char *cmd[] = {"sudo", "uname", "-r", (char *)0};
    execv("/bin/bash", cmd);

    return 0;
}