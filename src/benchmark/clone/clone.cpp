#include <string>
#include <stdlib.h> 
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

using namespace std;

static int child_func(void* arg) {
  char* buf = (char*)arg;
  printf("Child sees buf = \"%s\"\n", buf);
  strcpy(buf, "hello from child");
  printf("Child  = \"%x\"\n", buf);
  printf("Child updates buf = \"%s\"\n", buf);
  fstream fs;
	fs.open("testFile", ios::in);

	if (!fs.is_open())
	{
			fs.clear();
			return -1;
	}

	string content;
	fs >> content;

	cout << "file content: " << content << endl;
  return 0;
}

int main(int argc, char** argv) {
  // Allocate stack for child task.
  const int STACK_SIZE = 65536;
  char* stack = (char *)malloc(STACK_SIZE);
  if (!stack) {
    perror("malloc");
    exit(1);
  }

  char buf[100];
  strcpy(buf, "hello from parent");
  if (clone(child_func, stack + STACK_SIZE, CLONE_VM | SIGCHLD, buf) == -1) {
    perror("clone");
    exit(1);
  }

  int status;
  if (wait(&status) == -1) {
    perror("wait");
    exit(1);
  }

  printf("Parent  = \"%x\"\n", buf);
  printf("Child exited with status %d. buf = \"%s\"\n", status, buf);
  return 0;
}