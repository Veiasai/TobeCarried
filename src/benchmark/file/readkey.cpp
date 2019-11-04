#include <string>
#include <stdio.h>
#include <fstream>
#include <iostream>

using namespace std;

void error(const string msg)
{
    perror(msg.c_str());
    exit(1);
}

//  read func check
//  filename
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        error("Please enter filename!\n");
    }
    
    string filename = argv[1];

    fstream fs;
    fs.open(filename.c_str(), ios::in);

    if (!fs.is_open())
    {
        fs.clear();
        return -1;
    }

    string content;
    fs >> content;

    cout << "file content: " << content << endl;

    fs.close();

    return 0;
}