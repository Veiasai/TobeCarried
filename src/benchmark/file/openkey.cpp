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

//  open func check
//  filename
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        error("Please enter filename!\n");
    }

    string filename = argv[1];

    fstream fs;
    cout << "filename: " << filename << endl;

    fs.open(filename.c_str(), ios::app);

    if (!fs.is_open())
    {
        cerr << "Error open!" << endl;
        fs.clear();
        return -1;
    }

    return 0;
}