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
//  filename filecontent
int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        error("Please enter filename and content!\n");
    }

    string filename = argv[1];

    fstream fs;
    cout << filename << endl;

    fs.open(filename.c_str(), ios::app);

    if (!fs.is_open())
    {
        cerr << "Error open!" << endl;
        fs.clear();
        return -1;
    }

    string filecontent = argv[2];

    fs << filecontent;

    fs.seekp(0, fs.end);
    size_t filesize = fs.tellp();

    cout << "file size: " << filesize << endl;

    fs.close();

    return 0;
}