#include <string>
#include <fstream>
#include <iostream>

using namespace std;

//  read func check
//  filename
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        cerr << "Please enter filename!" << endl;
        return -1;
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