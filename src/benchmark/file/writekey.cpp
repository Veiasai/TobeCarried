#include <string>
#include <fstream>
#include <iostream>

using namespace std;

//  open func check
//  filename filecontent
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        cerr << "Please enter filename!" << endl;
        return -1;
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