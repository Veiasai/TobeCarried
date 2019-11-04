#include <string>
#include <fstream>
#include <iostream>

using namespace std;

//  open func check
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
    cout << "filename: " << filename << endl;

    fs.open(filename.c_str(), ios::app);

    if (!fs.is_open())
    {
        cerr << "Error open!" << endl;
        fs.clear();
        return -1;
    }

    fs.close();
    if (fs.is_open())
    {
        cerr << "Error close!"<<endl;
    }

    return 0;
}