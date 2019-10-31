#include <string>
#include <fstream>
#include <iostream>

int main()
{
    std::string filename = "test.txt";

    std::fstream fs;

    fs.open(filename);

    if(!fs.is_open())
    {
       fs.clear();
       return -1;
    }
    char s[100];
    fs.read(s, 128);
    return 0;
}