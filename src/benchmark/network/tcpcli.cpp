#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>
using namespace std;

void error(const string msg)
{
    perror(msg.c_str());
    exit(1);
}

void send_msg(int &sockfd, const string message)
{
    int n = 0;
    int length = message.length();

    n = write(sockfd, (char *)&length, sizeof(length));
    if (n < 0)
    {
        error("Error: cannot send message length to server!\n");
    }

    n = write(sockfd, message.c_str(), length);
    if (n < 0)
    {
        error("Error: cannot send message to server!\n");
    }
}

void recv_msg(int &sockfd)
{
    int n = 0;
    // fisrt accept the length of message
    int length = 0;
    n = read(sockfd, (char *)&length, sizeof(length));
    cout << "MSG Length: " << length << endl;
    if (n < 0)
    {
        error("Error: cannot read message length from client!\n");
    }

    // receive message from client
    int buffer_length = length + 1;
    char *buffer = new char[buffer_length];
    bzero(buffer, buffer_length);
    int byte_read = 0;
    while (byte_read < length)
    {
        n = read(sockfd, buffer + byte_read, length - byte_read);
        if (n < 0)
        {
            error("Error: cannot read message from client!\n");
        }
        byte_read += n;
    }

    cout << "MSG: " << buffer << endl;
}

int main(int argc, char *argv[])
{
    int sockfd, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    // char buffer[256];

    if (argc < 3)
    {
        error("Error! Usage: cmd hostname port\n");
    }

    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error: cannot open socket!\n");
    }

    server = gethostbyname(argv[1]);
    if (server == NULL)
    {
        error("Error: cannot find the server!");
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("Error: cannot connect to server!\n");
    }

    cout << "Please enter the message: \n";
    string message = "";
    getline(cin, message);

    // send message
    cout << "sending message...\n";
    send_msg(sockfd, message);

    // receive message from server
    cout << "receiving message...\n";
    recv_msg(sockfd);
    cout << "******************************\n";

    close(sockfd);
    return 0;
}