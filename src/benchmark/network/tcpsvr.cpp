#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
using namespace std;

void error(const string &msg)
{
    perror(msg.c_str());
    exit(1);
}

void send_msg(int &sockfd, const string &message)
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
    if (n == -1 || n != sizeof(length))
    {
        error("Read error!");
    }

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
        if (n == -1 || n != sizeof(length))
        {
            error("Read error!");
        }

        if (n < 0)
        {
            error("Error: cannot read message from client!\n");
        }
        byte_read += n;
    }

    cout << "MSG: " << buffer << endl;
}

// ./tcpcli.o localhost <port>
int main(int argc, char *argv[])
{
    int sockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    if (argc < 2)
    {
        error("Error: no port provided!\n");
    }

    // build socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error: cannot open socket!\n");
    }

    // fill sockaddr_in
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("Error: binding error!\n");
    }

    listen(sockfd, 5); // backlog = 5, defines the maximum length to which the queue of pending connections for sockfd may grow
    clilen = sizeof(cli_addr);
    while (1)
    {
        int newsockfd;
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0)
        {
            error("Error: cannot accept!\n");
        }

        // recieve message
        cout << "receiving message...\n";
        recv_msg(newsockfd);
        cout << "******************************\n";

        // send message to client
        cout << "sending message...\n";
        send_msg(newsockfd, "Successfully received!");
        close(newsockfd);
    }

    close(sockfd);
    return 0;
}