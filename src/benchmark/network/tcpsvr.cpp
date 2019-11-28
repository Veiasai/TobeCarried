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
    int length = message.length();
    // write length
    write(sockfd, (char *)&length, sizeof(length));
    // write content
    write(sockfd, message.c_str(), length);
}

void recv_msg(int &sockfd)
{
    // read buffer of 123 is like 3000313233 (03-00-00-00-31-32-33 actually),
    // first four byte is message length and content follows

    // fisrt accept the length of message
    int length = 0;
    read(sockfd, (char *)&length, sizeof(length));
    cout << "message length: " << length << endl;

    // receive message from client
    char buffer[length + 1];
    bzero(buffer, length + 1);
    read(sockfd, buffer, length + 1);
    cout << "message content: " << buffer << endl;
}

// ./tcpcli.o localhost <port>
int main(int argc, char *argv[])
{
    if (argc < 2) {
        error("Error: no port provided!\n");
    }

    // build socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("Error: cannot open socket!\n");
    }

    // fill sockaddr_in
    struct sockaddr_in serv_addr;
    bzero((char *)&serv_addr, sizeof(serv_addr));
    int port = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("Error: binding error!\n");
    }

    listen(sockfd, 5); // backlog = 5, defines the maximum length to which the queue of pending connections for sockfd may grow
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    while (1) {
        int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            error("Error: cannot accept!\n");
        }

        // recieve message
        cout << "receiving message...\n";
        recv_msg(newsockfd);
        cout << "******************************\n";

        // send message to client
        cout << "sending message...\n";
        send_msg(newsockfd, "ACK");
        close(newsockfd);
    }

    close(sockfd);
    return 0;
}