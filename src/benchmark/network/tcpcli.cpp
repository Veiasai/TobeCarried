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

void error(const string &msg)
{
    perror(msg.c_str());
    exit(1);
}

void send_msg(int &sockfd, const string &message)
{
    int length = message.length();
    write(sockfd, (char *)&length, sizeof(length));
    write(sockfd, message.c_str(), length);
}

void recv_msg(int &sockfd)
{
    // read buffer of 123 is like 3000313233 (03-00-00-00-31-32-33 actually),
    // first four byte is message length and content follows

    // fisrt accept the length of message
    int length = 0;
    int n = read(sockfd, (char *)&length, sizeof(length));
    cout << "message length: " << length << endl;

    // receive message from client
    char buffer[length + 1];
    bzero(buffer, length + 1);
    n = read(sockfd, buffer, length + 1);
    cout << "message content: " << buffer << endl;
}

// ./tcpsvr.o <port>
int main(int argc, char *argv[])
{
    if (argc < 3) {
        error("Error! Usage: cmd hostname port\n");
    }

    int port = atoi(argv[2]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("Error: cannot open socket!\n");
    }

    struct hostent *server = gethostbyname(argv[1]);
    if (!server) {
        error("Error: cannot find the server!");
    }

    struct sockaddr_in serv_addr;
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("Error: cannot connect to server!\n");
    }

    cout << "Please enter the message: \n";
    string message = "hello, world!";
    // getline(cin, message);

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