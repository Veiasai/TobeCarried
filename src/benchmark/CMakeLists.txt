PROJECT(ptrace)

configure_file(scripts/main.py scripts/main.py)
#   file
#   file open
#   ./openkey.o filename
ADD_EXECUTABLE(openkey file/openkey.cpp)
#   file close
#   ./closekey.o filename
ADD_EXECUTABLE(closekey file/closekey.cpp)
#   file read
#   ./readkey.o filename
ADD_EXECUTABLE(readkey file/readkey.cpp)
#   file write
#   ./writekey.o filename filecontent
ADD_EXECUTABLE(writekey file/writekey.cpp)

#   network
#   network tcpcli
#   ./tcpcli localhost <port>
ADD_EXECUTABLE(tcpcli network/tcpcli.cpp)
#   network tcpsvr
#   ./tcpsvr <port>
ADD_EXECUTABLE(tcpsvr network/tcpsvr.cpp)
