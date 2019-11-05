PROJECT(ptrace)

#   file
#   file open
#   ./openkey.o filename
ADD_EXECUTABLE(openkey.o file/openkey.cpp)
#   file close
#   ./closekey.o filename
ADD_EXECUTABLE(closekey.o file/closekey.cpp)
#   file read
#   ./readkey.o filename
ADD_EXECUTABLE(readkey.o file/readkey.cpp)
#   file write
#   ./writekey.o filename filecontent
ADD_EXECUTABLE(writekey.o file/writekey.cpp)

#   network
#   network tcpcli
#   ./tcpcli localhost <port>
ADD_EXECUTABLE(tcpcli.o network/tcpcli.cpp)
#   network tcpsvr
#   ./tcpsvr <port>
ADD_EXECUTABLE(tcpsvr.o network/tcpsvr.cpp)
