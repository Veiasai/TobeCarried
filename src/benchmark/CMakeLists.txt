PROJECT(benchmark)

configure_file(scripts/main.py main.py)
configure_file(scripts/default_config.yaml default_config.yaml)
configure_file(scripts/whitelist.yml whitelist.yml)

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
#   network netlink
#   ./netlink
ADD_EXECUTABLE(netlink network/netlink.cpp)

#   clone
#   clone
#   ./clone
ADD_EXECUTABLE(clone clone/clone.cpp)
