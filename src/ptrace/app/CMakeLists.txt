AUX_SOURCE_DIRECTORY(. DIR_SRCS)
AUX_SOURCE_DIRECTORY(.. DIR_SRCS)

ADD_EXECUTABLE(TobeCarried ${DIR_SRCS})

target_link_libraries(TobeCarried PRIVATE spdlog::spdlog)
target_link_libraries(TobeCarried PRIVATE yaml-cpp)
target_link_libraries(TobeCarried PRIVATE cxxopts)

configure_file(example.yml example.yml)
configure_file(start.sh start.sh)