AUX_SOURCE_DIRECTORY(. DIR_SRCS)
AUX_SOURCE_DIRECTORY(.. DIR_SRCS)

ADD_EXECUTABLE(ptrace ${DIR_SRCS})

target_link_libraries(ptrace PRIVATE spdlog::spdlog)
target_link_libraries(ptrace PRIVATE yaml-cpp)

configure_file(example.yml example.yml)