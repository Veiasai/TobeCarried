AUX_SOURCE_DIRECTORY(. DIR_SRCS)
AUX_SOURCE_DIRECTORY(.. DIR_SRCS)

ADD_EXECUTABLE(ptrace_test ${DIR_SRCS})

target_link_libraries(ptrace_test PRIVATE gtest)
target_link_libraries(ptrace_test PRIVATE gmock)
target_link_libraries(ptrace_test PRIVATE spdlog::spdlog)
target_link_libraries(ptrace_test PRIVATE yaml-cpp)