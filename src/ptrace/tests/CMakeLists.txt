AUX_SOURCE_DIRECTORY(. DIR_SRCS)
AUX_SOURCE_DIRECTORY(.. DIR_SRCS)

ADD_EXECUTABLE(tbc_test ${DIR_SRCS})

target_link_libraries(tbc_test PRIVATE gtest)
target_link_libraries(tbc_test PRIVATE gmock)
target_link_libraries(tbc_test PRIVATE spdlog::spdlog)
target_link_libraries(tbc_test PRIVATE yaml-cpp)