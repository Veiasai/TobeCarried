#include <gtest/gtest.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

int main(int argc, char **argv) {
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_default_logger(spdlog::basic_logger_mt("test_logger", "logs/test.txt"));
    ::testing::InitGoogleTest(&argc, argv); 
    return RUN_ALL_TESTS();
}