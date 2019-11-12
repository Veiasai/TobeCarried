#include <sys/ptrace.h>
#include <iostream>
#include <memory>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cxxopts.hpp>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "../tracer.h"
#include "../tracee.h"
#include "../utils.h"
#include "../ruleManager.h"

using namespace SAIL;

void initLogger(const char * logLevel) {
    // TODO
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_default_logger(spdlog::basic_logger_mt("default_logger", "logs/basic.txt"));
}

void startChild(const char * target) {
    __pid_t child = fork();
    if (child == 0) {
        int childLogFd = open("/dev/null", O_WRONLY);
        dup2(childLogFd, 1);
        dup2(childLogFd, 2);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(target, NULL);
    }
}

int main(int argc,char **argv){
    cxxopts::Options options("ToBeCarried", "Trace the systemcall used by a process.");
    options.add_options()
    ("l,loglevel", "Log Level: Info, Debug", cxxopts::value<std::string>())
    ("f,file", "the file you want to check", cxxopts::value<std::string>())
    ("c,config", "config file path", cxxopts::value<std::string>())
    ;
    try {
        auto result = options.parse(argc, argv);

        initLogger(result["l"].as<std::string>().c_str());
        startChild(result["f"].as<std::string>().c_str());

        YAML::Node config = YAML::LoadFile(result["c"].as<std::string>());

        std::shared_ptr<SAIL::rule::RuleManager> ymlmgr=std::make_shared<SAIL::rule::YamlRuleManager>(config);
        (void) ymlmgr;

        std::shared_ptr<utils::CustomPtrace> cp = std::make_shared<utils::CustomPtraceImpl>();
        std::shared_ptr<utils::Utils> up = std::make_shared<utils::UtilsImpl>(cp);

        auto tracer = std::make_unique<core::Tracer>(up, cp);
        tracer->run();
    } catch (std::exception & e){
        std::cout << e.what() << std::endl;
        return 0;
    }

    return 0;
}
