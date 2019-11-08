#include <sys/ptrace.h>
#include <iostream>
#include <memory>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "../tracer.h"
#include "../tracee.h"
#include "../utils.h"
#include "../ruleManager.h"

using namespace std;
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
    if (argc != 2) {
        cout << "please input the target file name and log level\n";
        return -1;
    }

    startChild(argv[1]);
    initLogger(argv[2]);
    YAML::Node config=YAML::LoadFile("yamls/try.yml");
    std::shared_ptr<SAIL::rule::YamlRuleManger> ymlmgr=std::make_shared<SAIL::rule::YamlRuleManger>(config);
    
    // std::shared_ptr<utils::CustomPtrace> cp = std::make_shared<utils::CustomPtraceImpl>();
    // std::shared_ptr<utils::Utils> up = std::make_shared<utils::UtilsImpl>(cp);

    // auto tracer = std::make_unique<core::Tracer>(up, cp);
    // tracer->run();

    return 0;
}
