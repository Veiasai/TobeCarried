#include <sys/ptrace.h>
#include <sys/wait.h>
#include <iostream>
#include <memory>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cxxopts.hpp>
#include <exception>
#include <stdexcept>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "../tracer.h"
#include "../tracee.h"
#include "../utils.h"
#include "../ruleManager.h"
#include "../report.h"

using namespace SAIL;

void initLogger(const std::string & logLevel, const std::string & logFile) {
    spdlog::set_default_logger(spdlog::basic_logger_mt("ToBeCarried", logFile));
    if (logLevel == "info"){
        spdlog::set_level(spdlog::level::info);
        spdlog::default_logger()->flush_on(spdlog::level::err);
    }else if (logLevel == "debug"){
        spdlog::set_level(spdlog::level::debug);
        spdlog::default_logger()->flush_on(spdlog::level::debug);
    }
    else if (logLevel == "error"){
        spdlog::set_level(spdlog::level::err);
        spdlog::default_logger()->flush_on(spdlog::level::err);
    }else{
        throw std::logic_error("logLevel is invalid, it must be one of 'info,debug,error'");
    }
}

void startChild(const std::string & target, const std::vector<std::string> & args, const std::string & childLog) {
    spdlog::debug("start child {}, output path {}", target, childLog);

    __pid_t child = fork();
    if (child == 0) {
        std::vector<char *> cargs;
        cargs.push_back(const_cast<char *>(target.c_str()));
        for (auto & s : args){
            spdlog::debug("start child arg: {}", s);
            cargs.push_back(const_cast<char *>(s.c_str()));
        }
        cargs.push_back(nullptr);
        char ** command = &cargs[0];
        int childLogFd = open(childLog.c_str(), O_CREAT | O_APPEND, 0666);
        assert(childLogFd > 0);
        dup2(childLogFd, 1);
        dup2(childLogFd, 2);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(target.c_str(), command);
        assert(0);
    }
    wait(NULL);
    spdlog::debug("start child ret: {}", child);
    long ptraceOption = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK;
	ptrace(PTRACE_SETOPTIONS, child, NULL, ptraceOption);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
}

int main(int argc,char **argv){
    cxxopts::Options options("ToBeCarried", "Trace the systemcall used by a process.");
    options.add_options()
    ("l,loglevel", "Log Level: info, debug, error", cxxopts::value<std::string>())
    ("o,logfile", "log file path",  cxxopts::value<std::string>())
    ("f,file", "the file you want to check", cxxopts::value<std::string>())
    ("d,childlog", "target output file path", cxxopts::value<std::string>())
    ("c,config", "config file path", cxxopts::value<std::string>())
    ("a,args", "pass args to child, format like --a=a1,a2,a3", cxxopts::value<std::vector<std::string>>())
    ("r,report", "report file path", cxxopts::value<std::string>())
    ;
    try {
        auto result = options.parse(argc, argv);

        initLogger(result["l"].as<std::string>(), result["o"].as<std::string>());
        startChild(result["f"].as<std::string>(), result["a"].as<std::vector<std::string>>(), result["d"].as<std::string>());

        YAML::Node config = YAML::LoadFile(result["c"].as<std::string>());

        std::shared_ptr<utils::CustomPtrace> cp = std::make_shared<utils::CustomPtraceImpl>();
        std::shared_ptr<utils::Utils> up = std::make_shared<utils::UtilsImpl>(cp);
        std::shared_ptr<rule::RuleManager> ymlmgr=std::make_shared<SAIL::rule::YamlRuleManager>(config);
        std::shared_ptr<core::Report> report = std::make_shared<core::ReportImpl>(result["r"].as<std::string>());
        
        std::unique_ptr<core::Tracer> tracer = std::make_unique<core::Tracer>(up, cp, ymlmgr, report);
        tracer->run();
    } catch (std::exception & e){
        std::cout << options.help() << std::endl;
        std::cout << e.what() << std::endl;
        return -1;
    }

    return 0;
}
