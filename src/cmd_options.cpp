#include "cmd_options.h"
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        ("help,h", "produce help message")
        ("command,c", po::value<std::string>(), "command to execute: encrypt, decrypt, checksum")
        ("input,i", po::value<std::string>(), "input file")
        ("output,o", po::value<std::string>(),"output file")
        ("password,p", po::value<std::string>(), "password");

    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.contains("help")) {
        std::cout << desc_ << '\n';
        helpRequested_ = true;
        return;
    }

    if (!vm.contains("command")) {
        throw std::invalid_argument{"--command is required"};
    }
    const auto &command = vm["command"].as<std::string>();
    const auto it = commandMapping_.find(command);
    if (it == commandMapping_.end()) {
        throw std::invalid_argument{"Unknown command: " + command};
    }
    command_ = it->second;

    if (!vm.contains("input")) {
        throw std::invalid_argument{"--input is required"};
    }
    inputFile_ = vm["input"].as<std::string>();

    if (command_ != COMMAND_TYPE::CHECKSUM) {
        if (!vm.contains("output") || !vm.contains("password")) {
            throw std::invalid_argument{"--output and --password are required for encrypt/decrypt"};
        }
        outputFile_ = vm["output"].as<std::string>();
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
