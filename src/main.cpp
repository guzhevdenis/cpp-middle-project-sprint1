#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

namespace {

std::fstream OpenInputFile(const std::string &path) {
    std::fstream file{path, std::ios::in | std::ios::binary};
    if (!file.is_open()) {
        throw std::runtime_error{"Failed to open input file: " + path};
    }
    return file;
}

std::fstream OpenOutputFile(const std::string &path) {
    std::fstream file{path, std::ios::out | std::ios::binary | std::ios::trunc};
    if (!file.is_open()) {
        throw std::runtime_error{"Failed to open output file: " + path};
    }
    return file;
}

// При ошибке удаляет недописанный выходной файл, чтобы не оставлять на диске мусор
template <typename Operation>
void ProcessFiles(const CryptoGuard::ProgramOptions &options, Operation operation) {
    auto in = OpenInputFile(options.GetInputFile());
    auto out = OpenOutputFile(options.GetOutputFile());
    try {
        operation(in, out);
        out.close();
        if (out.fail()) {
            throw std::runtime_error{"Failed to write output file: " + options.GetOutputFile()};
        }
    } catch (...) {
        out.close();
        std::error_code ec;
        std::filesystem::remove(options.GetOutputFile(), ec);
        throw;
    }
}

}  // namespace

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.IsHelpRequested()) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            ProcessFiles(options, [&](std::fstream &in, std::fstream &out) {
                cryptoCtx.EncryptFile(in, out, options.GetPassword());
            });
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            ProcessFiles(options, [&](std::fstream &in, std::fstream &out) {
                cryptoCtx.DecryptFile(in, out, options.GetPassword());
            });
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM: {
            auto in = OpenInputFile(options.GetInputFile());
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(in));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
