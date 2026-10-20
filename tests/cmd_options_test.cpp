#include "cmd_options.h"
#include <gtest/gtest.h>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace po = boost::program_options;
using CryptoGuard::ProgramOptions;
using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;

// Parse() принимает char *argv[], поэтому храним строки и массив указателей на них
struct Args {
    std::vector<std::string> storage;
    std::vector<char *> argv;

    Args(std::initializer_list<std::string> list) : storage(list) {
        for (auto &s : storage) {
            argv.push_back(s.data());
        }
    }

    // при копировании argv указывал бы на строки исходного объекта
    Args(const Args &) = delete;
    Args &operator=(const Args &) = delete;

    int argc() const { return static_cast<int>(argv.size()); }
};

void Parse(ProgramOptions &options, Args args) { options.Parse(args.argc(), args.argv.data()); }

}  // namespace

TEST(ProgramOptions, EncryptWithLongOptions) {
    ProgramOptions options;
    Parse(options, {"CryptoGuard", "--command", "encrypt", "--input", "in.txt", "--output", "out.txt", "--password",
                    "1234"});

    EXPECT_FALSE(options.IsHelpRequested());
    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

TEST(ProgramOptions, DecryptWithShortOptions) {
    ProgramOptions options;
    Parse(options, {"CryptoGuard", "-c", "decrypt", "-i", "in.txt", "-o", "out.txt", "-p", "1234"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

TEST(ProgramOptions, ChecksumRequiresOnlyInput) {
    ProgramOptions options;
    EXPECT_NO_THROW(Parse(options, {"CryptoGuard", "-c", "checksum", "-i", "in.txt"}));

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, HelpWithoutOtherOptions) {
    ProgramOptions options;
    EXPECT_NO_THROW(Parse(options, {"CryptoGuard", "--help"}));

    EXPECT_TRUE(options.IsHelpRequested());
}

TEST(ProgramOptions, MissingCommandThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-i", "in.txt"}), std::invalid_argument);
}

TEST(ProgramOptions, UnknownCommandThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-c", "foo", "-i", "in.txt"}), std::invalid_argument);
}

TEST(ProgramOptions, MissingInputThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-c", "checksum"}), std::invalid_argument);
}

TEST(ProgramOptions, EncryptWithoutPasswordThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-c", "encrypt", "-i", "in.txt", "-o", "out.txt"}),
                 std::invalid_argument);
}

TEST(ProgramOptions, DecryptWithoutOutputThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-c", "decrypt", "-i", "in.txt", "-p", "1234"}),
                 std::invalid_argument);
}

TEST(ProgramOptions, UnknownOptionThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "--bad"}), po::unknown_option);
}

TEST(ProgramOptions, OptionWithoutValueThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-c", "encrypt", "-i"}), po::invalid_command_line_syntax);
}

TEST(ProgramOptions, DuplicateOptionThrows) {
    ProgramOptions options;
    EXPECT_THROW(Parse(options, {"CryptoGuard", "-c", "checksum", "-i", "a.txt", "-i", "b.txt"}),
                 po::multiple_occurrences);
}
