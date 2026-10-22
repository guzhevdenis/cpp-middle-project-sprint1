#include "crypto_guard_ctx.h"
#include <format>
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using CryptoGuard::CryptoGuardCtx;

std::string Encrypt(const std::string &data, std::string_view password) {
    std::stringstream in{data};
    std::stringstream out;
    CryptoGuardCtx ctx;
    ctx.EncryptFile(in, out, password);
    return out.str();
}

std::string Decrypt(const std::string &data, std::string_view password) {
    std::stringstream in{data};
    std::stringstream out;
    CryptoGuardCtx ctx;
    ctx.DecryptFile(in, out, password);
    return out.str();
}

std::string ToHex(const std::string &data) {
    std::string hex;
    for (unsigned char c : data) {
        hex += std::format("{:02x}", c);
    }
    return hex;
}

std::string FromHex(std::string_view hex) {
    std::string data;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        data.push_back(static_cast<char>(std::stoi(std::string{hex.substr(i, 2)}, nullptr, 16)));
    }
    return data;
}

// Шифротекст "Hello OpenSSL crypto world!" с паролем "1234", полученный утилитой openssl
constexpr std::string_view REFERENCE_CIPHER_HEX = "9b636bafae1e135b77da3843a723e1e64b8af3c3511c116e8eccd79c0159276d";

}  // namespace

TEST(CryptoGuardCtx, EncryptMatchesOpenSSL) {
    // Эталон получен утилитой openssl с тем же ключом и IV:
    // openssl enc -aes-256-cbc -md sha256 -S 3132333435363738 -pass pass:1234 -P
    EXPECT_EQ(ToHex(Encrypt("Hello OpenSSL crypto world!", "1234")), REFERENCE_CIPHER_HEX);
}

TEST(CryptoGuardCtx, EncryptAddsPadding) {
    // AES-CBC дополняет данные до кратного 16 байтам, полный блок дополняется ещё одним
    EXPECT_EQ(Encrypt("", "1234").size(), 16u);
    EXPECT_EQ(Encrypt(std::string(15, 'a'), "1234").size(), 16u);
    EXPECT_EQ(Encrypt(std::string(16, 'a'), "1234").size(), 32u);
    EXPECT_EQ(Encrypt(std::string(5000, 'a'), "1234").size(), 5008u);
}

TEST(CryptoGuardCtx, EncryptDependsOnPassword) {
    const std::string data = "Hello OpenSSL crypto world!";

    EXPECT_NE(Encrypt(data, "1234"), data);
    EXPECT_EQ(Encrypt(data, "1234"), Encrypt(data, "1234"));
    EXPECT_NE(Encrypt(data, "1234"), Encrypt(data, "4321"));
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadInputStream) {
    std::stringstream in{"data"};
    std::stringstream out;
    in.setstate(std::ios::failbit);

    CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(in, out, "1234"), std::runtime_error);
    EXPECT_TRUE(out.str().empty());
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadOutputStream) {
    std::stringstream in{"data"};
    std::stringstream out;
    out.setstate(std::ios::badbit);

    CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(in, out, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptMatchesOpenSSL) {
    EXPECT_EQ(Decrypt(FromHex(REFERENCE_CIPHER_HEX), "1234"), "Hello OpenSSL crypto world!");
}

TEST(CryptoGuardCtx, DecryptRestoresEncryptedData) {
    for (size_t size : {0, 1, 15, 16, 17, 1024, 1025, 5000}) {
        std::string data;
        for (size_t i = 0; i < size; ++i) {
            data.push_back(static_cast<char>(i % 256));
        }
        EXPECT_EQ(Decrypt(Encrypt(data, "1234"), "1234"), data) << "size = " << size;
    }
}

TEST(CryptoGuardCtx, DecryptThrowsOnWrongPassword) {
    ASSERT_THROW(Decrypt(FromHex(REFERENCE_CIPHER_HEX), "4321"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnTruncatedData) {
    // Длина шифротекста CBC всегда кратна 16, обрезанные данные расшифровать нельзя
    const auto cipher = FromHex(REFERENCE_CIPHER_HEX);
    ASSERT_THROW(Decrypt(cipher.substr(0, cipher.size() - 1), "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnBadInputStream) {
    std::stringstream in{FromHex(REFERENCE_CIPHER_HEX)};
    std::stringstream out;
    in.setstate(std::ios::failbit);

    CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(in, out, "1234"), std::runtime_error);
    EXPECT_TRUE(out.str().empty());
}

TEST(CryptoGuardCtx, ChecksumMatchesKnownValues) {
    CryptoGuardCtx ctx;
    std::stringstream empty;
    std::stringstream abc{"abc"};
    std::stringstream large{std::string(5000, 'a')};

    EXPECT_EQ(ctx.CalculateChecksum(empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(ctx.CalculateChecksum(abc), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(ctx.CalculateChecksum(large), "c526c6222044dab5674de9c4ac7f4566ebb5e4d8bf9d8ea34c9cc8a7cc3c869c");
}

TEST(CryptoGuardCtx, ChecksumThrowsOnBadInputStream) {
    CryptoGuardCtx ctx;
    std::stringstream in{"data"};
    in.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumBeforeEncryptAndAfterRoundTrip) {
    std::string data;
    for (size_t i = 0; i < 100'000; ++i) {
        data.push_back(static_cast<char>((i * 7919) % 256));
    }
    CryptoGuardCtx ctx;

    std::stringstream original{data};
    const auto checksumBefore = ctx.CalculateChecksum(original);

    const auto encrypted = Encrypt(data, "1234");
    std::stringstream encryptedStream{encrypted};
    EXPECT_NE(ctx.CalculateChecksum(encryptedStream), checksumBefore);

    std::stringstream decrypted{Decrypt(encrypted, "1234")};
    EXPECT_EQ(ctx.CalculateChecksum(decrypted), checksumBefore);
}

TEST(CryptoGuardCtx, OneContextHandlesSeveralOperations) {
    CryptoGuardCtx ctx;
    for (const std::string password : {"1234", "another password", "пароль"}) {
        std::stringstream in{"Hello OpenSSL crypto world!"};
        std::stringstream encrypted;
        std::stringstream decrypted;
        ctx.EncryptFile(in, encrypted, password);
        ctx.DecryptFile(encrypted, decrypted, password);
        EXPECT_EQ(decrypted.str(), "Hello OpenSSL crypto world!") << "password = " << password;
    }
}

TEST(CryptoGuardCtx, DecryptThrowsOnEmptyInput) { ASSERT_THROW(Decrypt("", "1234"), std::runtime_error); }

TEST(CryptoGuardCtx, ContextWorksAfterMove) {
    CryptoGuardCtx source;
    CryptoGuardCtx ctx{std::move(source)};
    std::stringstream in{"abc"};
    EXPECT_EQ(ctx.CalculateChecksum(in), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
