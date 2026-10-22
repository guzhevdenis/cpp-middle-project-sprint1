#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

namespace {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector

    ~AesCipherParams() {
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(iv.data(), iv.size());
    }
};

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

// Забирает из очереди OpenSSL все ошибки, оставляя её пустой
[[noreturn]] void ThrowOpenSSLError(std::string_view what) {
    std::string message{what};
    std::array<char, 256> buf{};
    bool first = true;
    while (const unsigned long code = ERR_get_error()) {
        ERR_error_string_n(code, buf.data(), buf.size());
        message += first ? ": " : "; ";
        message += buf.data();
        first = false;
    }
    if (first) {
        message += ": no details in OpenSSL error queue";
    }
    throw std::runtime_error{message};
}

}  // namespace

class CryptoGuardCtx::PImpl {
public:
    PImpl() { OpenSSL_add_all_algorithms(); }
    ~PImpl() { EVP_cleanup(); }

    PImpl(const PImpl &) = delete;
    PImpl &operator=(const PImpl &) = delete;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ERR_clear_error();
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        DoCrypt(inStream, outStream, params);
    }
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ERR_clear_error();
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        DoCrypt(inStream, outStream, params);
    }
    std::string CalculateChecksum(std::iostream &inStream) {
        ERR_clear_error();
        if (!inStream.good()) {
            throw std::runtime_error{"Input stream is not ready for reading"};
        }

        MdCtxPtr ctx{EVP_MD_CTX_new()};
        if (!ctx) {
            ThrowOpenSSLError("EVP_MD_CTX_new failed to create digest context");
        }
        if (!EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), nullptr)) {
            ThrowOpenSSLError("EVP_DigestInit_ex2 failed to initialize SHA-256");
        }

        std::array<char, BUF_SIZE> buf;
        while (inStream.read(buf.data(), buf.size()) || inStream.gcount() > 0) {
            if (!EVP_DigestUpdate(ctx.get(), buf.data(), inStream.gcount())) {
                ThrowOpenSSLError("EVP_DigestUpdate failed to hash data");
            }
        }
        if (inStream.bad()) {
            throw std::runtime_error{"Failed to read from input stream"};
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest;
        unsigned int digestLen = 0;
        if (!EVP_DigestFinal_ex(ctx.get(), digest.data(), &digestLen)) {
            ThrowOpenSSLError("EVP_DigestFinal_ex failed to finalize SHA-256");
        }

        std::stringstream hex;
        hex << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < digestLen; ++i) {
            hex << std::setw(2) << static_cast<int>(digest[i]);
        }
        return hex.str();
    }

private:
    static constexpr size_t BUF_SIZE = 1024;

    // Потоковое шифрование/дешифрование по образцу do_crypt из документации OpenSSL
    void DoCrypt(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {
        if (!inStream.good()) {
            throw std::runtime_error{"Input stream is not ready for reading"};
        }
        if (!outStream.good()) {
            throw std::runtime_error{"Output stream is not ready for writing"};
        }

        CipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            ThrowOpenSSLError("EVP_CIPHER_CTX_new failed to create cipher context");
        }
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            ThrowOpenSSLError("EVP_CipherInit_ex failed to initialize AES-256-CBC");
        }

        std::array<unsigned char, BUF_SIZE> inBuf;
        std::array<unsigned char, BUF_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf;
        int outLen = 0;

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            // Последний блок короче буфера: read выставит eof и fail, это не ошибка
            if (inStream.bad()) {
                throw std::runtime_error{"Failed to read from input stream"};
            }
            const auto inLen = static_cast<int>(inStream.gcount());
            if (inLen == 0) {
                break;
            }

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
                ThrowOpenSSLError(params.encrypt ? "EVP_CipherUpdate failed to encrypt data"
                                                 : "EVP_CipherUpdate failed to decrypt data");
            }
            WriteToStream(outStream, outBuf.data(), outLen);
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            ThrowOpenSSLError(
                params.encrypt ? "EVP_CipherFinal_ex failed to finalize encryption"
                               : "EVP_CipherFinal_ex failed to finalize decryption (wrong password or corrupted data)");
        }
        WriteToStream(outStream, outBuf.data(), outLen);
    }

    static void WriteToStream(std::iostream &outStream, const unsigned char *data, int len) {
        outStream.write(reinterpret_cast<const char *>(data), len);
        if (!outStream) {
            throw std::runtime_error{"Failed to write to output stream"};
        }
    }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            ThrowOpenSSLError("EVP_BytesToKey failed to create a key from password");
        }

        return params;
    }
};

// Специальные методы определены здесь, где PImpl уже полный тип:
// иначе std::unique_ptr не сможет вызвать его деструктор
CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
