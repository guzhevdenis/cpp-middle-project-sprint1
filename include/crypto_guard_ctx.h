#pragma once

#include <experimental/propagate_const>
#include <iosfwd>
#include <memory>
#include <string>
#include <string_view>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    class PImpl;
    std::experimental::propagate_const<std::unique_ptr<PImpl>> pImpl_;
};

}  // namespace CryptoGuard
