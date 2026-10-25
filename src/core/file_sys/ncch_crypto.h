// Copyright 2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv3 or any later version
// Refer to the LICENSE.txt file included.

#pragma once

#include <array>
#include <optional>
#include <vector>
#include <boost/serialization/array.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/export.hpp>
#include "common/common_types.h"
#include "common/file_util.h"
#include "core/file_sys/ncch_container.h"

namespace FileSys {

/// AES-CTR keys and counters needed to decrypt the sections of an encrypted NCCH.
struct NCCHCryptoKeys {
    std::array<u8, 16> primary_key{};   ///< exheader, exefs header and icon/banner sections
    std::array<u8, 16> secondary_key{}; ///< romfs and the remaining exefs sections (.code)
    std::array<u8, 16> exheader_ctr{};
    std::array<u8, 16> exefs_ctr{};
    std::array<u8, 16> romfs_ctr{};
};

/**
 * Derives the NCCH section keys and counters from the header. The KeyX slots come from the
 * user provided aes_keys.txt. Returns nullopt if a required key or the title seed is missing.
 */
std::optional<NCCHCryptoKeys> DeriveNCCHCryptoKeys(const NCCH_Header& header);

/**
 * Read-only file that exposes an encrypted NCCH as if it were decrypted, decrypting each read
 * on the fly. The NCCH header it returns has no_crypto set, so the loaders above it see a
 * plain NCCH. Nothing decrypted is ever written to disk.
 */
class NCCHDecryptIOFile final : public FileUtil::IOFileBase {
public:
    NCCHDecryptIOFile();
    NCCHDecryptIOFile(std::unique_ptr<FileUtil::IOFileBase> encrypted_ncch,
                      const NCCH_Header& header, const NCCHCryptoKeys& keys);
    ~NCCHDecryptIOFile() override;

    bool Seek(s64 off, int origin) override;
    u64 Tell() const override;
    bool Resize(u64 size) override;

    std::unique_ptr<FileUtil::IOFileBase> OpenCopy() const override;

protected:
    std::size_t ReadImpl(void* data, std::size_t length, std::size_t elem_size) override;
    std::size_t ReadAtImpl(void* data, std::size_t byte_count, std::size_t offset) override;
    std::size_t WriteImpl(const void* data, std::size_t length, std::size_t elem_size) override;
    FileUtil::IOType::Type MyType() const override {
        return FileUtil::IOType::Type::NCCHDecryptFile;
    }

private:
    struct Region {
        std::size_t offset;    ///< Start of the encrypted region inside the NCCH
        std::size_t size;      ///< Region length in bytes
        std::size_t seek_from; ///< NCCH offset where the region's CTR stream starts
        const std::array<u8, 16>* key;
        const std::array<u8, 16>* ctr;
    };

    /// Builds the region table. Reads and decrypts the ExeFS header to locate its sections.
    bool BuildRegions();

    std::array<u8, sizeof(NCCH_Header)> raw_header{}; ///< Original (encrypted) NCCH header
    NCCH_Header plain_header{};                       ///< Header returned to readers
    NCCHCryptoKeys keys{};
    std::vector<Region> regions;
    u64 pos = 0;
    bool good = false;

    template <class Archive>
    void serialize(Archive& ar, const unsigned int);
    friend class boost::serialization::access;
};

} // namespace FileSys

BOOST_CLASS_EXPORT_KEY(FileSys::NCCHDecryptIOFile)
