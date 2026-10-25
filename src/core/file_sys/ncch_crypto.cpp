// Copyright 2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv3 or any later version
// Refer to the LICENSE.txt file included.

#include <algorithm>
#include <cstring>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include "common/alignment.h"
#include "common/archives.h"
#include "common/file_derived.h"
#include "common/logging/log.h"
#include "core/file_sys/ncch_crypto.h"
#include "core/file_sys/seed_db.h"
#include "core/hw/aes/key.h"

namespace FileSys {

namespace {

constexpr std::size_t kBlockSize = 0x200; ///< NCCH media unit

std::optional<HW::AES::AESKey> NormalKeyFor(std::size_t slot, const HW::AES::AESKey& key_y) {
    HW::AES::SetKeyY(slot, key_y);
    if (!HW::AES::IsNormalKeyAvailable(slot)) {
        return std::nullopt;
    }
    return HW::AES::GetNormalKey(slot);
}

std::optional<std::size_t> SecondarySlot(u8 secondary_key_slot) {
    using namespace HW::AES;
    switch (secondary_key_slot) {
    case 0:
        return KeySlotID::NCCHSecure1;
    case 1:
        return KeySlotID::NCCHSecure2;
    case 10:
        return KeySlotID::NCCHSecure3;
    case 11:
        return KeySlotID::NCCHSecure4;
    default:
        return std::nullopt;
    }
}

std::optional<NCCHCryptoKeys> DeriveOnce(const NCCH_Header& header) {
    NCCHCryptoKeys keys;

    if (header.fixed_key) {
        // Fixed-key (zero key) crypto, used by some system titles and dev builds
        keys.primary_key.fill(0);
        keys.secondary_key.fill(0);
    } else {
        HW::AES::AESKey key_y_primary;
        std::copy(header.signature, header.signature + key_y_primary.size(),
                  key_y_primary.begin());

        HW::AES::AESKey key_y_secondary = key_y_primary;
        if (header.seed_crypto) {
            const auto seed = FileSys::GetSeed(header.program_id);
            if (!seed) {
                LOG_ERROR(Service_FS, "Seed for program {:016X} not found", header.program_id);
                return std::nullopt;
            }
            std::array<u8, 32> input;
            std::memcpy(input.data(), key_y_primary.data(), key_y_primary.size());
            std::memcpy(input.data() + key_y_primary.size(), seed->data(), seed->size());
            std::array<u8, CryptoPP::SHA256::DIGESTSIZE> hash;
            CryptoPP::SHA256().CalculateDigest(hash.data(), input.data(), input.size());
            std::memcpy(key_y_secondary.data(), hash.data(), key_y_secondary.size());
        }

        const auto slot = SecondarySlot(header.secondary_key_slot);
        if (!slot) {
            LOG_ERROR(Service_FS, "Unknown NCCH secondary key slot {}",
                      header.secondary_key_slot);
            return std::nullopt;
        }

        const auto primary = NormalKeyFor(HW::AES::KeySlotID::NCCHSecure1, key_y_primary);
        const auto secondary = NormalKeyFor(*slot, key_y_secondary);
        if (!primary || !secondary) {
            return std::nullopt;
        }
        keys.primary_key = *primary;
        keys.secondary_key = *secondary;
    }

    // Written with reference to
    // https://github.com/d0k3/GodMode9/blob/99af6a73be48fa7872649aaa7456136da0df7938/arm9/source/game/ncch.c#L34-L52
    if (header.version == 0 || header.version == 2) {
        // CTR is the partition ID (reversed) followed by a per-section magic number
        std::reverse_copy(header.partition_id, header.partition_id + 8,
                          keys.exheader_ctr.begin());
        keys.exefs_ctr = keys.romfs_ctr = keys.exheader_ctr;
        keys.exheader_ctr[8] = 1;
        keys.exefs_ctr[8] = 2;
        keys.romfs_ctr[8] = 3;
    } else if (header.version == 1) {
        // CTR is the partition ID followed by the section offset, as if the whole image were
        // encrypted with a single CTR stream
        std::copy(header.partition_id, header.partition_id + 8, keys.exheader_ctr.begin());
        keys.exefs_ctr = keys.romfs_ctr = keys.exheader_ctr;
        auto put_be32 = [](std::array<u8, 16>& ctr, u32 value) {
            ctr[12] = static_cast<u8>(value >> 24);
            ctr[13] = static_cast<u8>(value >> 16);
            ctr[14] = static_cast<u8>(value >> 8);
            ctr[15] = static_cast<u8>(value);
        };
        put_be32(keys.exheader_ctr, 0x200);
        put_be32(keys.exefs_ctr, static_cast<u32>(header.exefs_offset * kBlockSize));
        put_be32(keys.romfs_ctr, static_cast<u32>(header.romfs_offset * kBlockSize));
    } else {
        LOG_ERROR(Service_FS, "Unknown NCCH version {}", header.version);
        return std::nullopt;
    }

    return keys;
}

void CtrDecrypt(u8* data, std::size_t size, const std::array<u8, 16>& key,
                const std::array<u8, 16>& ctr, std::size_t stream_offset) {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d(key.data(), key.size(), ctr.data());
    if (stream_offset != 0) {
        d.Seek(stream_offset);
    }
    d.ProcessData(data, data, size);
}

} // namespace

std::optional<NCCHCryptoKeys> DeriveNCCHCryptoKeys(const NCCH_Header& header) {
    HW::AES::InitKeys();
    if (auto keys = DeriveOnce(header)) {
        return keys;
    }
    // The key file may have been read before the frontend set the user directory (it is
    // cached after the first load), so retry once with a forced reload.
    HW::AES::InitKeys(true);
    auto keys = DeriveOnce(header);
    if (!keys) {
        LOG_ERROR(Service_FS, "Missing keys to decrypt NCCH {:016X}", header.program_id);
    }
    return keys;
}

NCCHDecryptIOFile::NCCHDecryptIOFile() {
    Child() = std::make_unique<FileUtil::NullIOFile>();
}

NCCHDecryptIOFile::NCCHDecryptIOFile(std::unique_ptr<FileUtil::IOFileBase> encrypted_ncch,
                                     const NCCH_Header& header, const NCCHCryptoKeys& keys_)
    : keys(keys_) {
    Child() = std::move(encrypted_ncch);
    std::memcpy(raw_header.data(), &header, sizeof(NCCH_Header));
    good = BuildRegions();
}

NCCHDecryptIOFile::~NCCHDecryptIOFile() = default;

bool NCCHDecryptIOFile::BuildRegions() {
    regions.clear();
    pos = 0;
    std::memcpy(&plain_header, raw_header.data(), sizeof(NCCH_Header));
    plain_header.no_crypto.Assign(1);

    const NCCH_Header& h = plain_header;
    if (h.extended_header_size) {
        regions.push_back({sizeof(NCCH_Header), sizeof(ExHeader_Header), sizeof(NCCH_Header),
                           &keys.primary_key, &keys.exheader_ctr});
    }
    if (h.romfs_size) {
        const std::size_t romfs_offset = h.romfs_offset * kBlockSize;
        regions.push_back({romfs_offset, h.romfs_size * kBlockSize, romfs_offset,
                           &keys.secondary_key, &keys.romfs_ctr});
    }
    if (h.exefs_size) {
        const std::size_t exefs_offset = h.exefs_offset * kBlockSize;
        regions.push_back({exefs_offset, sizeof(ExeFs_Header), exefs_offset, &keys.primary_key,
                           &keys.exefs_ctr});

        ExeFs_Header exefs_header;
        if (Child()->ReadAtBytes(&exefs_header, sizeof(exefs_header), exefs_offset) !=
            sizeof(exefs_header)) {
            LOG_ERROR(Service_FS, "Failed to read encrypted ExeFS header");
            return false;
        }
        CtrDecrypt(reinterpret_cast<u8*>(&exefs_header), sizeof(exefs_header), keys.primary_key,
                   keys.exefs_ctr, 0);

        // Same section key split as the CIA installer (NCCHCryptoFile)
        for (const auto& section : exefs_header.section) {
            if (section.size == 0) {
                continue;
            }
            const bool is_primary = std::memcmp(section.name, "icon", 4) == 0 ||
                                    std::memcmp(section.name, "banner", 6) == 0;
            regions.push_back({exefs_offset + sizeof(ExeFs_Header) + section.offset,
                               Common::AlignUp(section.size, kBlockSize), exefs_offset,
                               is_primary ? &keys.primary_key : &keys.secondary_key,
                               &keys.exefs_ctr});
        }
    }
    return true;
}

std::size_t NCCHDecryptIOFile::ReadAtImpl(void* data, std::size_t byte_count,
                                          std::size_t offset) {
    if (!good) {
        return 0;
    }
    const std::size_t read = Child()->ReadAtArray(static_cast<char*>(data), byte_count, offset);
    if (read == 0) {
        return 0;
    }
    u8* out = static_cast<u8*>(data);
    const std::size_t end = offset + read;

    if (offset < sizeof(NCCH_Header)) {
        const std::size_t n = std::min(end, sizeof(NCCH_Header)) - offset;
        std::memcpy(out, reinterpret_cast<const u8*>(&plain_header) + offset, n);
    }

    for (const auto& reg : regions) {
        const std::size_t start = std::max(offset, reg.offset);
        const std::size_t stop = std::min(end, reg.offset + reg.size);
        if (start >= stop) {
            continue;
        }
        CtrDecrypt(out + (start - offset), stop - start, *reg.key, *reg.ctr,
                   start - reg.seek_from);
    }
    return read;
}

std::size_t NCCHDecryptIOFile::ReadImpl(void* data, std::size_t length, std::size_t elem_size) {
    if (elem_size == 0) {
        return 0;
    }
    const std::size_t read = ReadAtImpl(data, length * elem_size, pos);
    pos += read;
    return read / elem_size;
}

std::size_t NCCHDecryptIOFile::WriteImpl(const void*, std::size_t, std::size_t) {
    return 0; // read-only
}

bool NCCHDecryptIOFile::Seek(s64 off, int origin) {
    s64 target;
    switch (origin) {
    case SEEK_SET:
        target = off;
        break;
    case SEEK_CUR:
        target = static_cast<s64>(pos) + off;
        break;
    case SEEK_END:
        target = static_cast<s64>(GetSize()) + off;
        break;
    default:
        return false;
    }
    if (target < 0 || static_cast<u64>(target) > GetSize()) {
        return false;
    }
    pos = static_cast<u64>(target);
    return true;
}

u64 NCCHDecryptIOFile::Tell() const {
    return pos;
}

bool NCCHDecryptIOFile::Resize(u64) {
    return false;
}

std::unique_ptr<FileUtil::IOFileBase> NCCHDecryptIOFile::OpenCopy() const {
    auto ret = std::make_unique<NCCHDecryptIOFile>();
    ret->Child() = Child()->OpenCopy();
    ret->raw_header = raw_header;
    ret->keys = keys;
    ret->good = ret->BuildRegions();
    return ret;
}

template <class Archive>
void NCCHDecryptIOFile::serialize(Archive& ar, const unsigned int) {
    ar& boost::serialization::base_object<FileUtil::IOFileBase>(*this);
    ar & raw_header;
    ar & pos;
    if (Archive::is_loading::value) {
        // Keys are never stored in savestates; derive them again from the key file
        const u64 saved_pos = pos;
        NCCH_Header header;
        std::memcpy(&header, raw_header.data(), sizeof(NCCH_Header));
        const auto derived = DeriveNCCHCryptoKeys(header);
        good = derived.has_value();
        if (good) {
            keys = *derived;
            good = BuildRegions();
        }
        pos = saved_pos;
    }
}

} // namespace FileSys

SERIALIZE_EXPORT_IMPL(FileSys::NCCHDecryptIOFile)
