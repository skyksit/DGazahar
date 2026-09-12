// Copyright 2018-2025 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <vector>
#include "common/common_types.h"

namespace Core {
class System;
struct TimingEventType;
} // namespace Core

namespace CoreTiming {
struct EventType;
}

namespace Cheats {

class CheatBase;

class CheatEngine {
public:
    explicit CheatEngine(Core::System& system);
    ~CheatEngine();

    /// Registers the cheat execution callback.
    void Connect(u32 process_id);

    /// Returns a span of the currently active cheats.
    std::span<const std::shared_ptr<CheatBase>> GetCheats() const;

    /// Adds a cheat to the cheat engine.
    void AddCheat(std::shared_ptr<CheatBase>&& cheat);

    /// Removes a cheat at the specified index in the cheats list.
    void RemoveCheat(std::size_t index);

    /// Updates a cheat at the specified index in the cheats list.
    void UpdateCheat(std::size_t index, std::shared_ptr<CheatBase>&& new_cheat);

    /// Loads the cheat file from disk for the specified title id.
    void LoadCheatFile(u64 title_id);

    /**
     * Re-reads the cheat file from disk even if it is already loaded.
     *
     * LoadCheatFile() bails out when the same title is already loaded, which means a frontend
     * that edits the cheat file while the game runs cannot get the change applied until the
     * next boot. This forgets the memo and reloads, so a host-side cheat editor can take effect
     * immediately.
     */
    void ReloadCheatFile(u64 title_id);

    /// Saves currently active cheats to file for the specified title id.
    void SaveCheatFile(u64 title_id) const;

    u32 GetConnectedPID() const {
        return process_id;
    }

private:
    /// The cheat execution callback.
    void RunCallback(std::uintptr_t user_data, s64 cycles_late);

private:
    Core::System& system;
    Core::TimingEventType* event;
    std::optional<u64> loaded_title_id;
    u32 process_id = 0xFFFFFFFF;
    std::vector<std::shared_ptr<CheatBase>> cheats_list;
    mutable std::shared_mutex cheats_list_mutex;
};
} // namespace Cheats
