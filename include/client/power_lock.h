/*
 * Power Lock Provider Interface
 * 
 * Provides an abstraction for power management lock functionality.
 * This allows modules to acquire/release power locks without
 * directly depending on NetworkManager.
 */

#pragma once

/**
 * Power save level enumeration
 */
enum class PowerSaveLevel {
    UNKNOWN,      // Unknown power save level
    LOW_POWER,    // Maximum power saving (lowest power consumption)
    BALANCED,     // Medium power saving (balanced)
    PERFORMANCE,  // No power saving (maximum power consumption / full performance)
};

/**
 * PowerLockProvider - Abstract interface for power lock management
 * 
 * Implementations should provide reference-counting based power lock management.
 * Multiple acquisitions at the same level should increment a counter.
 */
class PowerLockProvider {
public:
    virtual ~PowerLockProvider() = default;
    
    /**
     * Acquire a power lock at the specified level
     * @param level Power save level to acquire
     */
    virtual void AcquirePowerLock(PowerSaveLevel level) = 0;
    
    /**
     * Release a power lock at the specified level
     * @param level Power save level to release
     */
    virtual void ReleasePowerLock(PowerSaveLevel level) = 0;
};

/**
 * ScopedPowerLock - RAII guard for power lock management
 * 
 * Automatically acquires power lock on construction and releases on destruction.
 */
class ScopedPowerLock {
public:
    ScopedPowerLock(PowerLockProvider* provider, PowerSaveLevel level)
        : provider_(provider), level_(level) {
        if (provider_) {
            provider_->AcquirePowerLock(level_);
        }
    }
    
    ScopedPowerLock(PowerLockProvider& provider, PowerSaveLevel level)
        : ScopedPowerLock(&provider, level) {}
    
    ~ScopedPowerLock() {
        if (provider_) {
            provider_->ReleasePowerLock(level_);
        }
    }
    
    // Non-copyable and non-movable
    ScopedPowerLock(const ScopedPowerLock&) = delete;
    ScopedPowerLock& operator=(const ScopedPowerLock&) = delete;
    ScopedPowerLock(ScopedPowerLock&&) = delete;
    ScopedPowerLock& operator=(ScopedPowerLock&&) = delete;
    
private:
    PowerLockProvider* provider_;
    PowerSaveLevel level_;
};

