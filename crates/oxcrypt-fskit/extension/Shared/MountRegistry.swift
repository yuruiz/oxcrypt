// MountRegistry.swift
// Thread-safe registry for tracking active FSKit mounts with ownership.

import Foundation
import os

/// Information about an active mount.
struct MountInfo: Sendable {
    /// Unique identifier for this mount.
    let mountId: UUID

    /// Path to the vault directory.
    let vaultPath: String

    /// Mountpoint where the vault is mounted.
    let mountpoint: String

    /// When the mount was created.
    let mountedAt: Date

    /// Audit token of the process that requested the mount (for ownership).
    let ownerAuditToken: Data

    /// Team ID of the process that requested the mount.
    let ownerTeamId: String

    /// Convert to dictionary for XPC response.
    func toDictionary() -> [String: Any] {
        return [
            "mountId": mountId.uuidString,
            "vaultPath": vaultPath,
            "mountpoint": mountpoint,
            "mountedAt": ISO8601DateFormatter().string(from: mountedAt),
            "backend": "fskit"
        ]
    }
}

/// Thread-safe registry for active mounts.
/// Tracks mount ownership to ensure only the creator (or same team) can query/unmount.
actor MountRegistry {
    /// Singleton instance.
    static let shared = MountRegistry()

    /// Active mounts by mountpoint.
    private var mounts: [String: MountInfo] = [:]

    /// Mounts by vault path (for detecting duplicate mount attempts).
    private var mountsByVault: [String: String] = [:]  // vaultPath -> mountpoint
    private var pendingVaults: Set<String> = []
    private var unmounting: Set<String> = []
    private var detached: Set<String> = []

    /// Maximum number of concurrent mounts (resource exhaustion protection).
    private let maxMounts = 10

    private let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "MountRegistry")

    init() {}

    /// Reserve a vault before changing credentials, then publish the system's
    /// actual mount path only after the mount API succeeds.
    func mount(
        vaultPath: String,
        ownerAuditToken: Data,
        ownerTeamId: String,
        prepare: () throws -> Void,
        performMount: () async throws -> URL,
        cleanup: () throws -> Void
    ) async throws -> MountInfo {
        guard mountsByVault[vaultPath] == nil, !pendingVaults.contains(vaultPath) else {
            throw OxVaultServiceError.alreadyMounted
        }
        guard mounts.count + pendingVaults.count < maxMounts else {
            throw OxVaultServiceError.resourceExhausted
        }
        pendingVaults.insert(vaultPath)
        defer { pendingVaults.remove(vaultPath) }

        let location: URL
        do {
            try prepare()
            location = try await performMount()
        } catch {
            do {
                try cleanup()
            } catch let cleanupError {
                throw NSError(
                    domain: "com.agucova.oxcrypt.xpc",
                    code: OxVaultServiceError.mountFailed.rawValue,
                    userInfo: [
                        NSLocalizedDescriptionKey: "Mount failed and its previous Keychain credential state could not be restored",
                        NSUnderlyingErrorKey: cleanupError
                    ]
                )
            }
            throw error
        }
        // The reservation holds a slot and prevents another mount of this vault.
        return register(
            vaultPath: vaultPath,
            mountpoint: location.path,
            ownerAuditToken: ownerAuditToken,
            ownerTeamId: ownerTeamId
        )
    }

    /// Publish a mount whose reservation has already been validated.
    private func register(
        vaultPath: String,
        mountpoint: String,
        ownerAuditToken: Data,
        ownerTeamId: String
    ) -> MountInfo {
        let info = MountInfo(
            mountId: UUID(),
            vaultPath: vaultPath,
            mountpoint: mountpoint,
            mountedAt: Date(),
            ownerAuditToken: ownerAuditToken,
            ownerTeamId: ownerTeamId
        )

        mounts[mountpoint] = info
        mountsByVault[vaultPath] = mountpoint

        logger.info("Registered mount: \(mountpoint) for vault \(vaultPath)")
        return info
    }

    /// Keep ownership and credentials available when system detachment fails.
    func unmount(
        mountpoint: String,
        clientAuditToken: Data,
        clientTeamId: String,
        detach: () async throws -> Void,
        removeCredential: (String) throws -> Void
    ) async throws {
        guard let info = mounts[mountpoint] else {
            throw OxVaultServiceError.notFound
        }
        guard canAccess(mountpoint: mountpoint, clientAuditToken: clientAuditToken, clientTeamId: clientTeamId) else {
            throw OxVaultServiceError.permissionDenied
        }
        guard unmounting.insert(mountpoint).inserted else {
            throw OxVaultServiceError.resourceExhausted
        }
        defer { unmounting.remove(mountpoint) }
        if !detached.contains(mountpoint) {
            try await detach()
            detached.insert(mountpoint)
        }
        // A credential cleanup failure can be retried without detaching twice.
        try removeCredential(info.vaultPath)
        _ = unregister(mountpoint: mountpoint)
        detached.remove(mountpoint)
    }

    private func unregister(mountpoint: String) -> MountInfo? {
        guard let info = mounts.removeValue(forKey: mountpoint) else {
            return nil
        }

        mountsByVault.removeValue(forKey: info.vaultPath)
        logger.info("Unregistered mount: \(mountpoint)")
        return info
    }

    /// Get mount info by mountpoint.
    func get(mountpoint: String) -> MountInfo? {
        return mounts[mountpoint]
    }

    /// Get mount info by vault path.
    func getByVaultPath(_ vaultPath: String) -> MountInfo? {
        guard let mountpoint = mountsByVault[vaultPath] else {
            return nil
        }
        return mounts[mountpoint]
    }

    /// List all mounts visible to the given client.
    /// A mount is visible if:
    /// 1. The client is the owner (same audit token), OR
    /// 2. The client has the same team ID
    func listMounts(forClientWithTeamId teamId: String) -> [MountInfo] {
        return Array(mounts.values.filter { mount in
            mount.ownerTeamId == teamId
        })
    }

    /// Check if a client can access a mount.
    /// Access is allowed if:
    /// 1. The client is the owner, OR
    /// 2. The client has the same team ID
    func canAccess(
        mountpoint: String,
        clientAuditToken: Data,
        clientTeamId: String
    ) -> Bool {
        guard let mount = mounts[mountpoint] else {
            return false
        }

        return mount.ownerAuditToken == clientAuditToken ||
               mount.ownerTeamId == clientTeamId
    }

    /// Get all mountpoints (for cleanup on extension termination).
    func allMountpoints() -> [String] {
        return Array(mounts.keys)
    }

    /// Clear all mounts (for cleanup).
    func clear() {
        mounts.removeAll()
        mountsByVault.removeAll()
        logger.info("Cleared all mounts")
    }
}
