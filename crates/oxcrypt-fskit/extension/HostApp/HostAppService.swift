// HostAppService.swift
// XPC service implementation for the Host App.
// Handles mount requests by storing passwords in Keychain and triggering FSKit.

import AppKit
import Foundation
import FSKit
import Security
import os

/// XPC service for CLI/Desktop communication hosted in the main app.
/// Unlike the extension-hosted version, this doesn't have direct access to
/// the Rust filesystem. Instead, it stores passwords in Keychain and triggers
/// FSKit to load the extension which reads the password.
final class HostAppService: NSObject, OxVaultServiceProtocol {
    private static let logger = Logger(subsystem: "com.agucova.oxcrypt", category: "HostAppService")

    /// The audit token of the connected client (for ownership tracking).
    private let clientAuditToken: Data

    /// The team ID of the connected client.
    private let clientTeamId: String

    /// Rate limiting: last request time per operation.
    private var lastRequestTime: Date = .distantPast
    private let minRequestInterval: TimeInterval = 0.1  // 100ms between requests

    init(auditToken: Data, teamId: String) {
        self.clientAuditToken = auditToken
        self.clientTeamId = teamId
        super.init()
        Self.logger.info("HostAppService initialized for client with team ID: \(teamId)")
    }

    // MARK: - OxVaultServiceProtocol

    func mount(
        vaultPath: String,
        password: String,
        reply: @escaping (String?, NSError?) -> Void
    ) {
        fputs("HostAppService: Mount request received for: \(vaultPath)\n", stderr)
        Self.logger.info("Mount request for: \(vaultPath)")

        // Rate limiting
        guard checkRateLimit() else {
            Self.logger.warning("Rate limit exceeded")
            reply(nil, OxVaultServiceError.resourceExhausted.nsError)
            return
        }

        // Input validation
        guard let validatedPath = validateVaultPath(vaultPath) else {
            fputs("HostAppService: Invalid vault path: \(vaultPath)\n", stderr)
            Self.logger.warning("Invalid vault path: \(vaultPath)")
            reply(nil, OxVaultServiceError.invalidVault.nsError)
            return
        }
        fputs("HostAppService: Vault path validated: \(validatedPath)\n", stderr)

        guard !password.isEmpty, password.count <= 10240 else {
            Self.logger.warning("Invalid password (empty or too long)")
            reply(nil, OxVaultServiceError.authFailed.nsError)
            return
        }

        Task {
            do {
                let mount = try await NativeMountManager.mount(
                    vaultPath: validatedPath,
                    password: password,
                    ownerAuditToken: clientAuditToken,
                    ownerTeamId: clientTeamId
                )
                Self.logger.info("Mounted vault at: \(mount.mountpoint)")
                reply(mount.mountpoint, nil)
            } catch let error as OxVaultServiceError {
                reply(nil, error.nsError)
            } catch {
                Self.logger.error("Public FSKit mount failed: \(error)")
                reply(nil, error as NSError)
            }
        }
    }

    func unmount(
        mountpoint: String,
        reply: @escaping (NSError?) -> Void
    ) {
        Self.logger.info("Unmount request for: \(mountpoint)")

        // Rate limiting
        guard checkRateLimit() else {
            reply(OxVaultServiceError.resourceExhausted.nsError)
            return
        }

        // Validate mountpoint
        guard validateMountpoint(mountpoint) else {
            Self.logger.warning("Invalid mountpoint: \(mountpoint)")
            reply(OxVaultServiceError.invalidVault.nsError)
            return
        }

        Task {
            do {
                try await MountRegistry.shared.unmount(
                    mountpoint: mountpoint,
                    clientAuditToken: clientAuditToken,
                    clientTeamId: clientTeamId,
                    detach: { try DiskutilUnmount.detach(mountpoint) },
                    removeCredential: { try KeychainHelper.delete(for: $0) }
                )
                Self.logger.info("Unmount successful: \(mountpoint)")
                reply(nil)
            } catch let error as OxVaultServiceError {
                reply(error.nsError)
            } catch {
                Self.logger.error("Unmount failed: \(error)")
                reply(error as NSError)
            }
        }
    }

    func listMounts(
        reply: @escaping ([[String: Any]]?, NSError?) -> Void
    ) {
        Self.logger.info("List mounts request")

        Task {
            let mounts = await MountRegistry.shared.listMounts(forClientWithTeamId: clientTeamId)
            let dicts = mounts.map { $0.toDictionary() }
            reply(dicts, nil)
        }
    }

    func getStats(
        mountpoint: String,
        reply: @escaping ([String: Any]?, NSError?) -> Void
    ) {
        Self.logger.info("Get stats request for: \(mountpoint)")

        Task {
            // Check access permission
            let canAccess = await MountRegistry.shared.canAccess(
                mountpoint: mountpoint,
                clientAuditToken: clientAuditToken,
                clientTeamId: clientTeamId
            )

            guard canAccess else {
                Self.logger.warning("Permission denied for stats: \(mountpoint)")
                reply(nil, OxVaultServiceError.permissionDenied.nsError)
                return
            }

            guard let mountInfo = await MountRegistry.shared.get(mountpoint: mountpoint) else {
                reply(nil, OxVaultServiceError.notFound.nsError)
                return
            }

            // Return basic mount info
            // TODO: Could query the mount for actual FS stats via statfs
            let stats: [String: Any] = [
                "vaultPath": mountInfo.vaultPath,
                "mountpoint": mountInfo.mountpoint,
                "mountedAt": ISO8601DateFormatter().string(from: mountInfo.mountedAt),
                "bytesRead": 0,
                "bytesWritten": 0,
                "filesOpened": 0,
                "opsCount": 0
            ]

            reply(stats, nil)
        }
    }

    func ping(reply: @escaping (Bool) -> Void) {
        Self.logger.debug("Ping received")
        reply(true)
    }

    // MARK: - Helpers

    /// Validate and canonicalize a vault path.
    private func validateVaultPath(_ path: String) -> String? {
        guard path.hasPrefix("/") else {
            return nil
        }

        let url = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        let canonicalPath = url.path

        let vaultConfigPath = url.appendingPathComponent("vault.cryptomator").path
        guard FileManager.default.fileExists(atPath: vaultConfigPath) else {
            Self.logger.warning("No vault.cryptomator found at: \(canonicalPath)")
            return nil
        }

        return canonicalPath
    }

    /// Validate a mountpoint path.
    private func validateMountpoint(_ path: String) -> Bool {
        guard path.hasPrefix("/") else {
            return false
        }

        let allowedPrefixes = ["/Volumes/", "/tmp/", NSHomeDirectory() + "/"]
        return allowedPrefixes.contains { path.hasPrefix($0) }
    }

    /// Check rate limiting.
    private func checkRateLimit() -> Bool {
        let now = Date()
        guard now.timeIntervalSince(lastRequestTime) >= minRequestInterval else {
            return false
        }
        lastRequestTime = now
        return true
    }
}
