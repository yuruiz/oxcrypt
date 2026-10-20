import Foundation
import FSKit

/// Public FSKit mounting for local vault directories.
enum NativeMountManager {
    static func mount(
        vaultPath: String,
        password: String,
        ownerAuditToken: Data,
        ownerTeamId: String
    ) async throws -> MountInfo {
        guard #available(macOS 27.0, *) else {
            throw OxVaultServiceError.unsupportedSystem
        }
        let vaultURL = URL(fileURLWithPath: vaultPath)
            .standardizedFileURL.resolvingSymlinksInPath()
        guard vaultPath.hasPrefix("/"),
              FileManager.default.fileExists(atPath: vaultURL.appendingPathComponent("vault.cryptomator").path) else {
            throw OxVaultServiceError.invalidVault
        }
        guard !password.isEmpty, password.count <= 10240 else {
            throw OxVaultServiceError.authFailed
        }
        let credentials = VaultCredentialTransaction(
            read: { try KeychainHelper.retrieve(for: vaultURL.path) },
            write: { try KeychainHelper.store(password: $0, for: vaultURL.path) },
            remove: { try KeychainHelper.delete(for: vaultURL.path) }
        )
        return try await MountRegistry.shared.mount(
            vaultPath: vaultURL.path,
            ownerAuditToken: ownerAuditToken,
            ownerTeamId: ownerTeamId,
            prepare: {
                try credentials.prepare(password: password)
            },
            performMount: {
                let resource = FSPathURLResource(url: vaultURL, writable: true)
                return try await FSClient.shared.mountSingleVolume(
                    resource: resource,
                    bundleID: "com.agucova.oxcrypt.desktop.fsextension",
                    options: []
                )
            },
            cleanup: {
                try credentials.rollback()
            }
        )
    }

    static func mountStoredVault(
        vaultPath: String,
        requestedMountpoint: String?,
        ownerTeamId: String
    ) async throws -> MountInfo {
        guard #available(macOS 27.0, *) else {
            throw OxVaultServiceError.unsupportedSystem
        }
        guard requestedMountpoint == nil else {
            throw NSError(
                domain: "com.agucova.oxcrypt.xpc",
                code: OxVaultServiceError.invalidVault.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "FSKit chooses its mount path under /Volumes; omit the mount URL parameter"]
            )
        }
        let path = URL(fileURLWithPath: vaultPath).standardizedFileURL.resolvingSymlinksInPath().path
        let password = try KeychainHelper.retrieve(for: path)
        return try await mount(
            vaultPath: path,
            password: password,
            ownerAuditToken: Data(),
            ownerTeamId: ownerTeamId
        )
    }
}
