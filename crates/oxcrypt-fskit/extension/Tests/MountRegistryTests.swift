import Foundation

private enum TestFailure: Error {
    case mount
    case cleanup
}

private actor MountGate {
    private var started = false
    private var startWaiter: CheckedContinuation<Void, Never>?
    private var completion: CheckedContinuation<Void, Never>?

    func waitForMount() async {
        started = true
        startWaiter?.resume()
        startWaiter = nil
        await withCheckedContinuation { completion = $0 }
    }

    func waitUntilStarted() async {
        if !started {
            await withCheckedContinuation { startWaiter = $0 }
        }
    }

    func release() {
        completion?.resume()
        completion = nil
    }
}

@main
struct MountRegistryTests {
    static func main() async throws {
        let registry = MountRegistry()
        var removedCredential = false

        do {
            _ = try await registry.mount(
                vaultPath: "/test/failure",
                ownerAuditToken: Data(),
                ownerTeamId: "test",
                prepare: {},
                performMount: { throw TestFailure.mount },
                cleanup: { removedCredential = true }
            )
            fatalError("Mount failure must propagate")
        } catch TestFailure.mount {}
        precondition(removedCredential, "Failed mounts must remove their credential")
        let failedMount = await registry.getByVaultPath("/test/failure")
        precondition(failedMount == nil, "Failed mounts must not enter the registry")

        let retry = try await registry.mount(
            vaultPath: "/test/failure",
            ownerAuditToken: Data([1]),
            ownerTeamId: "test",
            prepare: {},
            performMount: { URL(fileURLWithPath: "/Volumes/Actual name 2") },
            cleanup: { fatalError("Successful mount must retain its credential") }
        )
        precondition(retry.mountpoint == "/Volumes/Actual name 2")
        let actual = await registry.get(mountpoint: "/Volumes/Actual name 2")
        precondition(actual?.vaultPath == "/test/failure")

        let gate = MountGate()
        let first = Task {
            try await registry.mount(
                vaultPath: "/test/concurrent",
                ownerAuditToken: Data([2]),
                ownerTeamId: "test",
                prepare: {},
                performMount: {
                    await gate.waitForMount()
                    return URL(fileURLWithPath: "/Volumes/Concurrent")
                },
                cleanup: { fatalError("Duplicate request must not clean the owner's credential") }
            )
        }
        await gate.waitUntilStarted()
        do {
            _ = try await registry.mount(
                vaultPath: "/test/concurrent",
                ownerAuditToken: Data([3]),
                ownerTeamId: "test",
                prepare: { fatalError("Duplicate request must not overwrite credentials") },
                performMount: { fatalError("Duplicate request must not invoke FSKit") },
                cleanup: { fatalError("Duplicate request must not remove credentials") }
            )
            fatalError("Concurrent duplicate mount must fail")
        } catch OxVaultServiceError.alreadyMounted {}
        await gate.release()
        _ = try await first.value

        do {
            _ = try await registry.mount(
                vaultPath: "/test/cleanup",
                ownerAuditToken: Data(),
                ownerTeamId: "test",
                prepare: { throw TestFailure.mount },
                performMount: { fatalError("Failed preparation must not invoke FSKit") },
                cleanup: { throw TestFailure.cleanup }
            )
            fatalError("Cleanup failures must propagate")
        } catch {
            precondition((error as NSError).localizedDescription.contains("Keychain"))
        }
        let cleanupFailure = await registry.getByVaultPath("/test/cleanup")
        precondition(cleanupFailure == nil)
        try await checkUnmount(registry)
        try checkCredentials()
        try checkCommandTimeout()
        print("PASS: mount path, rollback, duplicates, credential preservation, unmount retry, command timeout")
    }

    private static func checkUnmount(_ registry: MountRegistry) async throws {
        let mountpoint = "/Volumes/Actual name 2"
        var invocations: [[String]] = []
        var removed = false
        do {
            try await registry.unmount(
                mountpoint: mountpoint,
                clientAuditToken: Data(),
                clientTeamId: "test",
                detach: {
                    try DiskutilUnmount.detach(mountpoint) {
                        invocations.append($0)
                        return 1
                    }
                },
                removeCredential: { _ in removed = true }
            )
            fatalError("Both diskutil failures must propagate")
        } catch {
            precondition((error as NSError).localizedDescription.contains("force unmount failed"))
        }
        precondition(invocations == [["unmount", mountpoint], ["unmount", "force", mountpoint]])
        precondition(!removed)
        let retained = await registry.get(mountpoint: mountpoint)
        precondition(retained != nil, "Failed detachment must retain retry state")

        try await registry.unmount(
            mountpoint: mountpoint,
            clientAuditToken: Data(),
            clientTeamId: "test",
            detach: {
                try DiskutilUnmount.detach(mountpoint) { arguments in
                    arguments.contains("force") ? 0 : 1
                }
            },
            removeCredential: { path in
                precondition(path == "/test/failure")
                removed = true
            }
        )
        precondition(removed)
        let gone = await registry.get(mountpoint: mountpoint)
        precondition(gone == nil)

        do {
            try await registry.unmount(
                mountpoint: "/Volumes/Concurrent",
                clientAuditToken: Data(),
                clientTeamId: "test",
                detach: {},
                removeCredential: { _ in throw TestFailure.cleanup }
            )
            fatalError("Credential cleanup failure must propagate")
        } catch TestFailure.cleanup {}
        try await registry.unmount(
            mountpoint: "/Volumes/Concurrent",
            clientAuditToken: Data(),
            clientTeamId: "test",
            detach: { fatalError("Already detached mount must not be unmounted again") },
            removeCredential: { _ in }
        )
    }

    private static func checkCredentials() throws {
        var stored: String? = "existing password"
        let credentials = VaultCredentialTransaction(
            read: {
                guard let stored else { throw KeychainError.notFound }
                return stored
            },
            write: { stored = $0 },
            remove: { stored = nil }
        )
        try credentials.prepare(password: "replacement")
        precondition(stored == "replacement")
        try credentials.rollback()
        precondition(stored == "existing password", "Failed mount must restore prior credentials")

        stored = nil
        try credentials.prepare(password: "new password")
        try credentials.rollback()
        precondition(stored == nil, "Failed mount must remove a newly created credential")

        let locked = VaultCredentialTransaction(
            read: { throw KeychainError.unhandled(-25293) },
            write: { _ in fatalError("Read errors must not overwrite credentials") },
            remove: { fatalError("Read errors must not remove credentials") }
        )
        do {
            try locked.prepare(password: "new")
            fatalError("Credential retrieval errors must propagate")
        } catch KeychainError.unhandled {}
        try locked.rollback()

        var writes = 0
        let failedWrite = VaultCredentialTransaction(
            read: { "existing" },
            write: { _ in
                writes += 1
                throw TestFailure.mount
            },
            remove: { fatalError("Failed atomic update must not delete existing credentials") }
        )
        do {
            try failedWrite.prepare(password: "new")
            fatalError("Credential write errors must propagate")
        } catch TestFailure.mount {}
        try failedWrite.rollback()
        precondition(writes == 1, "Failed atomic update needs no rollback write")
    }

    private static func checkCommandTimeout() throws {
        let start = ProcessInfo.processInfo.systemUptime
        do {
            _ = try DiskutilUnmount.runCommand(
                arguments: ["2"],
                executable: URL(fileURLWithPath: "/bin/sleep"),
                timeout: 0.05
            )
            fatalError("Unresponsive commands must time out")
        } catch {
            precondition((error as NSError).domain == NSPOSIXErrorDomain)
            precondition((error as NSError).code == Int(ETIMEDOUT))
        }
        precondition(ProcessInfo.processInfo.systemUptime - start < 1)
    }
}
