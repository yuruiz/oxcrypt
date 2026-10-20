import Darwin
import Foundation

enum DiskutilUnmount {
    static func detach(
        _ mountpoint: String,
        run: ([String]) throws -> Int32 = { try runCommand(arguments: $0) }
    ) throws {
        if try run(["unmount", mountpoint]) == 0 { return }
        let status = try run(["unmount", "force", mountpoint])
        guard status == 0 else {
            throw NSError(
                domain: "com.agucova.oxcrypt.xpc",
                code: OxVaultServiceError.mountFailed.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "diskutil force unmount failed with status \(status); mount remains registered for retry"]
            )
        }
    }

    /// Drain no pipes and bound both graceful and forced commands.
    static func runCommand(
        arguments: [String],
        executable: URL = URL(fileURLWithPath: "/usr/sbin/diskutil"),
        timeout: TimeInterval = 15
    ) throws -> Int32 {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while process.isRunning {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                // Process reaping is handled by Foundation's termination handler.
                kill(process.processIdentifier, SIGKILL)
                throw NSError(
                    domain: NSPOSIXErrorDomain,
                    code: Int(ETIMEDOUT),
                    userInfo: [NSLocalizedDescriptionKey: "diskutil unmount timed out; mount remains registered for retry"]
                )
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        return process.terminationStatus
    }
}
