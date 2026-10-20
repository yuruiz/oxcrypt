import Foundation

/// Restores the credential that existed before a failed mount attempt.
final class VaultCredentialTransaction {
    private let read: () throws -> String
    private let write: (String) throws -> Void
    private let remove: () throws -> Void
    private var previous: String?
    private var attemptedWrite = false

    init(
        read: @escaping () throws -> String,
        write: @escaping (String) throws -> Void,
        remove: @escaping () throws -> Void
    ) {
        self.read = read
        self.write = write
        self.remove = remove
    }

    func prepare(password: String) throws {
        do {
            previous = try read()
        } catch KeychainError.notFound {
            previous = nil
        }
        // A write may be followed by a failing mount, so retain the old value.
        try write(password)
        attemptedWrite = true
    }

    func rollback() throws {
        guard attemptedWrite else { return }
        if let previous {
            try write(previous)
        } else {
            try remove()
        }
        attemptedWrite = false
    }
}
