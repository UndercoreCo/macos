/// Holds a user-approved installation until an explicit retry at a safe moment.
/// Becoming idle alone never closes the application.
@MainActor
public final class UpdateInstallationGate {
    private var pending: (() -> Void)?
    public var hasPending: Bool { pending != nil }
    public init() {}

    public func postpone(if blocked: Bool, install: @escaping () -> Void) -> Bool {
        guard blocked else { return false }
        pending = install
        return true
    }

    public func resume(ifSafe safe: Bool) {
        guard safe, let install = pending else { return }
        pending = nil
        install()
    }

    public func cancel() { pending = nil }
}
