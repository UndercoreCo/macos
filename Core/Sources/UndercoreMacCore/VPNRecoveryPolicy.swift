import Foundation

public enum VPNRecoveryEvent: Sendable { case required, attemptFailed, restored, unavailable, checking, inconclusive }
public enum VPNRecoveryError: Error { case unavailable }

/// Transport-free policy driven by monotonic seconds; deterministic without real networking.
public struct VPNRecoveryPolicy {
    public enum Action: Equatable { case none, retry, stop }
    public private(set) var enabled = false
    public private(set) var recovering = false
    public private(set) var attempts = 0
    public private(set) var sleeping = false
    private var resumeNotBefore: TimeInterval = 0
    private var deadline: TimeInterval?
    private var nextAttempt: TimeInterval = 0
    private var attemptStarted: TimeInterval?
    private var healthySince: TimeInterval?
    private let delays: [TimeInterval] = [2, 5, 15]
    public init() {}

    public mutating func start() { self = Self(); enabled = true }
    public mutating func cancel() { self = Self() }
    public mutating func setSleeping(_ value: Bool, at now: TimeInterval) {
        if sleeping && !value { resumeNotBefore = now + 15 }
        sleeping = value
    }
    public mutating func receive(_ event: VPNRecoveryEvent, at now: TimeInterval) {
        guard enabled else { return }
        switch event {
        case .unavailable: cancel()
        case .checking:
            // A live diagnostic batch needs time to complete before another retry.
            // The overall deadline still bounds a stuck extension.
            if recovering, attemptStarted != nil { attemptStarted = now }
        case .inconclusive:
            // Uncertainty does not justify disrupting a running tunnel. Preserve
            // the attempt budget, but wait for new positive failure evidence.
            recovering = false; deadline = nil; attemptStarted = nil; healthySince = nil
        case .restored:
            recovering = false
            deadline = nil
            attemptStarted = nil
            if healthySince == nil { healthySince = now }
        case .required, .attemptFailed:
            if let healthySince, now - healthySince >= 60 { attempts = 0 }
            healthySince = nil
            if !recovering {
                recovering = true
                deadline = now + 420
                nextAttempt = now + delays[min(attempts, delays.count - 1)]
            }
            if case .attemptFailed = event {
                attemptStarted = nil
                nextAttempt = now + delays[min(attempts, delays.count - 1)]
            }
        }
    }
    public mutating func preparationCompleted(at now: TimeInterval) {
        if recovering, attemptStarted != nil { attemptStarted = now }
    }
    public mutating func tick(at now: TimeInterval, networkAvailable: Bool, canReconnect: Bool) -> Action {
        guard enabled, recovering, !sleeping, now >= resumeNotBefore else { return .none }
        if !canReconnect || now >= (deadline ?? now) { cancel(); return .stop }
        if let started = attemptStarted {
            guard now - started >= 40 else { return .none }
            attemptStarted = nil
            nextAttempt = now + delays[min(attempts, delays.count - 1)]
        }
        if attempts >= delays.count { cancel(); return .stop }
        guard networkAvailable, now >= nextAttempt else { return .none }
        attempts += 1
        attemptStarted = now
        return .retry
    }
}
