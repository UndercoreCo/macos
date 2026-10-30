#if USE_NETWORK_EXTENSION
import Foundation
import SystemExtensions

@MainActor
final class ExtensionActivation: NSObject, OSSystemExtensionRequestDelegate {
    private var pendingRequest: OSSystemExtensionRequest?
    private var continuation: CheckedContinuation<Void, Error>?
    var awaitingApproval: (() -> Void)?

    func activate() async throws {
        guard continuation == nil else { throw Failure.systemExtension }
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: NetworkExtensionBackend.providerID, queue: .main)
            pendingRequest = request
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func cancel() {
        pendingRequest = nil
        let pending = continuation; continuation = nil
        pending?.resume(throwing: CancellationError())
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            guard self.pendingRequest === request else { return }
            self.awaitingApproval?()
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                            actionForReplacingExtension existing: OSSystemExtensionProperties,
                            withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            guard self.pendingRequest === request else { return }
            self.pendingRequest = nil
            let pending = self.continuation
            self.continuation = nil
            if result == .completed { pending?.resume() }
            else { pending?.resume(throwing: Failure.systemExtension) }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            guard self.pendingRequest === request else { return }
            self.pendingRequest = nil
            let pending = self.continuation
            self.continuation = nil
            pending?.resume(throwing: Failure.systemExtension)
        }
    }
}

#endif
