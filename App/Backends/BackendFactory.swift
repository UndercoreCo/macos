import UndercoreMacCore

@MainActor
enum BackendFactory {
    static func make() -> any VPNBackend {
        #if USE_NETWORK_EXTENSION
        return NetworkExtensionBackend()
        #else
        return StandaloneBackend()
        #endif
    }
}

