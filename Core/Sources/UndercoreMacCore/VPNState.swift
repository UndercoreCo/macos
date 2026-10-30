public enum VPNState: String, Sendable {
    case disconnected, connecting, connected, unverified, checking, degraded, reasserting, disconnecting
}
