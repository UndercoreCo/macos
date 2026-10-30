public struct ConnectionHealth: Sendable {
    public private(set) var result: VPNDiagnosticCode.Health?
    public init() {}
    public mutating func receive(_ code: VPNDiagnosticCode) -> Bool {
        guard case .health(let value) = code else { return false }
        result = value
        return true
    }
    public mutating func receive(_ wireValue: String) -> Bool {
        guard let code = VPNDiagnosticCode(wireValue: wireValue) else { return false }
        return receive(code)
    }
    public var state: VPNState {
        switch result {
        case .unavailable: return .unverified
        case .ok: return .connected
        case .dns, .route, .degraded, .network_unavailable, .source_unconfirmed, .name_unavailable, .egress_unconfirmed, .tunnel_unreachable: return .degraded
        default: return .checking }
    }
    public var message: String {
        switch result {
        case .unavailable: return "Туннель запущен. Проверка доступа к интернету пока недоступна для этого VPN-компонента."
        case .ok: return ""
        case .dns: return "Не удалось разрешить имена проверочных сайтов. VPN остаётся включённым."
        case .network_unavailable: return "Сеть недоступна. Ждём её возвращения."
        case .source_unconfirmed: return "Доступ не подтверждён ни через VPN, ни напрямую. Проверяем сеть."
        case .name_unavailable: return "VPN передаёт данные. Проверочные сайты по имени пока недоступны."
        case .egress_unconfirmed: return "VPN-сервер отвечает, но доступ к проверочным сайтам не подтверждён."
        case .tunnel_unreachable: return "Сеть доступна, но VPN не отвечает. Восстанавливаем подключение…"
        case .route: return "Маршрут VPN нарушен. Отключитесь и подключитесь ещё раз."
        case .degraded: return "Туннель подключён, но доступ к интернету не подтверждён. Повторяем проверку."
        default: return "Проверяем доступ к интернету…"
        }
    }
}
