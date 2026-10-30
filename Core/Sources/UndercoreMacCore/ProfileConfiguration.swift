import Foundation
import WireGuardConfiguration

public enum ProfileError: LocalizedError {
    case invalidFile, unsupportedProfile, unsupportedStandaloneProfile
    public var errorDescription: String? {
        switch self {
        case .invalidFile: return "Не удалось прочитать подключение. Выберите файл AmneziaWG (.conf)."
        case .unsupportedStandaloneProfile: return "В файле есть настройки, которые эта версия приложения пока не поддерживает."
        case .unsupportedProfile: return "Этот файл не подходит. Нужна конфигурация с одним VPN-сервером, адресом и маршрутами."
        }
    }
}

public enum ProfileConfiguration {
    public static let maximumBytes = 65_536

    public static func parse(_ data: Data, name: String? = nil) throws -> TunnelConfiguration {
        guard !data.isEmpty, data.count <= maximumBytes,
              let text = String(data: data, encoding: .utf8), !text.contains("\0") else {
            throw ProfileError.invalidFile
        }
        let configuration: TunnelConfiguration
        do {
            configuration = try TunnelConfiguration(fromWgQuickConfig: text, called: name)
        } catch {
            // Upstream errors may contain keys or source lines. Never surface them.
            throw ProfileError.invalidFile
        }
        guard !configuration.interface.addresses.isEmpty, configuration.peers.count == 1,
              configuration.peers[0].endpoint != nil, !configuration.peers[0].allowedIPs.isEmpty else {
            throw ProfileError.unsupportedProfile
        }
        return configuration
    }
}
