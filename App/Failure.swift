import Foundation

enum Failure: LocalizedError {
    case systemExtension, preferences, start
    var errorDescription: String? {
        switch self {
        case .systemExtension: return "Не удалось включить VPN-компонент. Проверьте разрешение в системных настройках и подпись приложения."
        case .preferences: return "Не удалось сохранить настройки VPN. Попробуйте ещё раз."
        case .start: return "Не удалось подключиться. Проверьте сеть и попробуйте ещё раз."
        }
    }
}
