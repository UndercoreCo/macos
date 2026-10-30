import AppKit

/// Settings links are best-effort: the visible path remains usable if macOS changes them.
@MainActor
enum SystemExtensionSettings {
    static var instructions: String {
        if #available(macOS 15, *) {
            return "Основные → Объекты входа и расширения → Сетевые расширения. Включите Undercore — подключение продолжится автоматически."
        }
        return "Конфиденциальность и безопасность → разрешите расширение Undercore. Подключение продолжится автоматически."
    }

    static func open() {
        let destination: String
        if #available(macOS 15, *) {
            destination = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension?ExtensionItems"
        } else {
            destination = "x-apple.systempreferences:com.apple.preference.security?General"
        }
        if let url = URL(string: destination), NSWorkspace.shared.open(url) { return }
        // Fall back to the app; the on-screen instructions include the full path.
        let app = URL(fileURLWithPath: "/System/Applications/System Settings.app")
        NSWorkspace.shared.openApplication(at: app, configuration: .init())
    }
}
