import AppKit
import UniformTypeIdentifiers

@MainActor
enum DiagnosticExporter {
    static func save() async -> String? {
        await Task.yield() // Let the menu dismiss before showing a native panel.
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSSavePanel()
        panel.title = "Сохранить диагностику"
        panel.message = "События подключений без ключей, конфигураций и посещённых сайтов. Отчёт никуда не отправляется автоматически."
        panel.nameFieldStringValue = "Undercore-diagnostics.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        do {
            let data = try await ConnectionDiagnostics.shared.export()
            try await Task.detached(priority: .utility) {
                try data.write(to: url, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            }.value
            return "Диагностика сохранена"
        } catch { return "Не удалось сохранить диагностику. Попробуйте выбрать другую папку." }
    }
}
