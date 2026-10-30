import AppKit
import SwiftUI

@main
struct UndercoreApp: App {
    @NSApplicationDelegateAdaptor(UpdateApplicationDelegate.self) private var appDelegate
    @StateObject private var tunnel: TunnelController
    @StateObject private var updates: AppUpdateController

    init() {
        let tunnel = TunnelController()
        _tunnel = StateObject(wrappedValue: tunnel)
        _updates = StateObject(wrappedValue: AppUpdateController(tunnel: tunnel))
    }

    // Set the native image size explicitly: menu-bar labels can ignore SwiftUI fonts.
    private var menuBarIcon: NSImage {
        let configuration = NSImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        guard let image = NSImage(systemSymbolName: tunnel.statusSymbol, accessibilityDescription: "Undercore")?
            .withSymbolConfiguration(configuration) else { return NSImage() }
        let height: CGFloat = 16
        image.size = NSSize(width: image.size.width * height / image.size.height, height: height)
        image.isTemplate = true
        return image
    }

    var body: some Scene {
        MenuBarExtra {
            ConnectionView(tunnel: tunnel, account: tunnel.account)
        } label: {
            Image(nsImage: menuBarIcon)
                .renderingMode(.template)
                .accessibilityLabel("Undercore, \(tunnel.statusText)")
                .help("Undercore — \(tunnel.statusText)")
        }
        .menuBarExtraStyle(.window)
        Window("Аккаунт и настройки", id: "account") {
            AccountView(account: tunnel.account, tunnel: tunnel, updates: updates)
                .onAppear { NSApp.activate(ignoringOtherApps: true) }
        }
        .defaultSize(width: 480, height: 560)
        .windowResizability(.contentMinSize)
    }
}
