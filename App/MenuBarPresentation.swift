import AppKit
import SwiftUI

/// Tracks only this popup's host window, never whichever window happens to be key.
@MainActor
final class MenuBarPresentation {
    weak var window: NSWindow?

    func perform(_ action: @escaping @MainActor () async -> Void) {
        let popup = window
        Task { @MainActor in
            // Let the native action menu finish tracking before hiding its parent.
            await Task.yield()
            popup?.orderOut(nil)
            NSApp.activate(ignoringOtherApps: true)
            await action()
        }
    }
}

struct MenuBarWindowReader: NSViewRepresentable {
    let presentation: MenuBarPresentation

    func makeNSView(context: Context) -> WindowProbe {
        let view = WindowProbe()
        view.presentation = presentation
        return view
    }

    func updateNSView(_ view: WindowProbe, context: Context) {
        view.presentation = presentation
        presentation.window = view.window
    }

    final class WindowProbe: NSView {
        weak var presentation: MenuBarPresentation?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            presentation?.window = window
        }
    }
}
