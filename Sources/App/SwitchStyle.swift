import SwiftUI

/// The one switch used everywhere in the App (DESIGN.md §21.14).
///
/// The system switch draws itself grey whenever its window is not the
/// active one, so in the menu-bar panel an ON switch looked OFF (user
/// report, twice). This draws the state itself: accent-coloured track
/// when on, grey when off, the same in active and inactive windows. A
/// hidden label (labelsHidden) is honoured; otherwise label left,
/// switch right, as in System Settings rows.
struct AlwaysSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 8) {
            configuration.label
            Spacer(minLength: 8)
            AlwaysSwitchTrack(isOn: configuration.$isOn)
        }
    }
}

/// The switch itself, also on its own where a label would take room
/// (the panel's tiles).
struct AlwaysSwitchTrack: View {
    @Binding var isOn: Bool
    var width: CGFloat = 34
    var height: CGFloat = 20
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        ZStack(alignment: isOn ? .trailing : .leading) {
            Capsule()
                .fill(isOn ? Color.accentColor : Color.secondary.opacity(0.32))
            Circle()
                .fill(Color.white)
                .shadow(color: .black.opacity(0.25), radius: 1, y: 0.5)
                .padding(2)
        }
        .frame(width: width, height: height)
        .opacity(isEnabled ? 1 : 0.45)
        .animation(.easeOut(duration: 0.15), value: isOn)
        .contentShape(Capsule())
        .onTapGesture { if isEnabled { isOn.toggle() } }
        .accessibilityElement()
        .accessibilityLabel("开关")
        .accessibilityValue(isOn ? "开" : "关")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { if isEnabled { isOn.toggle() } }
    }
}

extension ToggleStyle where Self == AlwaysSwitchStyle {
    static var always: AlwaysSwitchStyle { AlwaysSwitchStyle() }
}
