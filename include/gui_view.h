#ifndef PORTSCANNER_GUI_VIEW_H
#define PORTSCANNER_GUI_VIEW_H

#include "scan_controller.h"

namespace GuiView {

    // Apply premium Dark Slate design system (Glassmorphism & Harmonious Palettes)
    void setup_theme();

    // Render MVC GUI frame
    void render_ui(ScanController& controller);

} // namespace GuiView

#endif // PORTSCANNER_GUI_VIEW_H
