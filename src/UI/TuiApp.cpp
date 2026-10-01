#include "UI/TuiApp.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "Version.h"

using namespace ftxui;

namespace WinLpeAuditor::UI {

namespace {

// ---- Palette (shadcn "zinc" dark theme + indigo accent) ----------------

Color Bg()          { return Color::RGB(9, 9, 11); }      // zinc-950
Color CardBg()       { return Color::RGB(16, 16, 19); }    // zinc-925-ish
Color Border()       { return Color::RGB(39, 39, 42); }    // zinc-800
Color Fg()           { return Color::RGB(250, 250, 250); } // zinc-50
Color MutedFg()      { return Color::RGB(161, 161, 170); } // zinc-400
Color FaintFg()      { return Color::RGB(113, 113, 122); } // zinc-500
Color Accent()       { return Color::RGB(129, 140, 248); } // indigo-400

Color DestructiveFg(){ return Color::RGB(248, 113, 113); } // red-400
Color DestructiveBg(){ return Color::RGB(50, 16, 16); }
Color WarningFg()    { return Color::RGB(250, 204, 21); }  // yellow-400
Color WarningBg()    { return Color::RGB(48, 38, 10); }
Color InfoFg()       { return Color::RGB(96, 165, 250); }  // blue-400
Color InfoBg()       { return Color::RGB(14, 26, 48); }
Color SuccessFg()    { return Color::RGB(74, 222, 128); }  // green-400
Color MutedBg()      { return Color::RGB(39, 39, 42); }    // zinc-800

std::pair<Color, Color> SeverityColors(Severity s) {  // {fg, bg}
    switch (s) {
        case Severity::Critical: return {DestructiveFg(), DestructiveBg()};
        case Severity::High:     return {DestructiveFg(), DestructiveBg()};
        case Severity::Medium:   return {WarningFg(), WarningBg()};
        case Severity::Low:      return {InfoFg(), InfoBg()};
        case Severity::Info:
        default:                 return {MutedFg(), MutedBg()};
    }
}

std::string SeverityLabel(Severity s) {
    switch (s) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High:     return "HIGH";
        case Severity::Medium:   return "MEDIUM";
        case Severity::Low:      return "LOW";
        case Severity::Info:
        default:                 return "INFO";
    }
}
    
Element RenderAnimatedHeader(int tick) {
    std::string title = "WinLpeAuditor";
    Elements letters;

    for (size_t i = 0; i < title.length(); ++i) {
        double wave = std::sin(tick * 0.15 + i * 0.4); 
        
        double intensity = 0.67 + (wave * 0.33);

        int r = static_cast<int>(129 * intensity);
        int g = static_cast<int>(140 * intensity);
        int b = static_cast<int>(248 * intensity);

        r = std::clamp(r, 40, 255);
        g = std::clamp(g, 40, 255);
        b = std::clamp(b, 80, 255);

        Color accentShimmer = Color::RGB(r, g, b);
        
        letters.push_back(text(std::string(1, title[i])) | bold | color(accentShimmer));
    }

    return hbox(std::move(letters));
}

Element Badge(const std::string& label, Color fg, Color bg) {
    return text(" " + label + " ") | bold | color(fg) | bgcolor(bg);
}

Element SeverityBadge(Severity s) {
    auto [fg, bg] = SeverityColors(s);
    return Badge(SeverityLabel(s), fg, bg);
}

Element Kbd(const std::string& key) {
    return text(" " + key + " ") | bold | color(Fg()) | bgcolor(MutedBg());
}

Element Card(Element content) {
    return content | borderStyled(ROUNDED) | color(Border()) | bgcolor(CardBg());
}

Element Dot(Color c) { return text("●") | color(c); }

const std::array<std::string, 10> kSpinnerFrames = {
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
};

Element ProgressBar(double fraction, int width) {
    fraction = std::clamp(fraction, 0.0, 1.0);
    int filled = static_cast<int>(fraction * width + 0.5);
    Elements segs;
    for (int i = 0; i < width; ++i) {
        segs.push_back(text(i < filled ? "█" : "░") | color(i < filled ? Accent() : Border()));
    }
    return hbox(std::move(segs));
}

}  // namespace
    
enum class View { Checks, About };

void TuiApp::Run() {
    std::cout << "\033]0;WinLpeAuditor - Windows Local Privilege Escalation Auditor\007" << std::flush;
    
    const auto& checks = engine_.Checks();
    const size_t count = checks.size();

    std::vector<CheckResult> results(count);
    std::vector<bool> hasRun(count, false);
    int selectedIndex = 0;
    std::atomic<bool> running{false};
    double progress = 0.0;
    std::string statusText = "Ready.";
    std::mutex stateMutex;
    
    View currentView = View::Checks;

    std::atomic<int> animationTick{0};
    std::atomic<bool> appActive{true};

    auto screen = ScreenInteractive::Fullscreen();
    
    std::thread animationThread([&] {
        while (appActive.load()) {
            animationTick++;
            screen.PostEvent(Event::Custom);
            std::this_thread::sleep_for(std::chrono::milliseconds(60)); // ~30ms für geschmeidige Übergänge
        }
    });

    auto runAudit = [&] {
        bool expected = false;
        if (!running.compare_exchange_strong(expected, true)) return;

        std::thread([&] {
            std::vector<size_t> indices(count);
            for (size_t i = 0; i < count; ++i) indices[i] = i;

            auto finalResults = engine_.RunAll(indices, [&](size_t done, size_t total, const ICheck& check) {
                std::lock_guard<std::mutex> lock(stateMutex);
                statusText = "Running " + check.Name();
                progress = static_cast<double>(done) / static_cast<double>(total);
            });

            {
                std::lock_guard<std::mutex> lock(stateMutex);
                size_t totalFindings = 0;
                for (size_t i = 0; i < count; ++i) {
                    results[i] = finalResults[i];
                    hasRun[i] = true;
                    totalFindings += results[i].findings.size();
                }
                statusText = std::to_string(totalFindings) + " finding(s) found across all checks.";
                progress = 1.0;
            }
            running = false;
            screen.PostEvent(Event::Custom);
        }).detach();
    };

    auto renderSidebar = [&]() -> Element {
        std::lock_guard<std::mutex> lock(stateMutex);
        Elements rows;
        for (size_t i = 0; i < count; ++i) {
            Color dot = FaintFg();
            if (hasRun[i]) {
                if (!results[i].ranSuccessfully) dot = DestructiveFg();
                else if (!results[i].findings.empty()) dot = WarningFg();
                else dot = SuccessFg();
            }

            bool selected = static_cast<int>(i) == selectedIndex;
            Element row = hbox({
                text(selected ? "▍" : " ") | color(Accent()),
                text(" "),
                Dot(dot),
                text(" " + checks[i]->Name()),
            });
            row = row | color(selected ? Fg() : MutedFg());
            if (selected) row = row | bgcolor(Color::RGB(24, 24, 28)) | bold;
            rows.push_back(row);
        }
        return Card(vbox({
            text(" CHECKS") | color(FaintFg()) | bold,
            text(""),
            vbox(std::move(rows)),
            filler(),
        })) | size(WIDTH, EQUAL, 36);
    };
    
    auto renderTabs = [&]() -> Element {
        auto tab = [&](const std::string& label, View v) {
            bool active = currentView == v;
            Element inner = hbox({text(label)}) | bold;
            if (active) {
                return inner | color(Color::RGB(9, 9, 11)) | bgcolor(Accent());
            }
            return inner | color(FaintFg());
        };

        return hbox({
                   text(" "),
                   tab("Checks", View::Checks),
                   text("    "),
                   tab("About", View::About),
                   text(" "),
               }) |
               borderStyled(ROUNDED) | color(Border()) | bgcolor(CardBg());
    };

    auto renderAbout = [&]() -> Element {
        Elements content;

        content.push_back(text(""));
        content.push_back(hcenter(RenderAnimatedHeader(animationTick.load())));
        content.push_back(hcenter(text("Windows LPE misconfiguration audit") | color(FaintFg())));
        content.push_back(text(""));
        content.push_back(hcenter(Badge(std::string("v") + WinLpeAuditor::kVersion, Accent(), MutedBg())));
        content.push_back(text(""));
        content.push_back(paragraphAlignCenter(
            "A modular Windows local-privilege-escalation misconfiguration auditor. "
            "Scans for common LPE vectors such as unquoted service paths and "
            "AlwaysInstallElevated.") | color(MutedFg()));
        content.push_back(text(""));
        content.push_back(separator() | color(Border()));
        content.push_back(text(""));

        auto infoRow = [&](const std::string& label, Element value) {
            return hbox({
                text(label) | color(FaintFg()) | size(WIDTH, EQUAL, 16),
                value,
            });
        };

        content.push_back(hcenter(vbox({
            infoRow("Created by", text(WinLpeAuditor::kAuthor) | color(Fg()) | bold),
            text(""),
            infoRow("GitHub", text(WinLpeAuditor::kGithubUrl) | color(InfoFg()) | underlined),
            text(""),
            infoRow("Checks loaded", text(std::to_string(count)) | color(Fg())),
            text(""),
            infoRow("Built with", text("FTXUI, CMake, MSVC") | color(Fg())),
        })));

        content.push_back(text(""));
        content.push_back(separator() | color(Border()));
        content.push_back(text(""));
        content.push_back(hcenter(text("KEYBINDINGS") | bold | color(FaintFg())));
        content.push_back(text(""));
        content.push_back(hcenter(hbox({
            Kbd("tab"), text("  switch view    ") | color(FaintFg()),
            Kbd("r"),   text("  run checks    ") | color(FaintFg()),
            Kbd("↑/↓"), text("  navigate    ") | color(FaintFg()),
            Kbd("q"),   text("  quit") | color(FaintFg()),
        })));
        content.push_back(filler());

        return Card(vbox(std::move(content)) | flex) | flex;
    };

    auto renderDetails = [&]() -> Element {
        std::lock_guard<std::mutex> lock(stateMutex);
        if (selectedIndex < 0 || static_cast<size_t>(selectedIndex) >= count) {
            return Card(text("No check selected.") | color(MutedFg())) | flex;
        }

        const auto& check = *checks[selectedIndex];
        Elements content;
        content.push_back(text(check.Name()) | bold | color(Fg()));
        content.push_back(text(""));
        content.push_back(paragraph(check.Description()) | color(MutedFg()));
        content.push_back(text(""));
        content.push_back(separator() | color(Border()));
        content.push_back(text(""));

        if (!hasRun[selectedIndex]) {
            content.push_back(Badge("PENDING", FaintFg(), MutedBg()));
            return Card(vbox(std::move(content)) | flex) | flex;
        }

        const auto& result = results[selectedIndex];
        if (!result.ranSuccessfully) {
            content.push_back(hbox({Badge("ERROR", DestructiveFg(), DestructiveBg()),
                                     text("  " + result.errorMessage) | color(MutedFg())}));
            return Card(vbox(std::move(content)) | flex) | flex;
        }

        if (result.findings.empty()) {
            content.push_back(Badge("CLEAN", SuccessFg(), MutedBg()));
            return Card(vbox(std::move(content)) | flex) | flex;
        }

        for (size_t i = 0; i < result.findings.size(); ++i) {
            const auto& finding = result.findings[i];
            content.push_back(hbox({SeverityBadge(finding.severity), text("  " + finding.title) | bold | color(Fg())}));
            for (const auto& detail : finding.details) {
                content.push_back(hbox({text("   " + detail.first + "  ") | color(FaintFg()),
                                         text(detail.second) | color(MutedFg())}));
            }
            if (i + 1 < result.findings.size()) content.push_back(text(""));
        }

        return Card(vbox(std::move(content)) | vscroll_indicator | frame | flex) | flex;
    };

    auto renderSummary = [&]() -> Element {
        std::lock_guard<std::mutex> lock(stateMutex);
        size_t counts[5] = {0, 0, 0, 0, 0};
        bool anyRun = false;
        for (size_t i = 0; i < count; ++i) {
            if (!hasRun[i] || !results[i].ranSuccessfully) continue;
            anyRun = true;
            for (const auto& f : results[i].findings) counts[static_cast<int>(f.severity)]++;
        }
        if (!anyRun) return text("");

        return hbox({
            Badge("CRITICAL " + std::to_string(counts[4]), DestructiveFg(), DestructiveBg()), text(" "),
            Badge("HIGH " + std::to_string(counts[3]), DestructiveFg(), DestructiveBg()), text(" "),
            Badge("MEDIUM " + std::to_string(counts[2]), WarningFg(), WarningBg()), text(" "),
            Badge("LOW " + std::to_string(counts[1]), InfoFg(), InfoBg()),
        });
    };

    int tick = 0;

    auto rootComponent = Renderer([&] {
        ++tick;

        std::string currentStatus;
        double currentProgress;
        bool isRunning = running.load();
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            currentStatus = statusText;
            currentProgress = progress;
        }

        auto header = hbox({
            vbox({
                RenderAnimatedHeader(animationTick.load()),
                text("Windows LPE misconfiguration audit") | color(FaintFg()),
                filler(),
                text(std::string("v") + WinLpeAuditor::kVersion) | color(FaintFg())
            }),
            filler(),
            Badge(std::to_string(count) + " CHECKS", MutedFg(), MutedBg()),
        });

        auto body = currentView == View::Checks
            ? hbox({renderSidebar(), text(" "), renderDetails()}) | flex
            : hbox({renderAbout()}) | flex;

        Element footerStatus = text(currentStatus) | color(MutedFg()) | flex;
        Element footerRight = text("");
        if (isRunning) {
            footerRight = hbox({
                text(kSpinnerFrames[tick % kSpinnerFrames.size()]) | color(Accent()) | bold,
                text("  "),
                ProgressBar(currentProgress, 20),
            });
        }
        auto footer = hbox({footerStatus, footerRight});

        auto hints = currentView == View::Checks
            ? hbox({
                  Kbd("r"), text(" run   ") | color(FaintFg()),
                  Kbd("↑/↓"), text(" navigate   ") | color(FaintFg()),
                  Kbd("tab"), text(" about   ") | color(FaintFg()),
                  Kbd("q"), text(" quit") | color(FaintFg()),
              })
            : hbox({
                  Kbd("tab"), text(" back   ") | color(FaintFg()),
                  Kbd("q"), text(" quit") | color(FaintFg()),
              });

        return vbox({
                   header,
                   text(""),
                   renderTabs(),
                   text(""),
                   renderSummary(),
                   text(""),
                   body,
                   text(""),
                   footer,
                   text(""),
                   hints,
               }) |
               bgcolor(Bg()) | color(Fg());
    });

    rootComponent |= CatchEvent([&](Event event) {
        if (event == Event::Tab) {
            currentView = (currentView == View::Checks) ? View::About : View::Checks;
            return true;
        }
        if (event == Event::Character('q') || event == Event::Character('Q') || event == Event::Escape) {
            screen.ExitLoopClosure()();
            return true;
        }
        if (currentView != View::Checks) {
            return false;
        }
        if (event == Event::Character('r') || event == Event::Character('R')) {
            runAudit();
            return true;
        }
        if (event == Event::ArrowUp || event == Event::Character('k')) {
            selectedIndex = std::max(0, selectedIndex - 1);
            return true;
        }
        if (event == Event::ArrowDown || event == Event::Character('j')) {
            selectedIndex = std::min(static_cast<int>(count) - 1, selectedIndex + 1);
            return true;
        }
        return false;
    });

    screen.Loop(rootComponent);
    
    appActive = false;
    if (animationThread.joinable()) {
        animationThread.join();
    }
}

}