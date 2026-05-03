// decided to make this on linux for some reason lol

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <format>

#include "mappedfile.h"
#include "parser.h"

#include <ftxui/component/component_base.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

using namespace ftxui;

Element RenderHeaders(const PEParser& pe) {
    auto nt = pe.NtHeaders();
    auto& opt = nt->OptionalHeader;


    auto timestamp = std::chrono::sys_seconds(
        std::chrono::seconds(nt->FileHeader.TimeDateStamp)
    );
    std::string time = std::format("{:%Y-%m-%d %H:%M:%S}", timestamp);

    auto table = Table({
        { "field",        "value"                          },
        { "magic",        opt.Magic == 0x20B ? "PE32+" : "PE32" },
        { "entry point",  std::format("0x{:08X}", opt.AddressOfEntryPoint) },
        { "image base",   std::format("0x{:016X}", opt.ImageBase) },
        { "subsystem",    std::format("{}", opt.Subsystem)  },
        { "sections",     std::format("{}", nt->FileHeader.NumberOfSections) },
        { "timestamp",    std::format("{}", time) },
    });

    table.SelectAll().Border(LIGHT);
    table.SelectRow(0).Decorate(bold);
    table.SelectColumn(0).Decorate(color(Color::Yellow));

    return table.Render();
}

Element RenderSections(const PEParser& pe) {
    auto sections = pe.Sections();
    std::vector<std::vector<std::string>> rows;
    rows.push_back({
        std::format("{:<12}", "name"),
        std::format("{:<14}", "virtaddr"),
        std::format("{:<14}", "virtsize"),
        std::format("{:<14}", "rawsize"),
        "flags",
        "entropy"
    });

    for (auto& section : sections) {

        std::string name( reinterpret_cast<const char*>(section.Name), 
        strnlen(reinterpret_cast<const char*>(section.Name), 8));
        std::string flags;
        flags += (section.Characteristics & IMAGE_SCN_MEM_READ)    ? 'r' : '-';
        flags += (section.Characteristics & IMAGE_SCN_MEM_WRITE)   ? 'w' : '-';
        flags += (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-';
        
        std::span<const std::byte> rawData = pe.SectionData(section);
        float entropy = pe.Entropy(rawData);

        rows.push_back({
        std::format("{:<12}", name),
        std::format("{:<14}", std::format("0x{:08X}", section.VirtualAddress)),
        std::format("{:<14}", std::format("0x{:08X}", section.Misc.VirtualSize)),
        std::format("{:<14}", std::format("0x{:08X}", section.SizeOfRawData)),
        std::format("{:<8}", flags),
        std::format("{:.2f}", entropy)
        });
    }

    auto table = Table(rows);
    table.SelectAll().Border(LIGHT);
    table.SelectRow(0).Decorate(bold);
    return table.Render();
}

Component RenderImports(const PEParser& pe) {
    auto entries = std::make_shared<std::vector<std::string>>();
    auto imports = pe.Imports();

    for (auto& import : imports) {
        entries->push_back(import.dllName);
        for (auto& fn : import.functions) // epstein fuck niggers
            entries->push_back("  " + fn);
        entries->push_back("");
    }

    auto selected = std::make_shared<int>(0);
    auto menu = Menu(entries.get(), selected.get());

    return Renderer(menu, [menu, entries, selected] {
        return menu->Render() | vscroll_indicator | frame | flex;
    });
}

Element RenderExports(const PEParser& pe) {
    
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << std::format("usage: {} <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    MappedFile file(argv[1]);
    PEParser pe(file);

    int tab = 0;
    std::vector<std::string> tabNames = {"headers", "sections", "imports", "exports"};
    auto tabToggle = Toggle(&tabNames, &tab);

    auto tabContent = Container::Tab({
        Renderer([&]{ return RenderHeaders(pe); }),
        Renderer([&] { return RenderSections(pe); }),
        RenderImports(pe),
        Renderer([&] { return text("i cba to make this rn bro"); })
    }, &tab);

    auto layout = Container::Vertical({ tabToggle, tabContent });

    auto ui = Renderer(layout, [&] {
        return vbox({
            text(std::format(" peparser - {}", argv[1])) | bold,
            separator(),
            tabToggle->Render(),
            separator(),
            tabContent->Render() | frame | flex,
        }) | border;
    });

    ScreenInteractive::Fullscreen().Loop(ui);
}