/** Temporary test file while iterating on gtirb's IR serialization */
#include <iostream>
#include <functional>
#include <string>
#include "etgtirb.h"
#include "gtirb/gtirb_serializer.h"

void GtirbApp::parse(const std::string &filename, bool include_dependencies) {
    egalito = new EgalitoInterface(true, true);

    std::cout << "Transforming file [" << filename << "]\n";

    try {
        egalito->initializeParsing();

        if(!include_dependencies) {
            std::cout << "Parsing ELF file...\n";
        }
        else {
            std::cout << "Parsing ELF file and all shared library dependencies...\n";
        }
        egalito->parse(filename, include_dependencies);
        // egalito->prepareForGeneration(include_dependencies);
        // egalito->generate(".tmp");
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

void GtirbApp::generate(const std::string &output) {

    std::cout << "Performing code generation into [" << output << "]...\n";
    GtirbSerializer serializer;
    serializer.serialize(getProgram(), output);
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] [mode] input-file output-file\n"
        "    Uses egalito to parse a binary and generate a gtirb IR file.\n"
        "         Creates 'OUTPUT_FILE.json' and 'OUTPUT_FILE.gtirb' containing"
        "         human-readable and protobuf-formatted IR, respectively."
        "\n"
        "Options:\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "\n"
        "Modes:\n"
        "    --deep         include dependencies in parsing\n";
}

void GtirbApp::run(int argc, char **argv) {
    bool includeDeps = false;

    const struct {
        const char *str;
        std::function<void ()> action;
    } actions[] = {
        // should we show debugging log messages?
        {"-v", [this] () { quiet = false; }},
        {"-q", [this] () { quiet = true; }},

        // Whether to attempt to parse included libraries
        {"--deep", [&includeDeps] () { includeDeps = true; }},
    };

    for(int a = 1; a < argc-1; a ++) {
        const char *arg = argv[a];
        if(arg[0] == '-') {
            bool found = false;
            for(auto action : actions) {
                if(std::strcmp(arg, action.str) == 0) {
                    action.action();
                    found = true;
                    break;
                }
            }
            if(!found) {
                std::cout << "Warning: unrecognized option \"" << arg << "\"\n";
                break;
            }
        }
    }
    parse(argv[argc-2], includeDeps);
    generate(argv[argc-1]);
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "etgtirb");
        return 0;
    }

    GtirbApp app;
    app.run(argc, argv);
    return 0;
}
