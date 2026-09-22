#include <exception>
#include <iostream>
#include <set>
#include <string>

#include "analysis/call.h"
#include "chunk/concrete.h"
#include "conductor/interface.h"

static bool isExampleFunction(const std::string &name) {
    return name == "main" || name == "fcg_left"
        || name == "fcg_right" || name == "fcg_leaf";
}

int main(int argc, char **argv) {
    if(argc != 2) {
        std::cerr << "usage: " << argv[0] << " input-elf\n";
        return 2;
    }

    try {
        EgalitoInterface egalito(false, false);
        egalito.initializeParsing();
        egalito.parse(argv[1]);
        CallGraph graph(egalito.getProgram());
        std::set<std::string> edges;

        for(size_t index = 0; index < graph.getCount(); ++index) {
            auto node = graph.get(static_cast<int>(index));
            auto caller = node->getFunction()->getName();
            if(!isExampleFunction(caller)) continue;

            for(auto link : node->downwardLinks()) {
                auto callee = graph.getFunction(link->getTargetID())->getName();
                if(isExampleFunction(callee)) {
                    edges.insert(caller + " -> " + callee);
                }
            }
        }

        for(const auto &edge : edges) std::cout << edge << '\n';
    }
    catch(const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    catch(const char *error) {
        std::cerr << error << '\n';
        return 1;
    }
}
