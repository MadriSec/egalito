#include <iostream>
#include <stdexcept>
#include <string>

#include "chunk/concrete.h"
#include "conductor/interface.h"
#include "instr/concrete.h"
#include "pass/instrumentcalls.h"
#include "pass/switchcontext.h"

int main(int argc, char **argv) {
    if(argc != 3) {
        std::cerr << "usage: " << argv[0] << " input-elf output-elf\n";
        return 2;
    }

    try {
        EgalitoInterface egalito(false, false);
        egalito.initializeParsing();
        auto module = egalito.parse(argv[1]);
        auto functions = CIter::named(module->getFunctionList());
        auto advice = functions->find("entryAdvice");
        auto mainFunction = functions->find("main");
        if(!advice || !mainFunction) {
            throw std::runtime_error("entryAdvice or main was not found");
        }

        SwitchContextPass switcher;
        advice->accept(&switcher);

        InstrumentCallsPass instrumenter;
        instrumenter.setEntryAdvice(advice);
        instrumenter.setPredicate([](Function *function) {
            return function->getName() == "main";
        });
        module->accept(&instrumenter);

        int insertedCalls = 0;
        for(auto block : CIter::children(mainFunction)) {
            for(auto instruction : CIter::children(block)) {
                auto controlFlow = dynamic_cast<ControlFlowInstruction *>(
                    instruction->getSemantic());
                if(controlFlow && controlFlow->getLink()
                    && controlFlow->getLink()->getTarget() == advice) {
                    ++insertedCalls;
                }
            }
        }
        if(insertedCalls != 1) {
            throw std::runtime_error("expected one inserted call to entryAdvice");
        }

        egalito.generate(argv[2], false);
        std::cout << "inserted_calls=" << insertedCalls << '\n';
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
