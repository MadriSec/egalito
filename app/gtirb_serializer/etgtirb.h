#ifndef EGALITO_APP_HARDEN_H
#define EGALITO_APP_HARDEN_H

#include "conductor/interface.h"

class GtirbApp {
private:
    EgalitoInterface *egalito;
    bool quiet;

public:
    GtirbApp() {}
    void run(int argc, char **argv);
    void parse(const std::string &filename, bool includeDependences);
    void generate(const std::string &filename);
    Program *getProgram() const { return egalito->getProgram(); }
};

#endif
