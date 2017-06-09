#ifndef ASSEMBLER_HPP
#define ASSEMBLER_HPP

#include <iostream>
#include <list>
#include "protocol_headers.h"
#include <mutex>
#include <fstream>
#include <string.h>

class Assembler {
private:
    char* fileName;
    std::list<fc_header> fileParts;
    std::mutex listMutex;
    unsigned long long expected;
    std::ofstream fh;

public:
    Assembler(char* fileName);
    ~Assembler() {
        fh.close();
    }

    char *getFileName() {
        return fileName;
    }

    void pushToBuffer(fc_header pck);
    void writeToFile();

    unsigned long long getExpected() { return expected;}
};

#endif
