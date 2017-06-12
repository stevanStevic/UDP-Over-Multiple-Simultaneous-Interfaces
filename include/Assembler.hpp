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
    FILE* fh;
	bool finished;

public:
    Assembler(char* fileName);
    ~Assembler() {
        fclose(fh);
    }

    void closeFile() {
        fclose(fh);
    }

    void printBuffer();

    char *getFileName() {
        return fileName;
    }
    void pushToBuffer(fc_header pck);
    void writeToFile();

    unsigned long long getExpected() { return expected;}
	bool isFinished() {return finished;}
};

#endif
