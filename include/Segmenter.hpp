#ifndef SEGMENTER_HPP
#define SEGMENTER_HPP

#include <iostream>
#include <vector>
#include "protocol_headers.h"
#include <mutex>

#define BUFF_SIZE 256

/*
 * Segmenter will have thread which can fill up to BUFF_SIZE parts of file to the vector.
 * Devices will read and send part by part and remove that from buffer
 * When there is free space for segmenter he puts another part, until it reads the whole file.
 * This is done to prevent memory overflow.
 */

class Segmenter {
private:
    char* fileName;
    std::vector<pck_data> fileParts;
    unsigned long long size;
    unsigned long long numOfPcks;
    int currPos;
    int partsInVector;
    bool full;
    std::mutex vectorMutex;

public:
    Segmenter(char* fileName);

    char *getFileName() {
        return fileName;
    }

    unsigned long long getNumOfPcks() {
        return numOfPcks;
    }

    bool splitFile();
    bool getSize();
    bool isFull() {
        return full;
    }

    pck_data getFront();
    void putPartBack(pck_data);

};


#endif
