#include <iostream>
#include <fstream>
#include <vector>
#include "protocol_headers.h"
#include "Segmenter.hpp"

Segmenter::Segmenter(char* fileName) {
    this->fileName = fileName;

    currPos = 0;
    partsInVector = 0;
    if(getSize() == false) {
        std::cout << "[ERROR] Can't open file " << fileName << std::endl;
    }
}

bool Segmenter::getSize() {
    // Opens the file and positions at the end
    std::ifstream fh(fileName, std::ios::in|std::ios::binary|std::ios::ate);

    if (fh.is_open())
    {
        // Because position is at the end, it returns the size of a file
        size = fh.tellg();
        numOfPcks = size / DATA_SIZE;
        numOfPcks++; //The last one that is not DATA_SIZE size

        return true;
    }
    else {
        return false;
    }
}

bool Segmenter::splitFile() {
    char* buff_t;

    // Opens the file
    std::ifstream fh(fileName, std::ios::in|std::ios::binary);

    if (fh.is_open())
    {
        //Find the position next for reading
        fh.seekg (currPos * DATA_SIZE, std::ios::beg);

        if(isFull() == false) {
            for(int i = currPos; i < numOfPcks; i++) {
                pck_data tData;
                buff_t = new char[DATA_SIZE];

                //If it's last one than only the rest needs to be read not, DATA_SIZE
                if(currPos == numOfPcks - 1) {
                    fh.read(buff_t, size - (currPos * DATA_SIZE));
                }
                else {
                    fh.read(buff_t, DATA_SIZE);
                }

                // Set data to be put in vector
                tData.data = buff_t;
                tData.data_num = currPos;

                vectorMutex.lock();
                fileParts.push_back(tData);
                partsInVector++;
                vectorMutex.unlock();

                currPos++;

                std::lock_guard<std::mutex> lock(vectorMutex);
                if(partsInVector == BUFF_SIZE) {
                    full = true;
                    break;
                }

                fh.seekg (currPos * DATA_SIZE, std::ios::beg);
            }

            fh.close();
            return true;
        }
    }
    else {
        return false;
    }
}

pck_data Segmenter::getFront() {
    pck_data temp;

    vectorMutex.lock();
    if(fileParts.empty() == false) {
        temp = fileParts.front();
        fileParts.erase(fileParts.begin());
        partsInVector--;
    }
    vectorMutex.unlock();

    return temp;
}

void Segmenter::putPartBack(pck_data pd) {
    vectorMutex.lock();
    fileParts.push_back(pd);
    vectorMutex.unlock();
}
