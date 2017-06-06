#include <iostream>
#include <fstream>
#include <list>
#include "protocol_headers.h"
#include "Segmenter.hpp"

Segmenter::Segmenter(char* fileName) {
    this->fileName = fileName;

    full = false;
    currPos = 0;
    partsInVector = 0;
    if(getSizeOfFile() == false) {
        std::cout << "[ERROR] Can't open file " << fileName << std::endl;
    }
}

bool Segmenter::getSizeOfFile() {
    // Opens the file and positions at the end
    std::ifstream fh(fileName, std::ios::in|std::ios::binary|std::ios::ate);

    if (fh.is_open())
    {
        // Because position is at the end, it returns the size of a file
        sizeOfFile = fh.tellg();
        numOfPcks = sizeOfFile / DATA_SIZE;
        numOfPcks++; //The last one that is not DATA_SIZE size

        return true;
    }
    else {
        return false;
    }
}

int Segmenter::splitFile() {
    char* buff_t;

    // Opens the file
    std::ifstream fh(fileName, std::ios::in|std::ios::binary);

    // If hole file is segmented
    //std::cout << "curPos " << currPos << " numPck " << numOfPcks << "isfin" << isFinished() << std::endl;
    if(!isFinished()) {
        if (fh.is_open())
        {
            //Find the position next for reading
            fh.seekg (currPos * DATA_SIZE, std::ios::beg);

            //If there is space in buffer
            if(isFull() == false) {
                for(int i = currPos; i < numOfPcks; i++) {
                    pck_data tData;

                    //If it's last one than only the rest of the size needs to be read, not DATA_SIZE
                    if(currPos == numOfPcks - 1) {
                        buff_t = new char[sizeOfFile % DATA_SIZE];
                        fh.read(buff_t, sizeOfFile % DATA_SIZE);
                        tData.data_size = sizeOfFile % DATA_SIZE;
                    }
                    else {
                        buff_t = new char[DATA_SIZE];
                        fh.read(buff_t, DATA_SIZE);
                        tData.data_size = DATA_SIZE;
                    }

                    // Set data to be put in vector
                    tData.data = buff_t;
                    tData.data_num = currPos;

                    vectorMutex.lock();
                    fileParts.push_back(tData);
                    partsInVector++;
                    vectorMutex.unlock();

                    currPos++;

                    //Check if buffer is full
                    std::lock_guard<std::mutex> lock(vectorMutex);
                    if(partsInVector == BUFF_SIZE) {
                        full = true;
                        break;
                    }

                    //Get next
                    fh.seekg (currPos * DATA_SIZE, std::ios::beg);
                }

                fh.close();

                //Filled buffer with segments, not fully segmented
                return 0;
            }
        }
        else {
            //File not opened
            return -1;
        }
    }
    else {
        //File is fully segmented
        return 1;
    }
}

int Segmenter::getFront(pck_data* pd) {
    int succ = 0;

    vectorMutex.lock();
    if(fileParts.empty() == false) {
        *pd = fileParts.front();
        fileParts.pop_front();
        partsInVector--;
        full = false;

        //Took one from the buffer
        succ = 0;
    }
    else if(isFinished()) {
        //whole file is segmented
        succ = 1;
    }
    else {
        //File is not fully segmented but currently there is no parts in buffer
        succ = -1;
    }
    vectorMutex.unlock();

    return succ;
}

void Segmenter::putPartBack(pck_data pd) {
    vectorMutex.lock();
    fileParts.push_front(pd);
    partsInVector++;
    if(partsInVector == BUFF_SIZE) {
        full = true;
    }
    vectorMutex.unlock();
}
