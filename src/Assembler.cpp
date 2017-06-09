#include "Assembler.hpp"

bool compareFunc(const fc_header& pck1, const fc_header& pck2) {
    return pck1.frame_count < pck2.frame_count;
}

Assembler::Assembler(char* fileName) {
    this->fileName = fileName;
    this->expected = 0;
    this->fileParts.clear();

    fh.open(fileName, std::ios::out | std::ios::binary);
    if(!fh.is_open()) {
        std::cout << "[ERROR] Couldn't open a file: " << fileName << std::endl;
    }
}

void Assembler::pushToBuffer(fc_header pck) {
    if(pck.frame_count < expected) {
        return;
    }

    std::unique_lock<std::mutex> lock(listMutex);
    fileParts.push_back(pck);

    fileParts.sort(compareFunc);
}

void Assembler::writeToFile() {
    char* buff;

    std::unique_lock<std::mutex> lock(listMutex);
    if(!fileParts.empty()) {
        while(fileParts.front().frame_count == expected) {
            fc_header pck = fileParts.front();
            fileParts.pop_front();

            buff = new char[pck.data_len];
            memcpy(buff, pck.data, sizeof(char) * pck.data_len);

            fh.write(buff, pck.data_len);

            expected++;
        }
    }
}
