#ifndef SEGMENTER_HPP
#define SEGMENTER_HPP

#include <iostream>
#include <vector>
#include "protocol_headers.h"

class Segmenter {
private:
    std::vector<char*> file_parts;
    std::vector<bool[DATA_SIZE]> sent_bytes;
    unsigned long long num_of_pcks;
    char* file_name;

public:
    Segmenter(char* file_name);

    bool split_file();

    std::vector<char*> get_file_parts() {
        return file_parts;
    }

    unsigned long long get_num_of_pcks() {
        return num_of_pcks;
    }
};


#endif
