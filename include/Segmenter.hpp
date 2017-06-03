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
};


#endif
