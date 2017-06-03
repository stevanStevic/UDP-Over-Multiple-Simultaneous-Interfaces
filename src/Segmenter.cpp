#include <iostream>
#include <fstream>
#include <vector>
#include "protocol_headers.h"
#include "Segmenter.hpp"

Segmenter::Segmenter(char* file_name) {
    this->file_name = file_name;
}

bool Segmenter::split_file() {
    std::streampos size, curr_pos;
    char* buff_t;

    // Opens the file and positions at the end
    std::ifstream fh(file_name, std::ios::in|std::ios::binary|std::ios::ate);

    if (fh.is_open())
    {
        // Because position is at the end, it returns the size of a file
        size = fh.tellg();
        num_of_pcks = size / DATA_SIZE;

        fh.seekg (0, std::ios::beg);
        curr_pos = 0;

        for(int i = 0; i < num_of_pcks; i++) {
            buff_t = new char[DATA_SIZE];

            fh.read(buff_t, DATA_SIZE);

            file_parts.push_back(buff_t);

            curr_pos += DATA_SIZE;
            fh.seekg (curr_pos, std::ios::beg);
        }

        fh.close();
    }
    else {
        return false;
    }
}
