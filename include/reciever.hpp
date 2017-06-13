#ifndef RECIEVER_HPP
#define RECIEVER_HPP

#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include "protocol_headers.h"
#include "network.hpp"
#include <thread>
#include <mutex>
#include <fstream>
#include <string.h>
#include "Assembler.hpp"

// Function declarations
void reciever_thread_fun(pcap_if_t* device, unsigned char* src_mac, unsigned char* dst_mac, unsigned char* src_ip, unsigned char* dst_ip, Assembler* assembler);

#endif
