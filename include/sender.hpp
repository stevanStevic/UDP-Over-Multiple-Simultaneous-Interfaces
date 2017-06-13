#ifndef SENDER_HPP
#define SENDER_HPP

#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include "Segmenter.hpp"

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

void segmenterThreadFunction(Segmenter* segmenter);
void sender_thread_fun(pcap_if_t* device, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip, Segmenter* segmenter);

#endif
