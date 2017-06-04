#ifndef SENDER_HPP
#define SENDER_HPP

#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

pcap_t* device_handle_wlan, *device_handle_eth;

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
pcap_if_t* select_device(pcap_if_t* devices);

#endif
