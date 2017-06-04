#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H

#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"

#define CLIENT_PORT 27015
#define SERVER_PORT 27016

void setup_ethernet_header(frame* frame_to_send, char* source_mac, char* dest_mac);
void setup_ip_header(frame* frame_to_send);
void setup_udp_header(frame* frame_to_send, int frame_to_set);
void setup_fc_header(frame* frame_to_send, unsigned long long frame_cnt, unsigned long long total_num_of_frames, unsigned char* buff, unsigned int data_len);

void fill_data_frame(frame* frame_to_send, char* source_mac, char* dest_mac, char* buff, unsigned long long frame_cnt, unsigned long long total_num_of_frames, unsigned int data_len);
void fill_ack_frame(frame* frame_to_send, char* source_mac, char* dest_mac, unsigned long long ack_number);

#endif
