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
#include <iostream>

#define CLIENT_PORT 27015
#define SERVER_PORT 27016

void setup_ethernet_header(frame* frame_to_send, unsigned char* source_mac, unsigned char* dest_mac);
void setup_ip_header(frame* frame_to_send, unsigned char* src_ip, unsigned char* dest_ip);
void setup_udp_header(frame* frame_to_send, int frameToSet);
void setup_fc_header(frame* frame_to_send, unsigned long long frame_cnt, unsigned long long total_num_of_frames, char* buff, unsigned int data_len);

void fill_data_frame(frame* frame_to_send,unsigned char* source_mac, unsigned char* dest_mac, char* buff, unsigned long long frame_cnt, unsigned long long total_num_of_frames, unsigned int data_len, unsigned char* src_ip, unsigned char* dest_ip);
void fill_ack_frame(ack_frame* frame_to_send, unsigned char* source_mac, unsigned char* dest_mac, unsigned long long ack_number, unsigned char* src_ip, unsigned char* dest_ip);

pcap_if_t* select_device(pcap_if_t* devices);

#endif
