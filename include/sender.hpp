#ifndef SENDER_HPP
#define SENDER_HPP

pcap_t* device_handle_in, *device_handle_out;

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
pcap_if_t* select_device(pcap_if_t* devices);

#endif
