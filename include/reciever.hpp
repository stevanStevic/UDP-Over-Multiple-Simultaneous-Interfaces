#ifndef RECIEVER_HPP
#define RECIEVER_HPP

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
void reciever_thread_fun(pcap_if_t* device, unsigned char* src_mac_addr, unsigned char* dst_mac_addr, unsigned char* src_ip_addr, unsigned char* dst_ip_addr);

#endif
