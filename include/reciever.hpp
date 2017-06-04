#ifndef RECIEVER_HPP
#define RECIEVER_HPP

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
void eth_thread_function(pcap_t* device_handle);
void wlan_thread_function(pcap_t* device_handle);

#endif
