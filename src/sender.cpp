#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <thread>
#include <chrono>
#include "network.hpp"
#include "protocol_headers.h"
#include "sender.hpp"
#include "Segmenter.hpp"

#define PATH "/home/stevan/Desktop/ORM2/testFiles/500kb.dat"

unsigned char src_mac_eth[6] = { 0x10, 0x1f, 0x74, 0xcc, 0x28, 0xf9};
unsigned char dest_mac_eth[6] = {0x40, 0x16, 0x7e, 0x84, 0xb9, 0x8a};

/*
unsigned char source_mac_eth[6] = { 0x38, 0xd5, 0x47, 0xde, 0xf1, 0xbf};
unsigned char dest_mac_eth[6] = { 0x38, 0xd5, 0x47, 0xde, 0xeb, 0xd9};
*/

unsigned char src_ip_eth[4] = {10, 42, 0, 1};
unsigned char dest_ip_eth[4] = {192, 168, 9, 106};

unsigned char dest_mac_wlan[6] = {0x54, 0x27, 0x1e, 0x83, 0x59, 0x8d}; //godra
unsigned char src_mac_wlan[6] = {0x60, 0xd8, 0x19, 0x59, 0x0d, 0xb3};

unsigned char src_ip_wlan[4] = {192, 168, 9, 105};
unsigned char dest_ip_wlan[4] = {192, 168, 9, 103};

void sender_thread_fun(pcap_if_t* device, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip, Segmenter* segmenter) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned int netmask;
    char filter_exp[] = "udp portrange 27015-27016";
    struct bpf_program fcode;
    pcap_t* device_handle;
    frame frame_to_send;
    int deviceAvailable = 1;

    // Open the output eth adapter
    if ((device_handle = pcap_open_live(device->name, 65536, 1, 20, error_buffer)) == NULL){
        printf("\n Unable to open adapter %s.\n", device->name);
        return;
    }

#ifdef _WIN32
    if(device->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;
#else
    if (!device->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;
#endif

    // Compile the filter
    if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
    {
        printf("\n Unable to compile the packet filter. Check the syntax.\n");
        return;
    }

    // Set the filter
    if (pcap_setfilter(device_handle, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return;
    }

    while (!segmenter->isAllSent()) {
        pck_data pd;
        int result;
        int tryCountNotRecieved = 0;
        int tryCountRecieved = 0;
        struct pcap_pkthdr* packet_header;
        const unsigned char* packet_data;

        result = segmenter->getFront(&pd);
        if(result == -1) {
            // Segmenter buffer is empty
            while(segmenter->getFront(&pd) == -1);
        }
        else if(result == 1) {
            //All parts sent
            return;
        }

        fill_data_frame(&frame_to_send, src_mac, dest_mac, pd.data, pd.data_num, segmenter->getNumOfPcks(), pd.data_size, src_ip, dest_ip);
        pcap_sendpacket(device_handle, (const unsigned char*)&frame_to_send, sizeof(frame));

        while ((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0) {
            if(result == 1) {
                ack_frame* ack_f = (ack_frame*)packet_data;

                if(!deviceAvailable) {
                    std::cout << "Device " << device->name << " is available again" << std::endl;
                    deviceAvailable = 1;
                }

                //std::cout << device->name << "ack: " << ack_f->ack_num  << std::endl;
                if(ack_f->ack_num == pd.data_num) {

                    break;
                }
                else {                 
                    segmenter->putPartBack(pd);
                }
            }
            else {
                if(++tryCountNotRecieved == ACK_TIMEOUT) {
                    segmenter->putPartBack(pd);
                    if(deviceAvailable) {
                        deviceAvailable = 0;
                        std::cout << "Device " << device->name << " not available any more" << std::endl;
                    }

                    break;
                }
            }

            //pcap_sendpacket(device_handle, (const unsigned char*)&frame_to_send, sizeof(frame));
        }
    }

    pcap_close(device_handle);
}

void segmenterThreadFunction(Segmenter* segmenter) {

    //While hole file is not segmented. When finished fully returns 1
    while(segmenter->splitFile() != 1) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

int main(int argc, char* argv[]) {
    pcap_if_t* devices;
    pcap_if_t* device_eth;
    pcap_if_t* device_wlan;
    char error_buffer[PCAP_ERRBUF_SIZE];

    /*
     * Retrieve the device list on the local machine
     */
    if (pcap_findalldevs(&devices, error_buffer) == -1){
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    // Choose eth device
    if ((device_eth = select_device(devices)) == NULL) {
            pcap_freealldevs(devices);
            return -1;
    }

    // Choose wlan device
    if ((device_wlan = select_device(devices)) == NULL) {
            pcap_freealldevs(devices);
            return -1;
    }

    Segmenter segmenter((char*)PATH);

    auto start = std::chrono::steady_clock::now();

    std::thread segmenterThread(segmenterThreadFunction, &segmenter);
    std::thread ethThread(sender_thread_fun, device_eth, src_mac_eth, dest_mac_eth, src_ip_eth, dest_ip_wlan, &segmenter);
    std::thread wlanThread(sender_thread_fun, device_wlan, src_mac_wlan, dest_mac_wlan, src_ip_wlan, dest_ip_wlan, &segmenter);


    ethThread.join();
    wlanThread.join();
    segmenterThread.join();

    auto finish = std::chrono::steady_clock::now();
    double elapsed_seconds = std::chrono::duration_cast<
      std::chrono::duration<double> >(finish - start).count();



    std::cout << "Finished in ..." << elapsed_seconds << std::endl;
    getchar();

    return 0;
}
