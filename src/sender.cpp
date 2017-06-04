#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <thread>
#include "network.hpp"
#include "protocol_headers.h"
#include "sender.hpp"
#include "Segmenter.hpp"

char error_buffer[PCAP_ERRBUF_SIZE];

void ethThreadFunction(pcap_if_t* device) {
    // Open the output eth adapter
    if ((device_handle_eth = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL){
        printf("\n Unable to open adapter %s.\n", device->name);

    }

}

void wlanThreadFunction(pcap_if_t* device) {

}

int main() {
    pcap_if_t* devices;
    pcap_if_t* device_eth;
    pcap_if_t* device_wlan;

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

    std::thread ethThread(ethThreadFunction, device_eth);
    std::thread wlanThread(wlanThreadFunction, device_wlan);

/*
    frame frame_to_send;
    char b[100] = "/home/stevan/Desktop/ORM2/tekst.txt";

    //fill_data_frame(frame_to_send, source_mac_eth, dest_mac_eth, b, 0, 1, 5);
   // fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, b, 1, 1, 6);

    //pcap_sendpacket(device_handle_out, (const unsigned char*)&frame_to_send, sizeof(frame));

    Segmenter segmenter(b);
    if(!segmenter.split_file()) {
        std::cout << "[ERROR] Can't open file " << segmenter.get_file_name() << std::endl;
    }

    for(int i = 0; i < segmenter.get_num_of_pcks(); i++)  {
        fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, segmenter.get_file_parts().at(i), i, segmenter.get_num_of_pcks(), DATA_SIZE);
        pcap_sendpacket(device_handle_out, (const unsigned char*)&frame_to_send, sizeof(frame));

        std::cout << i << std::endl;
/*
        for(int j = 0; j < DATA_SIZE; j++) {
            std::cout << segmenter.get_file_parts().at(i)[j] << std::endl;
        }*/

    int n;
    std::cin >> n;
    /*for(int i = 0; i < 200; i++) {
        segmenter.get_file_parts().
    }
    fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, segmenter.get_file_parts()[0], 0, segmenter.get_num_of_pcks(), DATA_SIZE);
    pcap_sendpacket(device_handle_out, (const unsigned char*)&frame_to_send, sizeof(frame));

   /* for(int i = 0; i < segmenter.get_num_of_pcks(); i++) {
        fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, segmenter.get_file_parts()[i], i, segmenter.get_num_of_pcks(), DATA_SIZE);
        pcap_sendpacket(device_handle_out, (const unsigned char*)&frame_to_send, sizeof(frame));
    }
*/
    return 0;
}

pcap_if_t* select_device(pcap_if_t* devices) {
    int i = 0;
    pcap_if_t* device;
    int device_number;

    // Count devices and provide jumping to the selected device
    // Print the list
    for(device=devices; device; device=device->next){
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    // Check if list is empty
    if (i==0){
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        exit(EXIT_FAILURE);
    }

    printf("Enter the output interface number (1-%d):",i);
    scanf("%d", &device_number);

    if(device_number < 1 || device_number > i){
        printf("\nInterface number out of range.\n");
        exit(EXIT_FAILURE);
    }

    // Select the first device...
    device=devices;
    // ...and then jump to chosen devices
    for (i=0; i<device_number-1; i++){
        device=device->next;
    }

    return device;
}
