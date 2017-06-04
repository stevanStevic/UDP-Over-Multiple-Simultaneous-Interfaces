#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include "network.hpp"
#include "protocol_headers.h"
#include "sender.hpp"
#include "Segmenter.hpp"

using namespace std;

//ETH
unsigned char source_mac_eth[6] = { 0x10, 0x1f, 0x74, 0xcc, 0x28, 0xf9};
unsigned char dest_mac_eth[6] = { 0x40, 0x16, 0x7e, 0x84, 0xb9, 0x8a};

int main() {
    pcap_if_t* devices;
    pcap_if_t* device;
    char error_buffer[PCAP_ERRBUF_SIZE];

    /*
     * Retrieve the device list on the local machine
     */
    if (pcap_findalldevs(&devices, error_buffer) == -1){
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    if ((device = select_device(devices)) == NULL) {
            pcap_freealldevs(devices);
            return -1;
    }

    // Open the output adapter
    if ((device_handle_out = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL){
        printf("\n Unable to open adapter %s.\n", device->name);
        return -1;
    }

    frame frame_to_send;
    char b[6] = "steva";

    //fill_data_frame(frame_to_send, source_mac_eth, dest_mac_eth, b, 0, 1, 5);
    fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, b, 1, 1, 6);

    pcap_sendpacket(device_handle_out, (const unsigned char*)&frame_to_send, sizeof(frame));

   // Segmenter segmenter("tekst.txt");
    //segmenter.split_file()

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
