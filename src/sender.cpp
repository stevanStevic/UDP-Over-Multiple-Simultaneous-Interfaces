#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include "protocol_headers.h"

using namespace std;

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

pcap_t* device_handle_in, *device_handle_out;

int main() {

    int i = 0;
    int device_number;
    int sentBytes;
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
        return -1;
    }

    printf("Enter the output interface number (1-%d):",i);
    scanf("%d", &device_number);

    if(device_number < 1 || device_number > i){
        printf("\nInterface number out of range.\n");
        return -1;
    }

    // Select the first device...
    device=devices;
    // ...and then jump to chosen devices
    for (i=0; i<device_number-1; i++){
        device=device->next;
    }

    // Open the output adapter
    if ((device_handle_out = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL){
        printf("\n Unable to open adapter %s.\n", device->name);
        return -1;
    }

    return 0;
}
