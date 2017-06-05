#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <thread>
#include "network.hpp"
#include "protocol_headers.h"
#include "sender.hpp"
#include "Segmenter.hpp"

unsigned char source_mac_eth[6] = { 0x38, 0xd5, 0x47, 0xde, 0xf1, 0xbf};
unsigned char dest_mac_eth[6] = { 0x38, 0xd5, 0x47, 0xde, 0xeb, 0xd9};

unsigned char src_ip_eth[4] = {0x0a, 0x51, 0x23, 0x2b};
unsigned char dest_ip_eth[4] = {0x0a, 0x51, 0x23, 0x29};

char error_buffer[PCAP_ERRBUF_SIZE];

void ethThreadFunction(pcap_if_t* device, Segmenter* segmenter) {
    frame frame_to_send;  
    unsigned int netmask;
	char filter_exp[] = "udp portrange 27015-27016";
	struct bpf_program fcode;
	    
	// Open the output eth adapter
    if ((device_handle_eth = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL){
        printf("\n Unable to open adapter %s.\n", device->name);

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
	if (pcap_compile(device_handle_eth, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
	}

	// Set the filter
	if (pcap_setfilter(device_handle_eth, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
	}

    for(int i = 0; i < segmenter->getNumOfPcks(); i++) {
        pck_data pd = segmenter->getFront();
        int tryCount = 0;
        int result;
        struct pcap_pkthdr* packet_header;
        const unsigned char* packet_data;
      //  for(int i = 0; i < 200; i++) {
            //std::cout << segmenter->getNumOfPcks() << std::endl;
       // }

        fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, pd.data, pd.data_num, segmenter->getNumOfPcks(), DATA_SIZE, src_ip_eth, dest_ip_eth);
        pcap_sendpacket(device_handle_eth, (const unsigned char*)&frame_to_send, sizeof(frame));

        while ((result = pcap_next_ex(device_handle_eth, &packet_header, &packet_data)) >= 0) {
            if(result == 1) {
                ack_frame* ack_f = (ack_frame*)packet_data;
                std::cout << ack_f->ack_num  << std::endl;
                if(ack_f->ack_num == pd.data_num) {
                    delete []pd.data;
                    break;
                }
                else {
                    if(++tryCount == 5) {
                        std::cout << "saljiii " << tryCount <<  std::endl;
                        break;
                    }
                    else {
                        pcap_sendpacket(device_handle_eth, (const unsigned char*)&frame_to_send, sizeof(frame));
                        std::cout << pd.data_num << "result 1 al else" << tryCount << std::endl;
                    }
                }
            }
            else {
                if(++tryCount == 5) {
                    std::cout << "saljiiikad je result nula" << tryCount << std::endl;
                    break;
                }
                else {
                    pcap_sendpacket(device_handle_eth, (const unsigned char*)&frame_to_send, sizeof(frame));
                    std::cout << pd.data_num << "result nije 1 al else" << tryCount << std::endl;
                }
            }
        }
    }
}

void wlanThreadFunction(pcap_if_t* device, Segmenter* segmenter) {
/*    frame frame_to_send;

    // Open the output eth adapter
    if ((device_handle_wlan = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL){
        printf("\n Unable to open adapter %s.\n", device->name);

    }

    pck_data pd = segmenter->getFront();

    fill_data_frame(&frame_to_send, source_mac_eth, dest_mac_eth, pd.data, pd.data_num, 1, DATA_SIZE);
    pcap_sendpacket(device_handle_wlan, (const unsigned char*)&frame_to_send, sizeof(frame));
    */
}

void segmenterThreadFunction(Segmenter* segmenter) {

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

    char b[100] = "/home/rtrk/Desktop/example.txt";
    Segmenter segmenter(b);
    segmenter.splitFile();

    std::thread ethThread(ethThreadFunction, device_eth, &segmenter);
    std::thread wlanThread(wlanThreadFunction, device_wlan, &segmenter);
    std::thread segmenterThread(segmenterThreadFunction, &segmenter);

    ethThread.join();
    wlanThread.join();
    segmenterThread.join();

    int n;
    std::cin >> n;

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
