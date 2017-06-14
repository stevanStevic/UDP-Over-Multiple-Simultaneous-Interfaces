#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#endif

#include "reciever.hpp"

unsigned char dest_mac_eth[6] = { 0x38, 0xd5, 0x47, 0xde, 0xf1, 0xbf}; //steva
unsigned char src_mac_eth[6] = { 0x38, 0xd5, 0x47, 0xde, 0xeb, 0xd9}; //godra

unsigned char src_ip_eth[4] = {0x0a, 0x51, 0x23, 0x31};
unsigned char dest_ip_eth[4] = {};

unsigned char dest_mac_wlan[6] = {0x60, 0xd8, 0x19, 0x59, 0x0d, 0xb3}; //steva
unsigned char src_mac_wlan[6] = {0x54, 0x27, 0x1e, 0x83, 0x59, 0x8d}; //godra

unsigned char src_ip_wlan[4] = {192, 168, 9, 104};
unsigned char dest_ip_wlan[6] = {192, 168, 9, 105};

#define PATH "/home/godra/Desktop/example.png"

int main(){
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    pcap_if_t* device_eth;
    pcap_if_t* device_wlan;

    /* Retrieve the device list on the local machine */
    if(pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    // Chose one device from the list
    printf("\nSelect your ethernet interface first :\n\n");
    device_eth = select_device(devices);

    printf("You have selected device %s \n", device_eth->name);

    // Chose one device from the list
    printf("\nSelecet your wireless interface now :\n\n");
    device_wlan = select_device(devices);

    printf("You have selected device %s \n", device_wlan->name);
    fflush(stdout);

    Assembler assembler((char*)PATH);

    std::thread eth_thread(reciever_thread_fun, device_eth, src_mac_eth, dest_mac_eth, src_ip_eth, dest_ip_eth, &assembler);
    std::thread wlan_thread(reciever_thread_fun, device_wlan, src_mac_wlan, dest_mac_wlan, src_ip_wlan, dest_ip_wlan, &assembler);

//    pcap_free(device_eth);
//    pcap_free(device_wlan);

    eth_thread.join();
    wlan_thread.join();

    std::cout << std::endl << "Transfer complete" << std::endl;

    pcap_freealldevs(devices);

    return 0;
}

void reciever_thread_fun(pcap_if_t* device, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip, Assembler* assembler){
    pcap_t* device_handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned int netmask;
    char filter_exp[] = "udp portrange 27015-27016";
    struct bpf_program fcode;
    int result;							// result of pcap_next_ex function
    struct pcap_pkthdr* packet_header;	// header of packet (timestamp and length)
    const unsigned char* packet_data;	// packet content

    // Open the capture device
    if ((device_handle = pcap_open_live(device->name,		// name of the device
                              65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// promiscuous mode
                              500,							// read timeout
                              error_buffer					// buffer where error message is stored
                            ) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
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

    pcap_setnonblock(device_handle, 1, error_buffer); // Enabling non blocking mdoe for pcap_next_ex

    while((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0 && !assembler->isFinished()){
        if(result != 0) {
            frame* pFrame;
            ack_frame af;

            pFrame = (frame*)packet_data;

//            std::cout << device->name << std::endl;
//            std::cout << "Result : " << result << std::endl;
//            std::cout << "Frame captured" << std::endl;
//            std::cout << "Expected :" << assembler->getExpected() << std::endl;
//            std::cout << "Recieved : " << pFrame->fch.frame_count << std::endl;
//            std::cout << "Total data : " << pFrame->fch.num_of_total_frames << std::endl;

            fill_ack_frame(&af, src_mac, dest_mac, pFrame->fch.frame_count, src_ip, dest_ip);
            pcap_sendpacket(device_handle, (const unsigned char*)&af, sizeof(ack_frame));

            assembler->pushToBuffer(pFrame->fch);
            assembler->writeToFile();
        }
    }

    pcap_close(device_handle);
}
