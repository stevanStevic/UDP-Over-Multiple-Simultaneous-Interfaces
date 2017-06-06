#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include "protocol_headers.h"
#include "network.hpp"
#include "reciever.hpp"
#include "Segmenter.hpp"
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <string.h>

/*
 * Global variables, for communication between threads and proper
 * file asembly.
 */
std::ofstream file;
unsigned long long expected;
std::vector<fc_header> common_buffer;
std::mutex common_buffer_mutex;
std::mutex file_mutex;
//char *path = "/home/godra/Desktop/example.png";

unsigned char dest_mac_eth[6] = { 0x10, 0x1f, 0x74, 0xcc, 0x28, 0xf9}; //steva
unsigned char src_mac_eth[6] = { 0x40, 0x16, 0x7e, 0x84, 0xb9, 0x8a}; //godra

unsigned char src_ip_eth[4] = {0x0a, 0x51, 0x23, 0x29};
unsigned char dest_ip_eth[4] = {0x0a, 0x51, 0x23, 0x2b};

unsigned char dest_mac_wlan[6] = {0x60, 0xd8, 0x19, 0x59, 0x0d, 0xb3}; //steva
unsigned char src_mac_wlan[6] = {0x54, 0x27, 0x1e, 0x83, 0x59, 0x8d}; //godra

int main(){

    pcap_if_t* devices;
    pcap_if_t* device_eth;
    pcap_if_t* device_wlan;
    pcap_t* device_handle_eth;
    pcap_t* device_handle_wlan;
    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned int netmask_eth;
    unsigned int netmask_wlan;
    char filter_exp[] = "udp portrange 27015-27016";
    struct bpf_program fcode;

    expected = 0;

    /* Retrieve the device list on the local machine */
    if(pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    printf("\nSelect your ethernet interface first :\n\n");
    // Chose one device from the list
    device_eth = select_device(devices);

    // Check if device is valid
    if(device_eth == NULL)
    {
        pcap_freealldevs(devices);
        return -1;
    }

    printf("You have selected device %s \n", device_eth->name);

    printf("\nSelecet your wireless interface now :\n\n");
    // Chose one device from the list
    device_wlan = select_device(devices);

    // Check if device is valid
    if(device_wlan == NULL)
    {
        pcap_freealldevs(devices);
        return -1;
    }

    printf("You have selected device %s ", device_wlan->name);

    // Open the capture device
    if ((device_handle_eth = pcap_open_live( device_eth->name,		// name of the device
                              65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// promiscuous mode
                              500,							// read timeout
                              error_buffer					// buffer where error message is stored
                            ) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device_eth->name);
        pcap_freealldevs(devices);
        return -1;
    }


    // Open the capture device
    if ((device_handle_wlan = pcap_open_live( device_wlan->name,		// name of the device
                              65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// promiscuous mode
                              500,							// read timeout
                              error_buffer					// buffer where error message is stored
                            ) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device_wlan->name);
        pcap_freealldevs(devices);
        return -1;
    }

#ifdef _WIN32
    if(device_eth->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask_eth=((struct sockaddr_in *)(device_eth->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask_eth=0xffffff;
#else
    if (!device_eth->addresses->netmask)
        netmask_eth = 0;
    else
        netmask_eth = ((struct sockaddr_in *)(device_eth->addresses->netmask))->sin_addr.s_addr;
#endif


#ifdef _WIN32
    if(device_eth->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask_wlan=((struct sockaddr_in *)(device_eth->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask_wlan=0xffffff;
#else
    if (!device_eth->addresses->netmask)
        netmask_wlan = 0;
    else
        netmask_wlan = ((struct sockaddr_in *)(device_eth->addresses->netmask))->sin_addr.s_addr;
#endif

    // Compile the filter
    if (pcap_compile(device_handle_eth, &fcode, filter_exp, 1, netmask_eth) < 0)
    {
         printf("\n Unable to compile the packet filter. Check the syntax.\n");
         return -1;
    }

    // Set the filter
    if (pcap_setfilter(device_handle_eth, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return -1;
    }


    // Compile the filter
    if (pcap_compile(device_handle_wlan, &fcode, filter_exp, 1, netmask_wlan) < 0)
    {
         printf("\n Unable to compile the packet filter. Check the syntax.\n");
         return -1;
    }

    // Set the filter
    if (pcap_setfilter(device_handle_wlan, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return -1;
    }

    std::thread eth_thread(eth_thread_function, device_handle_eth);
    std::thread wlan_thread(wlan_thread_function, device_handle_wlan);
    eth_thread.join();
    wlan_thread.join();

    //file.close();
    return 0;
}

// This function provide possibility to choose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices) {
    int device_number;
    int i=0;			// Count devices and provide jumping to the selected device
    pcap_if_t* device;	// Iterator for device list
    // Print the list
    for(device=devices; device; device=device->next)
    {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    // Check if list is empty
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
        return NULL;
    }

    // Pick one device from the list
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &device_number);

    if(device_number < 1 || device_number > i)
    {
        printf("\nInterface number out of range.\n");
        return NULL;
    }

    // Jump to the selected device
    for(device=devices, i=0; i< device_number-1 ;device=device->next, i++);

    return device;
}


void eth_thread_function(pcap_t* device_handle){

    int result;							// result of pcap_next_ex function
    struct pcap_pkthdr* packet_header;	// header of packet (timestamp and length)
    const unsigned char* packet_data;	// packet content


    printf("\nRecieveing data over ethernet\n");

    while((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0){

        //Allocating new buffer for acepting data
        char* temp = new char[DATA_SIZE];

		if(result == 0) {
			std::cout << "Timeout expired" << std::endl;
		
		}else {

            frame* pFrame;
            pFrame = (frame*)packet_data;

            std::cout << "ETHERNET" << std::endl;
            std::cout << "Result : " << result << std::endl;
            std::cout << "Frame captured" << std::endl;
            std::cout << "Expected :" << expected << std::endl;
            std::cout << "Recieved : " << pFrame->fch.frame_count << std::endl;
            std::cout << "Total data : " << pFrame->fch.num_of_total_frames << std::endl;

            ack_frame af;
            fill_ack_frame(&af, src_mac_eth, dest_mac_eth, pFrame->fch.frame_count, src_ip_eth, dest_ip_eth);
            pcap_sendpacket(device_handle, (const unsigned char*)&af, sizeof(ack_frame));

            if(pFrame->fch.frame_count == expected){ //If frame is in order
                //Lock here, for file manipulation
                file_mutex.lock();
                file.open("/home/godra/Desktop/example.png", std::ios::out | std::ios::app | std::ios::binary);
                if(!file.is_open()){
                    printf("File opening failed\n");
                }

                memcpy(temp, pFrame->fch.data, pFrame->fch.data_len * sizeof(char));
                file.write(temp, pFrame->fch.data_len);
                file.close();
                expected = expected + 1; //Increment to next frame
                file_mutex.unlock();

                //After writing to file check the out-of-order-buffer for more frames to write to file
                std::vector<fc_header>::iterator it;
                int i;

                if(!common_buffer.empty()){

                    //Lock out-of-order-buffer-mutex for walk through that buffer
                    common_buffer_mutex.lock();
                    it = common_buffer.begin();
                    i = 0;
                    while(it != common_buffer.end()) {

                        fc_header current_item = (fc_header)(*it);

                        if(current_item.frame_count == expected){ //If the expected frame is found in out-of-order-buffer

                            file_mutex.lock(); //Lock file mutex before writing to file
                            file.open("/home/godra/Desktop/example.png"); //Open file
                            if(!file.is_open()){
                                printf("File opening failed");
                            }

                            memcpy(temp, pFrame->fch.data, pFrame->fch.data_len * sizeof(char));
                            file.write(temp, pFrame->fch.data_len);
                            file.close(); //Close file
                            expected = expected + 1; //Increment to expect next fram
                            file_mutex.unlock(); //Unlock file mutex after writing to file

                            common_buffer.erase(common_buffer.begin() + i); //Erase that good frame from out-of-order-buffer
                            it = common_buffer.begin();
                            i = 0;
                        }
                    i++;
                    it++;
                    }

                    //Unlock out-of-order-buffer-mutex after iteration through it
                    common_buffer_mutex.unlock();
                }

           } else if (strcmp(((const char *)pFrame->eh.src_address), (const char *)src_mac_eth) == 0) {

                std::cout << "\nIde preko reda!!!\n";

                common_buffer_mutex.lock(); //Lock down here for adding it to temp buffer (for out of order frames)

                common_buffer.push_back(pFrame->fch);
                std::vector<fc_header>::iterator it;
                std::cout << "###########Sadrzaj bafera za out of order ###########" << std::endl;
                for(it = common_buffer.begin(); it != common_buffer.end(); it++){
                    fc_header current_item = (fc_header)(*it);
                    std::cout << current_item.num_of_total_frames << std::endl;
                }
                std::cout << "#####################################################" << std::endl;

                common_buffer_mutex.unlock(); //Unlock after adding it to temp buffer

		   }

           delete[] temp;

		   if(pFrame->fch.num_of_total_frames == expected)
		        break;
		}
    }
}

void wlan_thread_function(pcap_t* device_handle){

    int result;							// result of pcap_next_ex function
    struct pcap_pkthdr* packet_header;	// header of packet (timestamp and length)
    const unsigned char* packet_data;	// packet content


    printf("\nRecieveing data over ethernet\n");

    while((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0){

        //Allocating new buffer for acepting data
        char* temp = new char[DATA_SIZE];

        if(result == 0) {
            std::cout << "Timeout expired" << std::endl;
        }else {

            frame* pFrame;
            pFrame = (frame*)packet_data;

            std::cout << "WLAN" << std::endl;
            std::cout << "Result : " << result << std::endl;
            std::cout << "Frame captured" << std::endl;
            std::cout << "Expected :" << expected << std::endl;
            std::cout << "Recieved : " << pFrame->fch.frame_count << std::endl;
            std::cout << "Total data : " << pFrame->fch.num_of_total_frames << std::endl;

            ack_frame af;
            fill_ack_frame(&af, src_mac_wlan, dest_mac_wlan, pFrame->fch.frame_count, src_ip_eth, dest_ip_eth);
            pcap_sendpacket(device_handle, (const unsigned char*)&af, sizeof(ack_frame));

            if(pFrame->fch.frame_count == expected){ //If frame is in order
                //Lock here, for file manipulation
                file_mutex.lock();
                file.open("/home/godra/Desktop/example.png", std::ios::out | std::ios::app | std::ios::binary);
                if(!file.is_open()){
                    printf("File opening failed\n");
                }

                memcpy(temp, pFrame->fch.data, pFrame->fch.data_len * sizeof(char));
                file.write(temp, pFrame->fch.data_len);
                file.close();
                expected = expected + 1; //Increment to next frame
                file_mutex.unlock();

                //After writing to file check the out-of-order-buffer for more frames to write to file
                std::vector<fc_header>::iterator it;
                int i;

                if(common_buffer.emplace) {

                    //Lock out-of-order-buffer-mutex for walk through that buffer
                    common_buffer_mutex.lock();
                    it = common_buffer.begin();
                    i = 0;
                    while(it != common_buffer.end()) {

                        fc_header current_item = (fc_header)(*it);

                        if(current_item.frame_count == expected){ //If the expected frame is found in out-of-order-buffer

                            file_mutex.lock(); //Lock file mutex before writing to file
                            file.open("/home/godra/Desktop/example.png"); //Open file
                            if(!file.is_open()){
                                printf("File opening failed");
                            }

                            memcpy(temp, pFrame->fch.data, pFrame->fch.data_len * sizeof(char));
                            file.write(temp, pFrame->fch.data_len);
                            file.close(); //Close file
                            expected = expected + 1; //Increment to expect next fram
                            file_mutex.unlock(); //Unlock file mutex after writing to file

                            common_buffer.erase(common_buffer.begin() + i); //Erase that good frame from out-of-order-buffer
                            it = common_buffer.begin();
                            i = 0;
                        }
                        i++;
                        it++;
                    }

                    //Unlock out-of-order-buffer-mutex after iteration through it
                    common_buffer_mutex.unlock();
                }

           } else if (strcmp(((const char *)pFrame->eh.src_address), (const char *)src_mac_eth) == 0) {

                std::cout << "\nIde preko reda!!!\n";

                common_buffer_mutex.lock(); //Lock down here for adding it to temp buffer (for out of order frames)

                common_buffer.push_back(pFrame->fch);
                std::vector<fc_header>::iterator it;
                std::cout << "###########Sadrzaj bafera za out of order ###########" << std::endl;
                for(it = common_buffer.begin(); it != common_buffer.end(); it++){
                    fc_header current_item = (fc_header)(*it);
                    std::cout << current_item.num_of_total_frames << std::endl;
                }
                std::cout << "#####################################################" << std::endl;

                common_buffer_mutex.unlock(); //Unlock after adding it to temp buffer

           }

           delete[] temp;

           if(pFrame->fch.num_of_total_frames == expected)
                break;
        }
    }
}
