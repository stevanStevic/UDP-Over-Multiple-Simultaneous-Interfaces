#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include "protocol_headers.h"

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
void print_raw_data(unsigned char* data, int data_length);

// Print packet headers
void print_winpcap_header(const struct pcap_pkthdr *packet_header, int packet_counter);
void print_ethernet_header(ethernet_header* eh);
void print_ip_header(ip_header * ih);
void print_udp_header(udp_header * uh);
void print_application_data(unsigned char* data, long data_length);

using namespace std;

int main()
{
    pcap_if_t* devices;
    pcap_if_t* device;
    pcap_t* device_handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    unsigned int netmask;
    char filter_exp[] = "udp";
    struct bpf_program fcode;

    int result;							// result of pcap_next_ex function
    int packet_counter = 0;				// counts packets in order to have numerated packets
    struct pcap_pkthdr* packet_header;	// header of packet (timestamp and length)
    const unsigned char* packet_data;	// packet content

    /* Retrieve the device list on the local machine */
    if(pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    // Chose one device from the list
    device = select_device(devices);

    // Check if device is valid
    if(device == NULL)
    {
        pcap_freealldevs(devices);
        return -1;
    }

    printf("You have selected device %s ", device->name);

    // Open the capture device
    if ((device_handle = pcap_open_live( device->name,		// name of the device
                              65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
                              1,							// promiscuous mode
                              500,							// read timeout
                              error_buffer					// buffer where error message is stored
                            ) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", device->name);
        pcap_freealldevs(devices);
        return -1;
    }

//    // Check the link layer. We support only Ethernet for simplicity.
//    if(pcap_datalink(device_handle) != DLT_EN10MB)
//    {
//        printf("\nThis program works only on Ethernet networks.\n");
//        return -1;
//    }

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
         return -1;
    }

    // Set the filter
    if (pcap_setfilter(device_handle, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return -1;
    }

    printf("\nListening on %s...\n", device->description);

    // At this point, we don't need any more the device list. Free it
    pcap_freealldevs(devices);

    int c = 0;

    // Retrieve the packets
    while((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0){
//        ethernet_header * eh;
//        ip_header* ih;
//        int ip_len;
//        udp_header* uh;
//        unsigned char * app_data;
//        int app_length;

//         // Check if timeout has elapsed
//        if(result == 0)
//            continue;

//        // Print libpcap/WinPcap pseudo header
//        print_winpcap_header(packet_header, ++packet_counter);

//        /* DATA LINK LAYER - Ethernet */
//        // Retrive the position of the ethernet header
//        eh = (ethernet_header *)packet_data;
//        // Print ethernet header
//        print_ethernet_header(eh);

//        /* NETWORK LAYER - IPv4 */
//        // Retrieve the position of the ip header
//        ih = (ip_header*) (packet_data + sizeof(ethernet_header));
//        // Print ip header
//        print_ip_header(ih);

//        /* TRANSPORT LAYER - UDP */
//        // Retrieve the position of the udp header
//        ip_len = ih->header_length * 4; // header length is calculated using words (1 word = 4 bytes)
//        uh = (udp_header*) ((unsigned char*)ih + ip_len);

        printf("Packets captured : %\r", ++c);

        // For demonstration purpose
        printf("\n\nPress enter to receive new packet\r");
        getchar();
    }

    if(result == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(device_handle));
        return -1;
    }

    return 0;
}

// This function provide possibility to choose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices)
{
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

// Print raw data of headers and applications
void print_raw_data(unsigned char* data, int data_length)
{
    int i;
    printf("\n-------------------------------------------------------------\n\t");
    for(i = 0; i < data_length; i=i+1)
    {
        printf("%.2x ", ((unsigned char*)data)[i]);

        // 16 bytes per line
        if ((i+1) % 16 == 0)
            printf("\n\t");
    }
    printf("\n-------------------------------------------------------------");
}

// Print pseudo header which is generated by libpcap/WinPcap driver
void print_winpcap_header(const struct pcap_pkthdr* packet_header, int packet_counter)
{
    time_t timestamp;			// Raw time (bits) when packet is received
    struct tm* local_time;		// Local time when packet is received
    char time_string[16];		// Local time converted to string

    printf("\n\n=============================================================");
    printf("\n\tlibpcap/WinPcap PSEUDO LAYER");
    printf("\n-------------------------------------------------------------");

    // Convert the timestamp to readable format
    timestamp = packet_header->ts.tv_sec;
    local_time = localtime(&timestamp);
    strftime( time_string, sizeof time_string, "%H:%M:%S", local_time);

    // Print timestamp and length of the packet
    printf("\n\tPacket number:\t\t%u", packet_counter);
    printf("\n\tTimestamp:\t\t%s.", time_string);
    printf("\n\tPacket length:\t\t%u ", packet_header->len);
    printf("\n=============================================================");
    return;
}

//Print content of Ethernet header
void print_ethernet_header(ethernet_header * eh)
{
    printf("\n=============================================================");
    printf("\n\tDATA LINK LAYER  -  Ethernet");

    print_raw_data((unsigned char*)eh, 14);

    printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->dest_address[0], eh->dest_address[1], eh->dest_address[2], eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);
    printf("\n\tSource address:\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->src_address[0], eh->src_address[1], eh->src_address[2], eh->src_address[3], eh->src_address[4], eh->src_address[5]);
    printf("\n\tNext protocol:\t\t0x%.4x", ntohs(eh->type));

    printf("\n=============================================================");

    return;
}

// Print content of ip header
void print_ip_header(ip_header * ih)
{
    printf("\n=============================================================");
    printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");

    print_raw_data((unsigned char*)ih, ih->header_length * 4);

    printf("\n\tVersion:\t\t%u", ih->version);
    printf("\n\tHeader Length:\t\t%u", ih->header_length*4);
    printf("\n\tType of Service:\t%u", ih->tos);
    printf("\n\tTotal length:\t\t%u", ntohs(ih->length));
    printf("\n\tIdentification:\t\t%u", ntohs(ih->identification));
    printf("\n\tFlags:\t\t\t%u", ntohs(ih->fragm_flags));
    printf("\n\tFragment offset:\t%u", ntohs(ih->fragm_offset));
    printf("\n\tTime-To-Live:\t\t%u", ih->ttl);
    printf("\n\tNext protocol:\t\t%u", ih->next_protocol);
    printf("\n\tHeader checkSum:\t%u", ntohs(ih->checksum));
    printf("\n\tSource:\t\t\t%u.%u.%u.%u", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
    printf("\n\tDestination:\t\t%u.%u.%u.%u", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

    printf("\n=============================================================");

    return;
}
