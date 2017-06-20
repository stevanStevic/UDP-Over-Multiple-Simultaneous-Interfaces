README v0.0 / JUNE 2017

# UDP-Over-Simultaneous-Interfaces

## Introduction

A demonstration of custom, __secure UDP based protocol__ that uses two interfaces (Wifi and ethernet) to transfer any kind of files between two users. Actual data transfer is concurent and it is based on data race. Sender parses file and sends those parsed pieces to reciever, who reconsturcts file from recieved segements. Both, sender and reciever have buffer in which they store file parts (sender gets file parts from segmenter, and reciever gets file parts from captured packets and asembler combines them into a single file). Whole protocol is based on usage __pcap library__. Read [**this**](https://en.wikipedia.org/wiki/Pcap) to get familiar with topic. Also this protocol is __reliable__, which means transfer will continue even if one of two interfaces goes down for any reason. If interface that went down, comes back online, this protocol will continue using that interface.

## Usage

### Starting the reciever

Reciever listens on device available devices (eth, wlan) and will start recieving packets, only from defined ports (27015, 27016) which are chosen durning develpoment. When senders starts the transfer, reciever will recognize this and will start with file recieving and assembly. Each time reciver successfully recives a packet he will send acknowledgement to sender.

Here is an example of starting the reciever from the top directory:

>sudo ./reciever

Super user privileges are needed due libpcap.

After starting, reciever will show you the list of available devices and ask you to chose your device interfaces, ethernet and wireless respectively. If user fails to do so, program should close. Durning file transfer it will print out the percentage of transfer completion, and will tell you when the transfer is completed. Recieved file will be present in same directory as reciever.o.

### Starting the sender

Sender will attempt to send packets that contain file parts to reciever, after he sends each packet he will wait to get acknowledgement from reciever for a certain time period, if ack doesen't arrive he will resend that packet, and if he doesen't get ack after multiple atempts he will recognize that interface is down and notify the user about that. If interface comes back up, sender will again notify user about that event and will continue using that interface. Both sender and reciever use predefined ports 27015 and 27016.

Here is an example of starting the sender from the top directory:

>sudo ./sender path_to_file_you_wish_to_send

After starting, sender will show list of available devies and ask user to chose devices interfaces, ethernet and wireless respctively. If user fails to do so, program will malfunction. When the transfer is complete, it will print out time transmision took and will close.

## Statistics

Graphs that show transfer statistics.

![alt text](https://user-images.githubusercontent.com/9517614/27356886-834f93b8-5610-11e7-86ae-7e81735a677b.jpg)

![alt text](https://user-images.githubusercontent.com/9517614/27356887-8351575c-5610-11e7-972d-2fa0d49444d0.jpg)

## Contributing

 __Note that this program is still under heavy development, so it has mac addresses and ip adresses hardcoded, this will be changed in later versions of program.__
In this version of program multi reciever platform is not yet implemented, but it is itended in later versions of program. Also there are few bugs that sometimes occur due libpcap filter compiling, and causes program to crash. This will be patched in later versions.

## Help

For any questions, bugs, or development you can contact us:  
* stevan.stevic4343@gmail.com
* marko.godra@gmail.com

## Installation

### Requirements

You will need...
* CMake
* *gcc and g++* - C/C++ compiler for Linux or *MinGW* for Windows
* [libpcap](http://www.tcpdump.org/) for Linux or WinPcap for Windows - Library that provides network functionalities, and it is core of this program.
* clang-format-3.8 - Application that formats source code (optional)
* Unix-like, Debian-based host (the implementation was tested on Ubuntu14.04)
* (or Windows 7 or later)
* If you are using Windows we suggest that you use Qt creator for running the project.

### Installation

#### For Linux

You should postion yourself in desired directory. For example, if you want to be downloaded in Home directory simply type:  
>cd ~

Next step is to get the program:
>git clone https://github.com/stevanStevic/UDP-Over-Multiple-Simultaneous-Interfaces
>cd UDP-Over-Multiple-Simultaneous-Interfaces

And after that just type in few simple comands:

>CMake CMakeLists.txt
>make

That's it. Now you are ready!

#### For Windows

Just use QtCreator to open the project. Setup needed for development kits (Click [**Here**](https://www.youtube.com/watch?v=eZ-HOc2P_EI) for video guide on how to do that). 

### Configuration

No further configuration is needed.

## Credits

Project authors are:
* Marko Dragojevic
* Stevan Stevic

It is done as part of our final exam for _Fundamentals of Computer Networks 2_ course.

## License

It uses GPL-3.0
