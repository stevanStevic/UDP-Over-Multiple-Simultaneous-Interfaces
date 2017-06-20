README v0.0 / DECEMBER 2016

# TopicServer

## Introduction

A demonstration of custom UDP based protocol that uses two interfaces (Wifi and ethernet) to transfer any kind of files between two users. Actual data transfer is concurent and it is based on data race. Sender parses file and sends those parsed pieces to reciever, who reconsturcts file from recieved segements. Both, sender and reciever have buffer in which they store file parts (sender gets file parts from segmenter, and reciever gets file parts from captured packets and asembler combines them into a single file). Whole protocl is based on pcap library. Read [**this**](https://en.wikipedia.org/wiki/Pcap) to get familiar with topic. Also this protocol is reliable, which means transfer will continue even if one of two interfaces goes down for any reason. If interface that went down, comes back online, this protocol will continue using that interface.

## Usage

###Starting the reciever

Reciever listens on device available devices (eth, wlan) and will start recieving packets, only from defined ports (27015, 27016) which are chosen durning develpoment. When senders starts the transfer, reciever will recognize this and will start with file recieving and assembly.

Here is an example of starting the reciever from the top directory:

>sudo ./reciever

Super user privileges are needed due libpcap.

After starting, reciever will show you the list of available devices and ask you to chose your device interfaces, ethernet and wireless respectively. If you fail to do so, program should close. Durning file transfer it will print out the percentage of transfer completion, and will tell you when the transfer is completed. Recieved file will be present in same directory as reciever.o.

####Starting the Subscriber
Subscriber is used when you want to recive info about certain topic. Info is provided by publishers.  
To start subscriber you use **client** executive, because it is adjusted to be used by both subscriber and publisher.  
You have to provide server's port number on which you want to connect. You decide which, based on your intentions - do you want to be susbcriber or publisher. This is done using -p flag.  
Also you need server's ip. This is done using -i flag.

Here is an example of starting the server from the top directory, and connecting to you local host:  
>./out/server -p 27015 -i 127.0.0.1

Client will try to connect to this address and port, if successful you'll get following output:
>You have successfully connected to: 127.0.0.1 : 27015  
>If you want to communicate with the server, type in your message and press enter 

####Subscriber usage
Subscriber has 3 commands:
* **Subscribe**  
	This command will subscribe you to specifed topic, so you could do that like this:  
	>SUBSCRIBE FOOD

	If topic dosen't exist you will get this message:  
	>Specifed topic is not active, or it does'nt exist. Check your spelling, or try later!

	Else you will recive following message:  
	>You will publish information for topic: FOOD!

* **Unsubscribe**  
	This command will unsubscribe tou from specifed topic, example:  
	>UNSUBSCRIBE FOOD

	If successful this is the message:  
	>You are sussccesfully unsubscribed! 

* **Quit**  
	This will get you off the server and quit program.

They are all case insensitive.

In the mean time you are listening for incoming messages from publishers. When they come you will recive them in this format:  
>[FOOD] I like eggs!

####Starting the publisher
Publisher has 2 commands:
* **Publish**
	This command will send information from publisher to subscribers. Here is th example:
	>PUBLISH FOOD I like eggs!

* **Quit**
	This will quit and remove topic from hash map.

They are all case insensitive.

## Contributing

For now, only one publisher should publish news, because every time one disconnects, list of subscribers for that topic is erased and the topic is removed from the hash map. If two publishers provide info for the same topic, and one disconnects, list of subscribers is erased and topic removed although second is still active.  
This happens because topics are not connected to publishers ip's. One of the ways to solve this is to implement another hashmap that also connects topics for list of publishers and keeps topics active as long as that list is not empty.  
This could be patched.

## Help

For any questions, bugs, or development you can contact us:  
* stevan.stevic4343@gmail.com
* marko.godra@gmail.com

## Installation

### Requirements

You will need...
* *gcc* - C/C++ compiler.
* [glib2](https://developer.gnome.org/glib/) - Library that provides the core application building blocks for libraries and applications written in C.
* clang-format-3.8 - Application that formats source code (optional)
* Unix-like, Debian-based host (the implementation was tested on Ubuntu14.04)

Or, you can just type:  
>make install

### Installation

You should postion yourself in desired directory. For example, if you want to be downloaded in Home directory simply type:  
>cd ~

Next step is to get the program:
>git clone https://github.com/stevanStevic/TopicServer  
>cd TopicServer

Now, you need to install applications and programs from **Requirements** section or just type:  
>make install  
>make  

to install and compile programs.

That's it. Now you are ready!

### Configuration

No further configuration is needed.

## Credits

Project atuhors are:
* Marko Dragojevic
* Stevan Stevic

It is done as part of our final exam for _Fundamentals of Computer Networks 1_ course.

## License

It uses GPL-3.0
