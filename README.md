README v0.0 / DECEMBER 2016

# TopicServer

## Introduction

A simple client - server demonstration of classic topic server with unlimited number of subscribers, as well as publishers. Read [**this**](https://en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern) to get familiar with this topic.  
This server forwards publishers messages for given topic to subscribed clients. It does that by implementing **hash map** that has **keys** with _topic names_, and **values** as _list_ of subscribed users. It does not store messages anywhere during that proccess.

## Usage

###Starting the server

Server listens for connections both from subscribers and from publishers. It _distinguishes_ subscribers from publisher _over the port_ they used to connect to server. That being said, ports **need to be provided** to server when starting it, because there are no default ports. This is done using -s and -p flag for subscribers, publishers respectively. If you don't provide right flags you will see error codes:  
* 1 - Number of arguments is not valid.
* 2 - Flags are not correctly set.
* 3 - Invalid flag is used.

Server lets ports to be initalised from full range 0 - 65535, but if they are reserved, OS will give error message (usually about permissions). It is not recommended to mess with that, instead change port to other (higher are more likely to work).

Here is an example of starting the server from the top directory:

>./out/server -p 30000 -s 27015

Server will try to create socket for publisher at port 30000 and port for subscribers at 27015. If successfull it will print info about that, and start listening for connections.

This is the output for this example, when started:

>Port for publishers: 30000  
>Port for subscribers: 27015  
>To shutdown server type: quit/QUIT  
>Socket for publishers created!  
>Socket for subscribers created!  

####Server Usage
Server is not interactive, except when command quit/QUIT is entered. It only provides information on new connections or when someone disconnects.  
Command **quit/QUIT** is self-explanatory and tells the server to go down.

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
