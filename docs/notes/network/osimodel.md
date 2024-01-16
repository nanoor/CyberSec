---
id: h2fzkjkvklqm0lsoxupxy84
title: OSI Model
desc: 'THM: Learn about the fundamental networking framework that determines the various stages in which data is handled across a network.'
updated: 1678217269223
created: 1675957790480
---
### Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
- [2. Layer 7 - Application](#2-layer-7---application)
- [3. Layer 6 - Presentation](#3-layer-6---presentation)
- [4. Layer 5 - Session](#4-layer-5---session)
- [5. Layer 4 - Transport](#5-layer-4---transport)
- [6. Layer 3 - Network](#6-layer-3---network)
- [7. Layer 2 - Data Link](#7-layer-2---data-link)
- [8. Layer 1 - Physical](#8-layer-1---physical)

---

### 1. Introduction
The Open Systems Interconnection Model (OSI model) is a fundamental model used in networking that provides a framework dictating how all networked devices will communicate and interpret data. OSI provides a measure of standardization by ensuring data sent across a network follows the uniformity of OSI model.

The OSI model consists of seven layers as illustrated below. The following sections will briefly discuss each layer in the OSI model and its function. TCP/IP model is shown as a comparison however, this model will not be discussed here.

![OSI Model](./assets/thm/osi_model/OSI.png)

### 2. Layer 7 - Application
The application layer of the OSI model is the layer most people are familiar with. The application layer ensures that an application can effectively communicate with other applications and acts as a user interface responsible for displaying received information to the end-user. Data input and output typically takes place at this level.

It should be noted that the application layer is not an application but is instead a set of protocols and rules within the application which controls the communication method to other devices and provides connections to the lower levels.

The application layer of the OSI model essentially provides networking options to programs running on a computer. It works almost exclusively with applications, providing an interface for them to use in order to transmit data. When data is given to the application layer, it is passed down into the presentation layer.

### 3. Layer 6 - Presentation
The presentation layer is responsible for the delivery and formatting of information to the application layer for further processing or display. It is at this layer where standardization of data structure begins to take place as the main purpose of this layer is to relieve the application layer of concern regarding syntactical differences in data representation with the end-user system.

The presentation layer is the lowest layer at which developers consider data structure and presentation instead of sending data as packets between hosts. Encryption and decryption are typically handled at this level.

Typical services handled at the presentation layer include:
  - Data conversion
  - Character code translation
  - Compression
  - Encryption and Decryption

Note tha the presentation layer is usually composed of 2 sub-layers:
  - Common Application Service Element (CASE)
  - Specific Application Service Element (SASE)

### 4. Layer 5 - Session
The session layer provides the mechanism for opening, closing and managing a session (connection) between end-user application processes. When a connection is established between two devices/processes, a session is created. This session remains alive as long as the connection remains active. The created sessions are unique and data meant for one session cannot travel over different sessions. This is what allows you to make multiple requests to different endpoints simultaneously without all the data getting mixed up.

The session layer will typically segment data into smaller packets before issuing service requests to the transport layer.

Typical services provided by the session layer are as follows:
  - Authentication
  - Authorization
  - Session restoration and synchronization
  
### 5. Layer 4 - Transport
The transport layer of the OSI model is instrumental in transmitting data across network. The task of the transport layer include the segmentation of data stream and in relieving congestion in the network. Data transport through this layer is done through transport layer protocols such as the Transmission Control Protocol (TCP) or the User Datagram Protocol (UDM).

TCP is a connection-oriented protocol that requires a three-way-handshake (SYN --> SYN/ACK --> ACK) and reserves a constant connection between the two devices for the duration of data transfer. TCP provides reliable data transfer with error checking, flow control and congestion control at the cost of speed.

TCP is typically used for applications such as file sharing, internet browsing and use-cases where transmitted data integrity is critical.

UDP is much simpler than TCP as this protocol does not support features such as error checking and reliability through retransmission. There is no synchronization between devices and as such dropped packets are not retransmitted (stateless). Essentially, data sent via UDP is transmitted to a device without checks on whether the data was successfully received or not. These checks are typically left to the application layer. 

The lack of synchronization does have the benefit of making the UDP protocol faster than TCP. Furthermore, UDP does not reserve a continuous connection on a device like TCP; however, this can lead to poor user experience in the event of an unstable connection.

UDP is typically used for applications involving video or audio streaming.

The following are some typical services performed by the transport layer depending on the transport protocol used:
  - Connection-oriented communication
  - Same order delivery
  - Reliability
  - Flow control
  - Congestion avoidance
  - Port Multiplexing

### 6. Layer 3 - Network
The network layer is responsible for packet forwarding including routing through intermediate routers and reassembling data packets. Layer 3 ensures that routing happens through the most optimal path either through OSPF (Open Shortest Path First) or RIP (Routing Information Protocol). The factors that decide what route is taken is decided by the following:
  - What path is the shortest?
  - What path is the most reliable?
  - Which path has the faster physical connection?

The network layer uses network addresses (IP addresses) to route packets to a destination node. Devices which are capable of delivering data packets using IP addresses are known as Layer 3 devices (because they are capable of working at hte third layer of the OSI model).

Some key functions of the network layer are:
  - Connection model
  - Host addressing
  - Message forwarding

### 7. Layer 2 - Data Link
The data link layer is responsible for data transfer between adjacent network nodes in WAN or between nodes on the same LAN segment. This layer provides the functional and procedural means to transfer data between network entities and may also provide the means to detect and possibly correct errors that occur in the physical layer.

The data link layer also focuses on the physical addressing of the transmission. It receives a data packet from the network layer (including the IP address for the remote device) and adds in the Media Access Control address (MAC) of the receiving end-point. MAC addresses are used to identify the destination of data packets in a network.

The data link layer is composed of two parts: 
  - Logical Link Control (LLC) which identifies network protocols, performs error checking and frame synchronization.
  - Media Access Control (MAC) which uses MAC addresses to connect devices and define permissions to transmit and receive data.

Some key services performed by the data link layer are:
  - Encapsulation
  - Frame synchronization
  - Logical link control (error & flow control)
  - Media Access Control (MAC, LAN switching, Physical addressing, VLAN)

### 8. Layer 1 - Physical
The physical layer is the lowest layer in the OSI model and provides mechanical, electrical and other functions to maintain and transmit bits through physical connections. The physical layer is a fundamental layer underlying the logical data structures of the higher level functions in a network.

The physical layer defines the means of transmitting raw bits rather than logical data packets over a physical link connecting the network nodes. Within the semantics of the OSI model, the physical layer translates logical communications requests from the data link layer into hardware specific operations.