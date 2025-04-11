# Liam, Lazuli, and Ruben Project Plan

## Description 
A decentralized peer-to-peer file sharing application that can send a file from one client to another.

## Learning Goals
* Rust  
* Networks  
* File upload/download  
* Fancy terminal interface (e.g. animated progress bars)  
* Given time, some sort of GUI in the terminal

## Feature Goals
* Essential  
  * Connect two peers using some identifier  
  * Sender can give identifier to receiver, connects the two clients, listening from a specific address  
    * More specific when we understand networks better :(  
  * Choose a file to send  
* Nice-to-have  
  * Fancy/interactive/animated terminal interface  
  * Encryption (using a pre-existing Rust library)  
* Stretch goals  
  * A GUI

## Description of Architecture
* Cargo for project and library management  
  * File for sender code (server)  
  * File for receiver code (client)  
  * Make our own basic network interfacing library  
  * CLI code file  
    * Handle all output the user sees and read the user input (stdin/stdout)  
    * Will be what makes the terminal fancy  
* Possibly some networking hardware (thanks Mike) if Carleton wifi doesn’t cooperate  
* Using our computers to test the file sharing capabilities

## Schedule of Development
* Learn Rust, can be done independently of each other and concurrently with other parts of project \- week 3 max  
* Research networks (can be done in parallel) \- week 3/4
  * What does the client need to do? (Ruben/Liam)
  * What does the server need to do? (Ruben/Liam)  
  * How can we talk from one machine to another? (Lazuli)  
    * How to open a P2P connection between two clients  
  * How can we send a file over a connection? (Lazuli)  
  * What are P2P best practices/methods? (Lazuli)  
* Write network code \- week 4-5
  * We don’t know how to break this up now (it all seems very interrelated). Comments are appreciated  
* Design CLI \- 6
* Create CLI \- 6/7
  * Break up aspects of design between members  
* Improve user experience with progress bar and file information (Lazuli) \- week 6/7
* Encryption? \- week 7/8
* Handle multiple OSs? \- week 8/9

## Worries
* Networking can be opaque  
  * Writing our own network code sounds daunting right now  
* Breaking up work effectively to allow us to work independently  
  * Networking seems very interrelated—it seems natural that the same person could write client and server.

## Communication Plan and Meeting Schedule
* Group chat  
* Meet in class, as needed outside of class  
* Whentomeet for availability

## Ensuring All Team Members Contribute Substantially
* Debriefing during (weekly-ish) meetings, will hold us accountable to have something to bring to meeting  
* Politely tell slacker to do more work, help them come up with a plan to catch up/contribute more if needed  
* Also make sure that 1 person doesn’t get so far ahead that others don’t know what’s going on
