**User-facing features we hope to implement:**

* Progress bar (sending and receiving)  
* We are going to limit ourselves to downloading one file from one client at a time  
  * Can download multiple files from one or more clients, but any one file will only ever have one seed/uploader.  
* Add protocol to enable downloaders to request some IP’s catalog, then sender’s client can passively process that request and send their available (“tracked”) files back to the requester  
* Add protocol to enable downloaders to request a specific file  
* Ideally indicate to the uploader if there is a download active so they don’t quit while the download is active  
  * Maybe when the user goes to exit, if there is a download happening, warn them, and make them confirm  
  * in\_progress subcommand?

*We have 2 ideas for what our application should look like. We are leaning towards idea 1 as it seems simpler without sacrificing much usability for our target audience, but we would like your feedback.*

**Idea 1: Multiple instances run individually**

* Subcommand to start a listener process to continually serve files and respond to requests  
* Subcommand to start a requester process that requests a specific file from a listening process (ends after file is fully sent)  
* Subcommand to request available files from user or list of users  
  * Idea is that this command will be run first so that users can then start a requester process for a file/list of files  
* Ability to add files to the list of available files for users to download  
  * add schoolwork/textbook.pdf  
* Upon startup, ping all IPs in the list of addresses to see who is online and who isn’t  
  * Also have a ping subcommand


**Idea 2: One environment:**

* One calling command that creates a singular instance that handles all functionality of the application   
  * Would be able to passively listen for incoming connections/requests while also allowing user to make requests of other listeners  
  * All the subcommands listed in idea 1 would be incorporated into this singular instance  
* Launching client starts listening for incoming connections/requests  
* The sender's client passively starts sending the file packets to the requester.  
* If you are only sending files to another user, all you have to do is launch the client and leave it running in the background