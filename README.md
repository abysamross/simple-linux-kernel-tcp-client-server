# simple-linux-kernel-tcp-client-server
A simple in-kernel tcp client and server implemented as LKMs (linux kernel
version 4.1.3)

This is an attempt to build a tcp server, entirely in kernel space, that supports mulitple tcp clients. The tcp client is also entirely in kernel space.

The client and server are built as loadable kernel modules.

**To try this out:**

1. clone this repo to server machine.
2. open network_server.c 
    * change the port number of your server.
    * sorry, this will soon be changed to module parameter.
3. make
4. sudo insmod network_server.ko
5. keep observing dmesg out.
6. clone this repo to client machine.
7. before inserting the client, open network_client.c
    * change the ip and port number to that of your server.
    * again, this too will soon be changed to module parameters.
8. make 
9. sudo insmod  network_client.ko

**Status:**

Work almost done.
