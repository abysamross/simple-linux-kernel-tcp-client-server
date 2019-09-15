#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/utsname.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");

#define PORT            2325
#define LEN             49
#define IPADDRLEN       5
#define OCTET_BYTES     8

#define pr_error(err)   do {                                                                            \
                            pr_info("MODULE: %s | VERSION: %s | FUNC: %s() | LINE: %d | ERROR: %d\n",   \
                                    THIS_MODULE->name, THIS_MODULE->version, __func__, __LINE__, err);  \
                        } while (0)

#define pr_banner() do {                                                                        \
                        pr_info("MODULE: %s | VERSION: %s | FUNC: %s() | LINE: %d |\n",         \
                                THIS_MODULE->name, THIS_MODULE->version, __func__, __LINE__);   \
                    } while (0)

struct socket *conn_socket = NULL;

u32 create_address(u8 *ip)
{
    u32 addr = 0;
    int octet_index;

    if (NULL != ip) {

        for(octet_index = 0; octet_index < IPADDRLEN - 1; octet_index++)
        {
            addr <<= OCTET_BYTES;
            addr += ip[octet_index];
        }
    }

    return addr;
}

int tcp_client_send(struct socket *sock, const char *buf, const size_t length, unsigned long flags)
{
    struct msghdr msg;
    //struct iovec iov;
    struct kvec vec;
    int len, written = 0, left = length;
    mm_segment_t oldmm;

    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    /*
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    */
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags   = flags;

    oldmm = get_fs(); set_fs(KERNEL_DS);
repeat_send:
    /*
    msg.msg_iov->iov_len  = left;
    msg.msg_iov->iov_base = (char *)buf + written; 
    */
    vec.iov_len = left;
    vec.iov_base = (char *)buf + written;

    //len = sock_sendmsg(sock, &msg, left);
    len = kernel_sendmsg(sock, &msg, &vec, left, left);
    if((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) &&\
                            (len == -EAGAIN)))
            goto repeat_send;
    if(len > 0)
    {
            written += len;
            left -= len;
            if(left)
                    goto repeat_send;
    }
    set_fs(oldmm);
    return written ? written:len;
}

int tcp_client_receive(struct socket *sock, char *str,\
                        unsigned long flags)
{
    //mm_segment_t oldmm;
    struct msghdr msg;
    //struct iovec iov;
    struct kvec vec;
    int len;
    int max_size = 50;

    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    /*
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    */
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags   = flags;
    /*
    msg.msg_iov->iov_base   = str;
    msg.msg_ioc->iov_len    = max_size; 
    */
    vec.iov_len = max_size;
    vec.iov_base = str;

    //oldmm = get_fs(); set_fs(KERNEL_DS);
read_again:
    //len = sock_recvmsg(sock, &msg, max_size, 0); 
    len = kernel_recvmsg(sock, &msg, &vec, max_size, max_size, flags);

    if(len == -EAGAIN || len == -ERESTARTSYS)
    {
            pr_info(" *** mtp | error while reading: %d | "
                    "tcp_client_receive *** \n", len);

            goto read_again;
    }


    pr_info(" *** mtp | the server says: %s | tcp_client_receive *** \n", str);
    //set_fs(oldmm);
    return len;
}

int tcp_client_connect(void)
{
    struct sockaddr_in saddr;
    unsigned char destip[IPADDRLEN] = {192, 168, 1, 133, '\0'};
    int len = LEN;
    char response[LEN + 1];
    char reply[LEN + 1];
    int ret = -1;

    DECLARE_WAIT_QUEUE_HEAD(recv_wait);
    
    ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);

    if (ret) {

        pr_error(ret);
        goto err;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(PORT);
    saddr.sin_addr.s_addr = htonl(create_address(destip));

    ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in), O_RDWR);

    if (ret && (ret != -EINPROGRESS)) {

        pr_error(ret);
        goto err;
    }

    memset(&reply, 0, len + 1);
    strcat(reply, "HOLA"); 

    tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);

    wait_event_timeout(recv_wait, !skb_queue_empty(&conn_socket->sk->sk_receive_queue), 5*HZ);

    if  (!skb_queue_empty(&conn_socket->sk->sk_receive_queue)) {

        memset(&response, 0, len + 1);
        tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
    }

err:
    return -1;
}

static int __init network_client_init(void)
{
    pr_info("\n==============\n");
    pr_info("MODULE DETAILS\n");
    pr_info("==============\n\n");

    pr_info("Kernel Version: %s\n", utsname()->version);
    pr_info("Kernel Release: %s\n", utsname()->release);
    pr_banner();
    tcp_client_connect();
    return 0;
}

static void __exit network_client_exit(void)
{
    int len = LEN;
    char response[LEN+1];
    char reply[LEN+1];

    DECLARE_WAIT_QUEUE_HEAD(exit_wait);

    memset(&reply, 0, len+1);
    strcat(reply, "ADIOS"); 
    tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);

    wait_event_timeout(exit_wait, !skb_queue_empty(&conn_socket->sk->sk_receive_queue), 5*HZ);

    if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue)) {

            memset(&response, 0, len+1);
            tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
    }


    if(conn_socket != NULL) {

            sock_release(conn_socket);
    }

    pr_info("\n==============\n");
    pr_info("MODULE REMOVED\n");
    pr_info("==============\n\n");
    pr_info("Kernel Version: %s\n", utsname()->version);
    pr_info("Kernel Release: %s\n", utsname()->release);
    pr_banner();
}

module_init(network_client_init)
module_exit(network_client_exit)
