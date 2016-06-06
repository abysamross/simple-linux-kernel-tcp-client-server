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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");

#define PORT 2325

struct socket *conn_socket = NULL;

u32 create_address(u8 *ip)
{
        u32 addr = 0;
        int i;

        for(i=0; i<4; i++)
        {
                addr += ip[i];
                if(i==3)
                        break;
                addr <<= 8;
        }
        return addr;
}

int tcp_client_send(struct socket *sock, const char *buf, const size_t length,\
                unsigned long flags)
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
        /*
        struct sockaddr_in daddr;
        struct socket *data_socket = NULL;
        */
        unsigned char destip[5] = {10,129,41,200,'\0'};
        /*
        char *response = kmalloc(4096, GFP_KERNEL);
        char *reply = kmalloc(4096, GFP_KERNEL);
        */
        int len = 49;
        char response[len+1];
        char reply[len+1];
        int ret = -1;

        //DECLARE_WAITQUEUE(recv_wait, current);
        DECLARE_WAIT_QUEUE_HEAD(recv_wait);
        
        ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
        if(ret < 0)
        {
                pr_info(" *** mtp | Error: %d while creating first socket. | "
                        "setup_connection *** \n", ret);
                goto err;
        }

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(PORT);
        saddr.sin_addr.s_addr = htonl(create_address(destip));

        ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr\
                        , sizeof(saddr), O_RDWR);
        if(ret && (ret != -EINPROGRESS))
        {
                pr_info(" *** mtp | Error: %d while connecting using conn "
                        "socket. | setup_connection *** \n", ret);
                goto err;
        }

        memset(&reply, 0, len+1);
        strcat(reply, "HOLA"); 
        tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);

        wait_event_timeout(recv_wait,\
                        !skb_queue_empty(&conn_socket->sk->sk_receive_queue),\
                                                                        5*HZ);
        /*
        add_wait_queue(&conn_socket->sk->sk_wq->wait, &recv_wait);
        while(1)
        {
                __set_current_status(TASK_INTERRUPTIBLE);
                schedule_timeout(HZ);
        */
                if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue))
                {
                        /*
                        __set_current_status(TASK_RUNNING);
                        remove_wait_queue(&conn_socket->sk->sk_wq->wait,\
                                                              &recv_wait);
                        */
                        memset(&response, 0, len+1);
                        tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
                        //break;
                }

        /*
        }
        */

err:
        return -1;
}

static int __init network_client_init(void)
{
        pr_info(" *** mtp | network client init | network_client_init *** \n");
        tcp_client_connect();
        return 0;
}

static void __exit network_client_exit(void)
{
        int len = 49;
        char response[len+1];
        char reply[len+1];

        //DECLARE_WAITQUEUE(exit_wait, current);
        DECLARE_WAIT_QUEUE_HEAD(exit_wait);

        memset(&reply, 0, len+1);
        strcat(reply, "ADIOS"); 
        //tcp_client_send(conn_socket, reply);
        tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);

        //while(1)
        //{
                /*
                tcp_client_receive(conn_socket, response);
                add_wait_queue(&conn_socket->sk->sk_wq->wait, &exit_wait)
                */
         wait_event_timeout(exit_wait,\
                         !skb_queue_empty(&conn_socket->sk->sk_receive_queue),\
                                                                        5*HZ);
        if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue))
        {
                memset(&response, 0, len+1);
                tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
                //remove_wait_queue(&conn_socket->sk->sk_wq->wait, &exit_wait);
        }

        //}

        if(conn_socket != NULL)
        {
                sock_release(conn_socket);
        }
        pr_info(" *** mtp | network client exiting | network_client_exit *** \n");
}

module_init(network_client_init)
module_exit(network_client_exit)
