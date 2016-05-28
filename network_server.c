#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/unistd.h>
#include <linux/wait.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>

#define DEFAULT_PORT 2325
//#define CONNECT_PORT 23
#define MODULE_NAME "tmem_tcp_server"
#define MAX_CONNS 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");

//static atomic_t recv_count;
//static atomic_t send_count;

static int tcp_listener_stopped = 0;
static int tcp_acceptor_stopped = 0;
//static int tcp_conn_handler_stopped = 0;
//static struct task_struct *thread_id[MAX_CONNS];

DEFINE_SPINLOCK(tcp_server_lock);

struct tcp_conn_handler
{
        struct task_struct *thread[MAX_CONNS];
        int tcp_conn_handler_stopped[MAX_CONNS]; 
};

struct tcp_conn_handler *tcp_conn_handler;

struct tcp_conn_handler_data
{
        struct socket *accept_socket;
        int thread_id;
};

struct tcp_server_service
{
      int running;  
      struct socket *listen_socket;
      struct task_struct *thread;
      struct task_struct *accept_thread;
};

struct tcp_server_service *tcp_server;

int tcp_server_send(struct socket *sock, int id, const char *buf,\
                const size_t length, unsigned long flags)
{
        struct msghdr msg;
        struct kvec vec;
        int len, written = 0, left =length;
        mm_segment_t oldmm;

        msg.msg_name    = 0;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = flags;
        msg.msg_flags   = 0;

        oldmm = get_fs(); set_fs(KERNEL_DS);

repeat_send:
        vec.iov_len = left;
        vec.iov_base = (char *)buf + written;

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
        return written?written:len;
}

int tcp_server_receive(struct socket *sock, int id, unsigned char *buf,int size,\
                        unsigned long flags)
{
        struct msghdr msg;
        struct kvec vec;
        int len;
        
        if(sock==NULL)
        {
                pr_info(" *** mtp | tcp server receive socket is NULL| "
                        " tcp_server_receive *** \n");
                return -1;
        }

        msg.msg_name = 0;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = flags;

        vec.iov_len = size;
        vec.iov_base = buf;

read_again:

        if(kthread_should_stop())
        {
                pr_info(" *** mtp | tcp server handle connection thread "
                        "stopped | tcp_server_receive *** \n");
                tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;
                //sock_release(sock);
                do_exit(0);
        }

        len = kernel_recvmsg(sock, &msg, &vec, size, size, flags);

        if(len == -EAGAIN || len == -ERESTARTSYS)
                goto read_again;

        pr_info(" *** mtp | the client says: %s | tcp_server_receive "
                "*** \n", buf);

        return len;
}

int connection_handler(void *data)
{
       struct tcp_conn_handler_data *conn_data = 
               (struct tcp_conn_handler_data *)data;

       struct socket *accept_socket = conn_data->accept_socket;
       int id = conn_data->thread_id;

       int ret; 
       int len = 49;
       unsigned char in_buf[len+1];
       unsigned char out_buf[len+1];

       memset(in_buf, 0, len+1);
       pr_info("receive the package\n");

       while((ret = tcp_server_receive(accept_socket, id, in_buf, len,\
                                       MSG_DONTWAIT)))
       {
               //if(kthread_should_stop())
               //{
               //        pr_info(" *** mtp | tcp server acceptor thread "
               //                "stopped | tcp_server_accept *** \n");
               //        tcp_acceptor_stopped = 1;
               //        do_exit(0);
               //}
               if(ret == 0)
                       continue;

               memset(out_buf, 0, len+1);
               strcat(out_buf, "kernel server: hi");
               pr_info("sending the package\n");
               tcp_server_send(accept_socket, id, out_buf, strlen(out_buf),\
                               MSG_DONTWAIT);
       }

       tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;
       return 0;
}

int tcp_server_accept(void)
{
        int ret = 0;
        int err = 0;
        struct socket *socket;
        struct socket *accept_sock;
        struct inet_connection_sock *isock; 
        int id = 0;

        //int len = 49;
        //unsigned char in_buf[len+1];
        //unsigned char out_buf[len+1];

        DECLARE_WAITQUEUE(wait, current);

        spin_lock(&tcp_server_lock);
        tcp_server->running = 1;
        current->flags |= PF_NOFREEZE;
        allow_signal(SIGKILL|SIGSTOP);
        spin_unlock(&tcp_server_lock);

        socket = tcp_server->listen_socket;
        pr_info(" *** mtp | creating the accept socket | tcp_server_accept "
                "*** \n");
        accept_sock = (struct socket*)kmalloc(sizeof(struct socket), GFP_KERNEL);
        
        err =  sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &accept_sock);
        if(err < 0)
        {
                pr_info(" *** mtp | Error: %d while creating tcp server "
                        "accept socket | tcp_server_accept *** \n", err);
                goto bad_exit;
        }

        isock = inet_csk(socket->sk);

        while(tcp_server->running == 1)
        {
               struct tcp_conn_handler_data *data = NULL;
                
               if(reqsk_queue_empty(&isock->icsk_accept_queue))
               {
                       add_wait_queue(&socket->sk->sk_wq->wait, &wait);
                       //__set_current_state(TASK_INTERRUPTIBLE);
                       set_current_state(TASK_INTERRUPTIBLE);

                       //change this HZ to about 5 mins in jiffies
                       schedule_timeout(HZ);

                        pr_info("icsk queue empty ? %s \n",
                        reqsk_queue_empty(&isock->icsk_accept_queue)?"yes":"no");

                        pr_info("recv queue empty ? %s \n",
                skb_queue_empty(&socket->sk->sk_receive_queue)?"yes":"no");

                        __set_current_state(TASK_RUNNING);
                        remove_wait_queue(&socket->sk->sk_wq->wait, &wait);

                        if(kthread_should_stop())
                        {
                                pr_info(" *** mtp | tcp server acceptor thread "
                                        "stopped | tcp_server_accept *** \n");
                                tcp_acceptor_stopped = 1;
                                sock_release(accept_sock);
                                kfree(accept_sock);
                                do_exit(0);
                        }

                        continue;
               } 

               pr_info("accept connection\n");
               ret = socket->ops->accept(socket, accept_sock, O_NONBLOCK);
               if(ret < 0)
               {
                       pr_info(" *** mtp | Error: %d while accepting tcp server"
                               " | tcp_server_accept *** \n", ret);
                       goto bad_exit;
               }

               //memset(in_buf, 0, len+1);
               //pr_info("receive the package\n");
               pr_info("handle connection\n");

               /*
               while((ret = tcp_server_receive(accept_sock, in_buf, len,\
                                               MSG_DONTWAIT)))
               {
                       //if(kthread_should_stop())
                       //{
                       //        pr_info(" *** mtp | tcp server acceptor thread "
                       //                "stopped | tcp_server_accept *** \n");
                       //        tcp_acceptor_stopped = 1;
                       //        do_exit(0);
                       //}
                       

                       if(ret == 0)
                               continue;

                       memset(out_buf, 0, len+1);
                       strcat(out_buf, "kernel server: hi");
                       pr_info("sending the package\n");
                       tcp_server_send(accept_sock, out_buf, strlen(out_buf),\
                                       MSG_DONTWAIT);
               }
               */
               for(id = 0; id < MAX_CONNS; id++)
               {
                        if(tcp_conn_handler->thread[id] == NULL)
                                break;
               }

               if(id == MAX_CONNS)
                       goto bad_exit;

               data = kmalloc(sizeof(struct tcp_conn_handler_data), GFP_KERNEL);
               memset(data, 0, sizeof(struct tcp_conn_handler_data));

               data->accept_socket = accept_sock; 
               data->thread_id = id;

               tcp_conn_handler->thread[id] = 
                kthread_run((void *)connection_handler, (void *)data,\
                               MODULE_NAME);

               if(kthread_should_stop())
               {
                       pr_info(" *** mtp | tcp server acceptor thread stopped"
                               " | tcp_server_accept *** \n");
                       tcp_acceptor_stopped = 1;
                       kfree(data);
                       sock_release(accept_sock);
                       kfree(accept_sock);
                       do_exit(0);
               }
        }

        tcp_acceptor_stopped = 1;
        return 0;

bad_exit:
       sock_release(accept_sock);
       kfree(accept_sock);
       tcp_acceptor_stopped = 1;
       return -1;
}

int tcp_server_listen(void)
{
        int ret;
        struct socket *conn_socket;
        struct sockaddr_in saddr;

        DECLARE_WAIT_QUEUE_HEAD(wq);

        spin_lock(&tcp_server_lock);
        tcp_server->running = 1;
        spin_unlock(&tcp_server_lock);

        ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP,\
                                &tcp_server->listen_socket);
        if(ret < 0)
        {
                pr_info(" *** mtp | Error: %d while creating tcp server "
                        "listen socket | tcp_server_listen *** \n", ret);
                goto err;
        }

        conn_socket = tcp_server->listen_socket;
        tcp_server->listen_socket->sk->sk_reuse = 1;

        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(DEFAULT_PORT);

        ret = 
        conn_socket->ops->bind(conn_socket, (struct sockaddr*)&saddr,\
                        sizeof(saddr));
        if(ret < 0)
        {
                pr_info(" *** mtp | Error: %d while binding tcp server "
                        "listen socket | tcp_server_listen *** \n", ret);
                goto err;
        }

        //while(1)
        //{
        ret = conn_socket->ops->listen(conn_socket, 16);

        if(ret < 0)
        {
                pr_info(" *** mtp | Error: %d while listening in tcp "
                        "server listen socket | tcp_server_listen "
                        "*** \n", ret);
                        goto err;
        }

        tcp_server->accept_thread = 
                kthread_run((void*)tcp_server_accept, NULL, MODULE_NAME);
        while(1)
        {
                wait_event_timeout(wq, 0, 3*HZ);

                if(kthread_should_stop())
                {
                        pr_info(" *** mtp | tcp server listening thread"
                                " stopped | tcp_server_listen *** \n");
                        tcp_listener_stopped = 1;
                        do_exit(0);
                }
        }
        //}

        tcp_listener_stopped = 1;
        return 0;
err:
        tcp_listener_stopped = 1;
        return -1;
}

int tcp_server_start(void)
{
        tcp_server->running = 1;
        tcp_server->thread = kthread_run((void *)tcp_server_listen, NULL,\
                                        MODULE_NAME);
        return 0;
}

static int __init network_server_init(void)
{
        pr_info(" *** mtp | network_server initiated | "
                "network_server_init ***\n");
        tcp_server = kmalloc(sizeof(struct tcp_server_service), GFP_KERNEL);
        memset(tcp_server, 0, sizeof(struct tcp_server_service));

        tcp_conn_handler = kmalloc(sizeof(struct tcp_conn_handler), GFP_KERNEL);
        memset(tcp_conn_handler, 0, sizeof(struct tcp_conn_handler));

        tcp_server_start();
        return 0;
}

static void __exit network_server_exit(void)
{
        int ret;
        int id;

        if(tcp_server->thread == NULL)
                pr_info(" *** mtp | No kernel thread to kill | "
                        "network_server_exit *** \n");
        else
        {
                for(id = 0; id < MAX_CONNS; id++)
                {
                        if(tcp_conn_handler->thread[id] != NULL)
                        {

                        if(!tcp_conn_handler->tcp_conn_handler_stopped[id])
                                {
                                        ret = 
                                kthread_stop(tcp_conn_handler->thread[id]);

                                if(!ret)
                                        pr_info(" *** mtp | tcp server "
                                                "connection handler thread: %d "
                                                "stopped | network_server_exit "
                                                "*** \n", id);
                                }
                       }

                }

                if(!tcp_acceptor_stopped)
                {
                        ret = kthread_stop(tcp_server->accept_thread);
                        if(!ret)
                                pr_info(" *** mtp | tcp server acceptor thread"
                                        " stopped | network_server_exit *** \n");
                }

                if(!tcp_listener_stopped)
                {
                        ret = kthread_stop(tcp_server->thread);
                        if(!ret)
                                pr_info(" *** mtp | tcp server listening thread"
                                        " stopped | network_server_exit *** \n");
                }


                if(tcp_server->listen_socket != NULL)
                {
                        sock_release(tcp_server->listen_socket);
                        tcp_server->listen_socket = NULL;
                }

                kfree(tcp_conn_handler);
                kfree(tcp_server);
                tcp_server = NULL;
        }

        pr_info(" *** mtp | network server module unloaded | "
                "network_server_exit *** \n");
}

module_init(network_server_init)
module_exit(network_server_exit)

