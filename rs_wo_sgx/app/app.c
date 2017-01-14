#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <mqueue.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "epoll_utils.h"
#include "agent_ecall_funcs.h"
#include "msg_buffer.h"
#include "socket_utils.h"
#include "const.h"
#include "datatypes.h"

#define REMOTE_NETWORK 0
#define LOCAL_NETWORK 1

typedef struct {
    uint32_t id;
    ds_t *p_ds;
} app_read_closure_t;

char g_rn_to_agnt_mq_name[AGNT_NUM][STR_LEN];
char g_agnt_to_rn_mq_name[AGNT_NUM][STR_LEN];

char g_ln_to_agnt_mq_name[AGNT_NUM][STR_LEN];
char g_agnt_to_ln_mq_name[AGNT_NUM][STR_LEN];

static mqd_t g_app_rn_sender_mqds[AGNT_NUM];
static mqd_t g_app_ln_sender_mqds[AGNT_NUM];

static int g_rn_sender_sockfds[AS_NUM] = {[0 ... AS_NUM-1] = -1};

static void app_handle_read_rn_agnt_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, diff, msg_size, offset = 0;
    char buffer[BUFFER_SIZE], *msg;
    bgp_message_t *bgp_msg;
    int as_sfd;
    app_read_closure_t *closure = h->closure;

    //// fprintf(stdout, "\n[app] read event from mqd:%d <-> agent:%d [%s]\n", h->fd, closure->id, __FUNCTION__);

    while (1) {
        bytes = mq_receive(h->fd, buffer, BUFFER_SIZE, NULL);

        // we have read all messages, the mqueue is empty
        if (bytes == -1 && errno == EAGAIN) {
            break;
        }

        // mqueue error
        if (bytes == -1) {
            // fprintf(stdout, "\n[app] mq_receive failed from agent %d, err: %s [%s]\n", closure->id, strerror(errno), __FUNCTION__);
            return;
        }

        //// fprintf(stdout, "\n[app] mq_receive %d bytes from agent %d [%s]\n", bytes, closure->id, __FUNCTION__);

        // add received buffer to local flow buffer to extract messages
        append_ds(closure->p_ds, buffer, bytes);
    }

    while (1) {
        get_msg(closure->p_ds, &msg, &msg_size);
        if (msg == NULL || msg_size == 0) {
            // we have processed all available msgs
            break;
        }
        bgp_msg = (bgp_message_t *) msg;
        as_sfd = g_rn_sender_sockfds[bgp_msg->dst_id];
        if (as_sfd == -1) {
            // fprintf(stdout, "\n[app] get %d bytes msg from agent %d to as %d, while socket fd is -1 [%s]\n", msg_size, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            continue;
        } else {
            // fprintf(stdout, "\n[app] get %d bytes msg from agent %d to as %d [%s]\n", msg_size, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
        }

        // send the msg
        while (msg_size != offset) {
            diff = msg_size - offset;
            bytes = (diff <= MAX_MSG_SIZE) ? diff : MAX_MSG_SIZE;
            if (write(as_sfd, bgp_msg + offset, bytes) == -1) {
                // fprintf(stdout, "\n[app] write socket failed to as %d, as_sfd %d, err: %s [%s]\n", bgp_msg->dst_id, as_sfd, strerror(errno), __FUNCTION__);
            } else {
                //// fprintf(stdout, "\n[app] write socket %d bytes successfully, to as %d, as_sfd %d [%s]\n", bytes, bgp_msg->dst_id, as_sfd, __FUNCTION__);
                offset += bytes;
            }
        }
        offset = 0;
    }
}

static void app_handle_read_ln_agnt_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, diff, msg_size, offset = 0;
    char buffer[BUFFER_SIZE], *msg;
    bgp_message_t *bgp_msg;
    mqd_t dest_mqd;
    app_read_closure_t *closure = h->closure;

    //// fprintf(stdout, "\n[app] read event from mqd:%d <-> agent:%d [%s]\n", h->fd, closure->id, __FUNCTION__);

    while (1) {
        bytes = mq_receive(h->fd, buffer, BUFFER_SIZE, NULL);

        // we have read all messages, the mqueue is empty
        if (bytes == -1 && errno == EAGAIN) {
            //// fprintf(stdout, "\n[app] mq_receive finished from agent %d [%s]\n", closure->id, __FUNCTION__);
            break;
        }

        // mqueue error
        if (bytes == -1) {
            // fprintf(stdout, "\n[app] mq_receive failed from agent %d, err: %s [%s]\n", closure->id, strerror(errno), __FUNCTION__);
            return;
        }

        //// fprintf(stdout, "\n[app] mq_receive %d bytes from agent %d [%s]\n", bytes, closure->id, __FUNCTION__);

        // add received buffer to local flow buffer to extract messages
        append_ds(closure->p_ds, buffer, bytes);
    }

    while (1) {
        get_msg(closure->p_ds, &msg, &msg_size);
        if (msg == NULL || msg_size == 0) {
            // we have processed all available msgs
            break;
        }
        bgp_msg = (bgp_message_t *) msg;
        assert(msg_size == bgp_msg->msg_len);
        dest_mqd = g_app_ln_sender_mqds[bgp_msg->dst_id];
        // fprintf(stdout, "\n[app] get %d bytes msg from agent %d to agent %d [%s]\n", msg_size, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);

        // send the msg
        while (msg_size != offset) {
            diff = msg_size - offset;
            bytes = (diff <= MAX_MSG_SIZE) ? diff : MAX_MSG_SIZE;
            if (mq_send(dest_mqd, (char *) bgp_msg + offset, bytes, 0) == -1) {
                // fprintf(stdout, "\n[app] write mqueue failed dst_id:%d, err: %s [%s]\n", bgp_msg->dst_id, strerror(errno), __FUNCTION__);
            } else {
                //// fprintf(stdout, "\n[app] write mqueue %d bytes successfully, to agent %d [%s]\n", bytes, bgp_msg->dst_id, __FUNCTION__);
                offset += bytes;
            }
        }
        offset = 0;
    }
}

static void app_register_read_agnt_event_handler(int efd, mqd_t mqd, uint32_t agnt_id, int net_type)
{
    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        // fprintf(stdout, "\n[app] malloc failed [%s]\n", __FUNCTION__);
        return;
    }
    handler->efd = efd;
    handler->fd = mqd;
    handler->handle = (net_type == REMOTE_NETWORK) ? app_handle_read_rn_agnt_event : app_handle_read_ln_agnt_event;

    app_read_closure_t *closure = malloc(sizeof *closure);
    closure->p_ds = NULL;
    if (!closure) {
        // fprintf(stdout, "\n[app] malloc failed [%s]\n", __FUNCTION__);
        return;
    }
    closure->id = agnt_id;
    init_ds(&closure->p_ds);
    if (!closure->p_ds) {
        free(closure);
        // fprintf(stdout, "\n[app] malloc failed [%s]\n", __FUNCTION__);
        return;
    }
    handler->closure = closure;

    //// fprintf(stdout, "\n[app] epoll add handler mqd:%d <-> agent:%d [%s]\n", handler->fd, closure->id, __FUNCTION__);
    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLRDHUP);
}

static void app_handle_read_as_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, diff, msg_size, offset = 0;
    char buffer[BUFFER_SIZE], *msg;
    bgp_message_t *bgp_msg;
    mqd_t dest_mqd;
    app_read_closure_t *closure = h->closure;

    //// fprintf(stdout, "\nread event from sfd:%d <-> as:%d [%s]\n", h->fd, closure->id, __FUNCTION__);

    // receive msgs from socket
    while (1) {
        bytes = read(h->fd, buffer, BUFFER_SIZE);

        if (bytes == 0) {
            // fprintf(stderr, "\n[app] socket from as %d closed [%s]\n", closure->id, __FUNCTION__);
            // TODO clean up sfd
            break;
        }

        // we have read all data
        if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }

        // read error or the remote as is close
        if (bytes == -1 || bytes == 0) {
            close(h->fd);
            free_ds(&closure->p_ds);
            free(closure);
            free(h);
            return;
        }

        //// fprintf(stdout, "\n[app] read %d bytes from as %d [%s]\n", bytes, closure->id, __FUNCTION__);

        // add received buffer to local flow buffer
        // to extract dst_id from messages
        append_ds(closure->p_ds, buffer, bytes);
    }

    while (1) {
        get_msg(closure->p_ds, &msg, &msg_size);
        if (msg == NULL || msg_size == 0) {
            // we have processed all available msgs
            break;
        }
        bgp_msg = (bgp_message_t *) msg;
        dest_mqd = g_app_rn_sender_mqds[bgp_msg->dst_id];
        // fprintf(stdout, "\n[app] get %d bytes msg from as %d to agent %d [%s]\n", msg_size, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);

        // assign src_id to as id, sfd to src_id,
        if (closure->id != bgp_msg->src_id) {
            closure->id = bgp_msg->src_id;
        }
        if (bgp_msg->src_id < AS_NUM && bgp_msg->src_id >= 0) {
            if (g_rn_sender_sockfds[bgp_msg->src_id] == -1) {
                // fprintf(stdout, "\n[app] bind as id: %u and sfd: %d [%s]\n", bgp_msg->src_id, h->fd, __FUNCTION__);
                g_rn_sender_sockfds[bgp_msg->src_id] = h->fd;
            }
        }

        // send the msg
        while (msg_size != offset) {
            diff = msg_size - offset;
            bytes = (diff <= MAX_MSG_SIZE) ? diff : MAX_MSG_SIZE;
            if (mq_send(dest_mqd, (char *) bgp_msg + offset, bytes, 0) == -1) {
                // fprintf(stdout, "\n[app] write mqueue failed dst_id:%d, err: %s [%s]\n", bgp_msg->dst_id, strerror(errno), __FUNCTION__);
            } else {
                //// fprintf(stdout, "\n[app] write mqueue %d bytes successfully, to agent %d [%s]\n", bytes, bgp_msg->dst_id, __FUNCTION__);
                offset += bytes;
            }
        }
        offset = 0;
    }
}

static void app_register_read_as_event_handler(int efd, int as_sfd)
{
    if (set_socket_non_blocking(as_sfd) == -1) {
        // fprintf(stdout, "\n[app] set_socket_non_blocking error [%s]\n", __FUNCTION__);
        return;
    }

    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        // fprintf(stdout, "\n[app] malloc error [%s]\n", __FUNCTION__);
    }
    handler->efd = efd;
    handler->fd = as_sfd;
    handler->handle = app_handle_read_as_event;

    app_read_closure_t *closure = malloc(sizeof *closure);
    closure->p_ds = NULL;
    closure->id = -1;   // id will be updated on receiving the first msg
    init_ds(&closure->p_ds);
    if (!closure->p_ds) {
        free(closure);
        // fprintf(stdout, "\n[app] malloc failed [%s]\n", __FUNCTION__);
        return;
    }
    handler->closure = closure;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLRDHUP);
}

static void app_handle_socket_event(epoll_event_handler_t *h, uint32_t events)
{
    int as_sfd;
    struct sockaddr_in as_addr;
    socklen_t as_len;

    // fprintf(stdout, "\n[app] new connection, enter [%s]\n", __FUNCTION__);

    while (1) {
        as_sfd = accept(h->fd, (struct sockaddr *) &as_addr, &as_len);
        //// fprintf(stdout, "\n[app] as_sfd: %d [%s]\n", as_sfd, __FUNCTION__);
        if (as_sfd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                // fprintf(stdout, "\n[app] accept connection failed [%s]\n", __FUNCTION__);
                return;
            }
        } else {
            // FIXME First session will show 0.0.0.0:16384
            // fprintf(stdout, "\n[app] accept new connection from as %s:%d [%s]\n", inet_ntoa(as_addr.sin_addr), (int) ntohs(as_addr.sin_port), __FUNCTION__);
            app_register_read_as_event_handler(h->efd, as_sfd);
        }
    }
}

static void app_register_socket_event_handler(int efd, char *port)
{
    int sfd;

    sfd = create_serv_socket(port);
    assert(sfd != -1);

    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        // fprintf(stdout, "malloc failed [%s]\n", __FUNCTION__);
        return;
    }
    handler->efd = efd;
    handler->fd = sfd;
    handler->handle = app_handle_socket_event;
    handler->closure = NULL;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET);
}

void app_init(int efd, char *port)
{
    uint32_t i;
    struct in_addr ina;
    struct mq_attr attr;
    mqd_t mqd;

    // init the ecall function name table
    // ecall functions have their enclave names as prefixes
    // generate these codes by other codes
    init_agent_handlers();

    // mqueue
    for (i = 0; i < AGNT_NUM; i++) {
        sprintf(g_rn_to_agnt_mq_name[i], "/mq_rn_to_agnt_%d", i);
        sprintf(g_agnt_to_rn_mq_name[i], "/mq_agnt_to_rn_%d", i);
        sprintf(g_ln_to_agnt_mq_name[i], "/mq_ln_to_agnt_%d", i);
        sprintf(g_agnt_to_ln_mq_name[i], "/mq_agnt_to_ln_%d", i);
    }

    attr.mq_flags = O_NONBLOCK;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = MAX_MSG_SIZE;
    attr.mq_curmsgs = 0;

    for (i = 0; i < AGNT_NUM; i++) {
        // remote network data exchange interface
        mqd = mq_open(g_rn_to_agnt_mq_name[i], O_CREAT | O_WRONLY | O_NONBLOCK, 0644, &attr);
        g_app_rn_sender_mqds[i] = mqd;
        mqd = mq_open(g_agnt_to_rn_mq_name[i], O_CREAT | O_RDONLY | O_NONBLOCK, 0644, &attr);
        app_register_read_agnt_event_handler(efd, mqd, i, REMOTE_NETWORK);
        // local network data exchange interface
        mqd = mq_open(g_ln_to_agnt_mq_name[i], O_CREAT | O_WRONLY | O_NONBLOCK, 0644, &attr);
        g_app_ln_sender_mqds[i] = mqd;
        mqd = mq_open(g_agnt_to_ln_mq_name[i], O_CREAT | O_RDONLY | O_NONBLOCK, 0644, &attr);
        app_register_read_agnt_event_handler(efd, mqd, i, LOCAL_NETWORK);
    }

    // server socket
    app_register_socket_event_handler(efd, port);
}
