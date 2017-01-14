#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include "epoll_utils.h"
#include "socket_utils.h"
#include "msg_buffer.h"
#include "error_codes.h"
#include "const.h"
#include "as_process_message.h"

typedef struct {
    uint32_t id;
    ds_t *p_ds;
} as_read_closure_t;

void as_handle_read_app_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, msg_size;
    char buffer[BUFFER_SIZE], *msg;
    uint32_t ret_status;
    as_read_closure_t *closure = h->closure;

    //// fprintf(stdout, "\nread event from sfd:%d <-> as:%d [%s]\n", h->fd, closure->id, __FUNCTION__);

    // receive msgs from socket
    while (1) {
        bytes = read(h->fd, buffer, BUFFER_SIZE);

        if (bytes == 0) {
            // fprintf(stderr, "\nsocket from rs closed [%s]\n", __FUNCTION__);
            //TODO: clean up the fd from epoll
            break;
        }

        // we have read all messages, the socket is empty
        if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }

        // socket error
        if (bytes == -1) {
            // fprintf(stderr, "\nread socket failed, err: %s [%s]\n", strerror(errno), __FUNCTION__);
            return;
        }

        //// fprintf(stdout, "\nread %d bytes from rs [%s]\n", bytes, __FUNCTION__);

        // add received buffer to local flow buffer to extract messages
        append_ds(closure->p_ds, buffer, bytes);
    }

    // processing parsed msgs
    while (1) {
        get_msg(closure->p_ds, &msg, &msg_size);
        if (msg == NULL || msg_size == 0) {
            // we have processed all available msgs
            break;
        }

        // fprintf(stdout, "\nget msg from rs [%s]\n", __FUNCTION__);

        // processing msg call, if there are some msgs to be sent, send_message_ocall will be invoked
        ret_status = as_process_message(h->fd, (void *) msg, msg_size);
        if (ret_status != SUCCESS) {
            // fprintf(stderr, "\nas_process_message failed [%s]\n", __FUNCTION__);
        }
    }
}

void as_register_read_app_event_handler(int efd, int sfd, uint32_t id)
{
    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        // fprintf(stderr, "\nmalloc error [%s]\n", __FUNCTION__);
        return;
    }
    handler->efd = efd;
    handler->fd = sfd;
    handler->handle = as_handle_read_app_event;

    as_read_closure_t *closure = malloc(sizeof *closure);
    closure->p_ds = NULL;
    if (!closure) {
        // fprintf(stderr, "\nmalloc error [%s]\n", __FUNCTION__);
        return;
    }
    init_ds(&closure->p_ds);
    if (!closure->p_ds) {
        free(closure);
        // fprintf(stderr, "\nmalloc error [%s]\n", __FUNCTION__);
        return;
    }
    closure->id = id;
    handler->closure = closure;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLRDHUP);
}

int main(int argc, char *argv[])
{
    int efd, sfd;

    if (argc != 7) {
        // fprintf(stderr, "Usage: %s [src_addr] [src_port] [dest_addr] [dest_port] [route_file] [as_id]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (load_rib(argv[5]) == -1) {
        abort();
    }

    efd = epoll_init();
    sfd = create_clnt_socket(argv[1], argv[2], argv[3], argv[4]);
    if (sfd == -1) {
        // fprintf(stderr, "\ncreate_clnt_socket failed [%s]\n", __FUNCTION__);
        exit(EXIT_FAILURE);
    }
    as_register_read_app_event_handler(efd, sfd, atoi(argv[6]));

    as_start_session_handshake_to_agnt(sfd, atoi(argv[6]));

    epoll_run(efd);
}
