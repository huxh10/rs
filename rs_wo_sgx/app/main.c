#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "epoll_utils.h"
#include "const.h"
#include "app.h"
#include "agent.h"

void create_threads(pthread_t *threads)
{
    int i, *id;

    // create agent threads
    for (i = 0; i < AS_NUM; i++) {
        id = malloc(sizeof *id);    // free in the thread function
        *id = i;
        if (pthread_create(&threads[i], NULL, agent, (void *) id) != 0) {
            fprintf(stderr, "app failed to create thread: %d, %s\n", i, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    int efd;

    // agents and route server
    pthread_t threads[AS_NUM];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    efd = epoll_init();
    app_init(efd, argv[1]);
    sleep(1);
    create_threads(threads);

    epoll_run(efd);
}
