#include <stdio.h>
#include <inttypes.h>
#include <time.h>

void print_current_time_with_us(char *func)
{
    long ms;    // Milliseconds
    time_t s;   // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    s  = spec.tv_sec;
    ms = spec.tv_nsec / 1.0e2; // Convert nanoseconds to microseconds

    printf("[%s] Current time: %"PRIdMAX".%07ld seconds since the Epoch\n", func, (intmax_t) s, ms);
}
