#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#define TIMEOUT 3
volatile sig_atomic_t timed_out = 0;

void handle_alarm(int sig) {
    timed_out = 1;
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int get_input_with_timeout() {
    char input[128];
    signal(SIGALRM, handle_alarm); // Set up the signal handler for the alarm
    alarm(TIMEOUT); // Set an alarm for TIMEOUT seconds

    if (fgets(input, sizeof(input), stdin)) {
        if (timed_out) {
            printf("Time is up. Exiting...\n");
            exit(EXIT_FAILURE);
        }

        int number;
        if (sscanf(input, "%d", &number) == 1) {
            alarm(0); // Cancel the alarm
            return number;
        } else {
            printf("Invalid input. Please enter a number.\n");
            alarm(0); // Cancel the alarm
            return -1;
        }
    }

    printf("No input received. Exiting...\n");
    exit(EXIT_FAILURE);
}

void math1() {
    srand((unsigned)time(NULL));
    int min = 1;
    int max = 10000;
    int a = min + rand() % (max - min + 1);
    int b = min + rand() % (max - min + 1);
    int c = a * b;
    printf("%d * %d = ", a, b);

    // Wait for input with timeout
    int user_input = get_input_with_timeout();

    if (user_input == c) {
        printf("Correct! Opening shell...\n");
        system("/bin/sh");
    } else {
        printf("Incorrect. The correct answer was %d. Exiting...\n", c);
        exit(EXIT_FAILURE);
    
}

int main() {
    init();
    welcome();
    math1();
    return 0;
}
