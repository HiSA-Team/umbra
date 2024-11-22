
#include "fibonacci.h"

void fibonacci() __attribute__((section(".app.fibonacci")));

void fibonacci(){

    // Compute the fibonacci number 128
    int n = 128;
    int i = 0;

    // initialize first and second terms
    int t1 = 0, t2 = 1;

    // initialize the next term (3rd term)
    int nextTerm = t1 + t2;


    // print 3rd to nth terms
    for (i = 3; i <= n; ++i) {
        t1 = t2;
        t2 = nextTerm;
        nextTerm = t1 + t2;
    }

    return;
}