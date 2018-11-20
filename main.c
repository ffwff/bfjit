#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

void (*fn)(void);

int main() {
    fn = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    char *tmp = (char*)fn;
    tmp[0] = 0xc3;
    fn();
    munmap(fn, 4096);
    return 0;
}
