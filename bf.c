#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned char *tape;
#define TAPE_SIZE 255
int ptr = 0;

// file
char *read_file(FILE *f) {
    size_t size = 1, s;
    char *str = NULL;
    char buf[4096];
    while((s = fread(buf, 1, sizeof(buf), f)) != 0) {
        if(str == NULL) {
            size = s;
            str = malloc(size);
            memcpy(str, buf, size);
            str[size] = 0;
        } else {
            str = realloc(str, size+s);
            memcpy(str+size, buf, s);
            size += s;
            str[size] = 0;
        }
    }
    return str;
}

int main(int argc, char **argv) {
    tape = malloc(TAPE_SIZE);
    memset(tape, 0, TAPE_SIZE);
    
    FILE *f = fopen(argv[1], "r");
    char *str = read_file(f);
    size_t i = 0;
    char c;
    while((c = str[i])) {
        //printf("%i %c\n",i,c);
        if(c == '>') {
            ++ptr;
        } else if(c == '<') {
            --ptr;
        } else if(c == '+') {
            tape[ptr]++;
        } else if(c == '-') {
            tape[ptr]--;
        } else if(c == '.') {
            printf("%c", tape[ptr]);
        } else if (c=='[') {
            if(!tape[ptr]) {
                int count = 1;
                while(count) {
                    i++;
                    if(str[i] == '[') count++;
                    if(str[i] == ']') count--;
                }
            }
        } else if (c==']') {
            if(tape[ptr]) {
                int count = 1;
                while(count) {
                    i--;
                    if(str[i] == ']') count++;
                    if(str[i] == '[') count--;
                }
            }
        } else if (c==';') {
            printf("---\n");
            printf("DEBUG\n");
            for(int i = 0; i < 10; i++) {
                printf("%d ", tape[i]);
            }
            printf("\n---\n");
        } else if (c==';') {
            return 1;
        }
        i++;
    }
    printf("\n\n");
    for(int i = 0; i < 10; i++) {
        printf("%d ", tape[i]);
    }
    return 0;
}
