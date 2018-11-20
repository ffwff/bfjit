#ifndef __x86_64__
#error "Only x86-64 architecture, please!"
#endif

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>

#define B1(x) (x&0xFF)
#define B2(x) ((x>>8)&0xFF)
#define B3(x) ((x>>16)&0xFF)
#define B4(x) ((x>>24)&0xFF)

struct addr_node {
    unsigned int pos; // position in source space
    uint64_t addr; // addr in "assembly" space
    uint64_t placeholder_addr;
    struct addr_node *next;
};
struct addr_node *addr_node_first = NULL, *addr_node_last = NULL;

// tape
uint8_t *tape;
#define TAPE_SIZE 30000

void init_tape() {
    tape = calloc(TAPE_SIZE, 1);
}

// file
#define is_legal_char(ch) (ch == '+' || ch == '-' || ch == '<' || ch == '>' || ch == '[' || ch == ']' || ch == '.' || ch == ',')
char *read_file(FILE *f) {
    char buf[128];
    char *str = malloc(sizeof(buf)+1);
    size_t cap = sizeof(buf), size = 0, s = 0;
    while((s = fread(buf,1,sizeof(buf),f)) > 0) {
        if(size+s>cap) {
            cap *= 2;
            str = realloc(str, cap+1);
        }
        for(unsigned int i = 0; i < s; i++) {
            if(is_legal_char(buf[i])) {
                str[size] = buf[i];
                size++;
            }
        }
    }
    str[size] = 0;
    return str;
}

// jit function
uint64_t (*_bfjit)(uint8_t *tape, uint8_t ptr);
uint8_t *_bfjit_mem;
uint64_t _bfjit_mem_ptr, _bfjit_mem_max;

void init_jit() {
    _bfjit_mem_ptr = 0;
    _bfjit_mem_max = 4096;
    _bfjit = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(_bfjit == (void*)-1) {
        perror("mmap()");
        exit(1);
    }
    _bfjit_mem = (uint8_t*)_bfjit;
}

void jit_append(uint8_t *buf, size_t size) {
    if(_bfjit_mem_ptr+size > _bfjit_mem_max) {
        _bfjit = mremap(_bfjit, _bfjit_mem_max, _bfjit_mem_max+4096, MREMAP_MAYMOVE);
        if(_bfjit == (void*)-1) {
            perror("mremap()");
            exit(1);
        }
        _bfjit_mem = (uint8_t*)_bfjit;
        _bfjit_mem_max += 4096;
    }
    memcpy(_bfjit_mem+_bfjit_mem_ptr, buf, size);
    _bfjit_mem_ptr += size;
}

void jit_fill_placeholders(char *str) {
    for (struct addr_node *addr_node = addr_node_first; addr_node != NULL; addr_node = addr_node->next) {
        char ch = str[addr_node->pos];
#ifdef DEBUG
        printf("%c\n", ch);
        printf("MAGIC: %x%x%x%x\n", *(_bfjit_mem+addr_node->placeholder_addr),
                                    *(_bfjit_mem+addr_node->placeholder_addr+1),
                                    *(_bfjit_mem+addr_node->placeholder_addr+2),
                                    *(_bfjit_mem+addr_node->placeholder_addr+3)
        );
#endif
        uint64_t delta;
        uint64_t matching_addr = (uint64_t)-1;
        if(ch == '[') {
            unsigned int j = addr_node->pos, count = 1;
            while(count && str[j]) {
                j++;
                if(str[j] == '[') count++;
                if(str[j] == ']') count--;
            }
            for (struct addr_node *addr_node_m = addr_node; addr_node_m != NULL; addr_node_m = addr_node_m->next) {
                if(addr_node_m->pos == j) {
                    matching_addr = addr_node_m->addr;
                }
            }
            if(matching_addr == (uint64_t)-1) {
                printf("unmatching bracket for [");
                exit(1);
            }
            delta = matching_addr-addr_node->addr-5;
        } else if (ch == ']') {
            unsigned int j = addr_node->pos, count = 1;
            while(count && str[j]) {
                j--;
                if(str[j] == ']') count++;
                if(str[j] == '[') count--;
            }
            for (struct addr_node *addr_node_m = addr_node_first; addr_node_m != addr_node; addr_node_m = addr_node_m->next) {
                if(addr_node_m->pos == j) {
                    matching_addr = addr_node_m->addr;
                }
            }
            if(matching_addr == (uint64_t)-1) {
                printf("unmatching bracket for [");
                exit(1);
            }
            delta = matching_addr-addr_node->addr-6;
        }
        //printf("delta: 0x%x\n", delta);
        *(_bfjit_mem+addr_node->placeholder_addr+0) = B1(delta);
        *(_bfjit_mem+addr_node->placeholder_addr+1) = B2(delta);
        *(_bfjit_mem+addr_node->placeholder_addr+2) = B3(delta);
        *(_bfjit_mem+addr_node->placeholder_addr+3) = B4(delta);
    }
}

#define jit_append_buf(...) \
    { char buf[] = { __VA_ARGS__ }; \
    jit_append(buf, sizeof(buf)); }

// addr vector
struct addr_node *addr_node_create(unsigned int pos, uint64_t addr, uint64_t placeholder_addr) {
    struct addr_node *addr_node = malloc(sizeof(struct addr_node));
    addr_node->pos = pos;
    addr_node->addr = addr;
    addr_node->placeholder_addr = placeholder_addr;
    addr_node->next = NULL;
    return addr_node;
}
void addr_node_append(unsigned int pos, uint64_t addr, uint64_t placeholder_addr) {
    struct addr_node *addr_node = addr_node_create(pos,addr,placeholder_addr);
    if(addr_node_first == NULL) {
        addr_node_first = addr_node_last = addr_node;
    } else {
        addr_node_last->next = addr_node;
        addr_node_last = addr_node;
    }
}

// breakpoint
asm("bp: nop; retq");
void bp(); // noop

int main(int argc, char **argv) {
    init_tape();
    init_jit();
    
    if(argc < 2) {
        printf("usage: <%s> source\n", argv[0]);
        return 1;
    }
    
    FILE *f;
    if(argv[1][0] == '-' && argv[1][1] == 0) f = stdin;
    else f = fopen(argv[1], "r");
    if(f == NULL) {
        perror("fopen()");
        return 1;
    }
    char *str = read_file(f);
    //printf("%s\n",str);
    if(str == NULL) {
        printf("unable to read\n");
        return 1;
    }
    
    unsigned int i = 0;
    char c;
    while((c = str[i])) {
        // https://www.nayuki.io/page/optimizing-brainfuck-compiler
        // http://www.wilfred.me.uk/blog/2015/08/29/an-optimising-bf-compiler/
        // http://calmerthanyouare.org/2015/01/07/optimizing-brainfuck.html
        //printf("C: %c\n",c);
        char next_ch = str[i+1], next_ch1 = next_ch ? str[i+2] : 0;
        
#ifdef OPTIMIZE
        // fusing incs/decs
        if((c == '+' || c == '-') && (next_ch == '+' || next_ch == '-')) {
            uint8_t value_delta = 0;
            while((c = str[i])) {
                if(c == '+') value_delta++;
                else if(c == '-') value_delta--;
                else break;
                i++;
            }
            if(value_delta == 0) continue;
            jit_append_buf(0x80, 0x04, 0x3e, value_delta); // addb $delta, (%rsi,%rdi,1)
            
            continue;
        }
        
        // fusing ptr movement
#ifdef ENABLE_FUSE_PTR
        if((c == '>' || c == '<') && (next_ch == '>' || next_ch == '<')) {
            uint64_t delta = 0;
            while((c = str[i])) {
                if(c == '>') delta++;
                else if(c == '<') delta--;
                else break;
                i++;
            }
            if(delta == 0) continue;
#ifdef DISABLE_BOUND_CHECKS
            jit_append_buf(0x48, 0x81, 0xc6, B1(delta), B2(delta), B3(delta), B4(delta)); // add    [number],%rsi
#else
            // wrapping adds like 10s to mandelbrot.b's execution time
            // not cheap!

            // idiv in x86 outputs euclidean modulo, not remainder!
            jit_append_buf(0x48, 0x89, 0xf0); // mov %rsi, %rax
            jit_append_buf(0x48, 0x05, B1(delta), B2(delta), B3(delta), B4(delta)); // add    [number],%rax
            jit_append_buf(0x48, 0x99); // cqo
            jit_append_buf(0x48, 0xc7, 0xc1, B1(TAPE_SIZE), B2(TAPE_SIZE), B3(TAPE_SIZE), B4(TAPE_SIZE)); // mov $TAPE_SIZE, %rcx
            jit_append_buf(0x48, 0xf7, 0xf9); // idiv %rcx
            jit_append_buf(0x48, 0x89, 0xd0); // mov %rdx,%rax
            jit_append_buf(0x48, 0x81, 0xc2, B1(TAPE_SIZE), B2(TAPE_SIZE), B3(TAPE_SIZE), B4(TAPE_SIZE)); // add    [number],%rdx
            jit_append_buf(0x48, 0x0f, 0x43, 0xd0); // cmovae %rax, %rdx (CF will be set)
            jit_append_buf(0x48, 0x89, 0xd6); // mov %rdx, %rsi
#endif
            
            continue;
        }
#endif
        
        // clear loops
        if(c == '[' && next_ch == '-' && next_ch1 == ']') {
            i += 3;
            c = str[i];
            uint8_t value_delta = 0;
            while((c = str[i])) {
                if(c == '+') value_delta++;
                else if(c == '-') value_delta--;
                else break;
                i++;
            }
            jit_append_buf(0xc6, 0x04, 0x3e, value_delta); // mov $0x0, (%rsi,%rdi,1)
            continue;
        }
#endif
        
        if(c == '>') {
            jit_append_buf(
                0x48, 0xff, 0xc6 // inc %rsi
#ifdef DISABLE_BOUND_CHECKS
            );
#else           
                ,// handle overflow>0x8000
                0x48, 0x31, 0xdb, // xor %rbx,%rbx
                0x48, 0x81, 0xfe, B1(TAPE_SIZE), B2(TAPE_SIZE), B3(TAPE_SIZE), B4(TAPE_SIZE), // cmp $0x8000,%rsi
                0x48, 0x0f, 0x4f, 0xf3); // cmovg  %rbx,%rsi
#endif
        } else if(c == '<') {
            jit_append_buf(
                0x48, 0xff, 0xce // dec %rsi
#ifdef DISABLE_BOUND_CHECKS
            );
#else
                ,// handle underflow<0x0
                0x48, 0xc7, 0xc3, B1(TAPE_SIZE), B2(TAPE_SIZE), B3(TAPE_SIZE), B4(TAPE_SIZE), // move $TAPE_SIZE,%rbx
                0x48, 0x85, 0xf6, // test %rsi, %rsi
                0x48, 0x0f, 0x48, 0xf3); // cmovs %rbx, %rsi
#endif
        } else if(c == '+') {
            jit_append_buf(0xfe, 0x04, 0x3e); // incb (%rsi,%rdi,1)
        } else if(c == '-') {
            jit_append_buf(0xfe, 0x0c, 0x3e); // decb (%rsi,%rdi,1)
        } else if(c == '.') {
            /*
             *    111d:       48 89 f3                mov    %rsi,%rbx
             *    1120:       48 89 fe                mov    %rdi,%rsi
             *    1123:       48 01 de                add    %rbx,%rsi
             *    1126:       48 c7 c0 01 00 00 00    mov    $0x1,%rax
             *    112d:       48 c7 c7 00 00 00 00    mov    $0x0,%rdi
             *    1134:       48 c7 c2 01 00 00 00    mov    $0x1,%rdx
             *    113b:       0f 05                   syscall
             *    113d:       48 89 f7                mov    %rsi,%rdi
             *    1140:       48 89 de                mov    %rbx,%rsi
             *    1143:       48 29 f7                sub    %rsi,%rdi
             * 
             */
            jit_append_buf(
                0x48 ,0x89 ,0xf3,
                0x48 ,0x89 ,0xfe,
                0x48 ,0x01 ,0xde,
                0x48 ,0xc7 ,0xc0 ,0x01 ,0x00 ,0x00 ,0x00,
                0x48 ,0xc7 ,0xc7 ,0x01 ,0x00 ,0x00 ,0x00,
                0x48 ,0xc7 ,0xc2 ,0x01 ,0x00 ,0x00 ,0x00,
                0x0f ,0x05,
                0x48 ,0x89 ,0xf7,
                0x48 ,0x89 ,0xde,
                0x48, 0x29 ,0xf7
            );
        } else if (c==',') {
            jit_append_buf(
                0x48 ,0x89 ,0xf3,
                0x48 ,0x89 ,0xfe,
                0x48 ,0x01 ,0xde,
                0x48 ,0xc7 ,0xc0 ,0x00 ,0x00 ,0x00 ,0x00,
                0x48 ,0xc7 ,0xc7 ,0x00 ,0x00 ,0x00 ,0x00,
                0x48 ,0xc7 ,0xc2 ,0x01 ,0x00 ,0x00 ,0x00,
                0x0f ,0x05,
                0x48 ,0x89 ,0xf7,
                0x48 ,0x89 ,0xde,
                0x48, 0x29 ,0xf7
            );
        } else if (c=='[') { // start while loop
#ifdef OPTIMIZE
            // empty while loop
            if(next_ch == ']') {
                /*
                 *  111d:       8a 04 3e                mov    (%rsi,%rdi,1),%al
                 *  1120:       3c 00                   cmp    $0x0,%al
                 *  
                 *  0000000000001122 <l>:
                 *  1122:       90                      nop
                 *  1123:       75 fd                   jne    1122 <l>
                 */
                jit_append_buf(
                    0x8a, 0x04, 0x3e,
                    0x3c, 0x00,
                    0x90,
                    0x75, 0xfd
                );
                i += 2;
                continue;
            }

            // simple optimisation
            int simple_opt = 0;
            do {
                unsigned int j = i+1;
                int delta_ptr = 0, delta_mem = 0;
                while(str[j]) {
                    if(str[j] == '[' || str[j] == '.' || str[j] == ',') { // can only contain mem/ptr manip
                        delta_ptr = -1;
                        break;
                    }
                    else if(str[j] == ']') break;
                    else if(str[j] == '+' && delta_ptr == 0) delta_mem++;
                    else if(str[j] == '-' && delta_ptr == 0) delta_mem--;
                    else if(str[j] == '>') delta_ptr++;
                    else if(str[j] == '<') delta_ptr--;
                    j++;
                }
#ifdef DEBUG
                printf("delta = %d\n", delta_mem);
#endif
                if(delta_ptr != 0 || delta_mem != -1) // not a balanced loop
                    break;
                
                i++; // skip [
                
                uint64_t rela_ptr = 0;
                while((c = str[i]) && i < j) {
#ifdef DEBUG
                    printf("%c\n",c);
#endif
                    if(c == '+' || c == '-') {
                        uint8_t value_delta = 0; // "normalized" value
                        while((c = str[i])) {
                            if(c == '+') value_delta++;
                            else if(c == '-') value_delta--;
                            else {i--; break; } // also a problem here <--
                            i++;
                        }
                        if(rela_ptr == 0) {i++; continue;}
#ifdef DEBUG
                        printf("delta: %d, rela_ptr: 0x%x\n", value_delta, rela_ptr);
#endif
                        // *(tape+ptr+rela_ptr) = value_delta*rela_ptr
                        jit_append_buf(0xb0, value_delta); // movb $value_delta,%al
                        //jit_append_buf(0xb3, rela_ptr+1); // movb $rela_ptr,%bl
                        jit_append_buf(0x8a,0x1c,0x3e) //mov    (%rsi,%rdi,1),%bl
                        jit_append_buf(0xf6, 0xe3); // mul %bl
                        
                        jit_append_buf(0x48, 0x89, 0xf3); // mov %rsi, %rbx
                        jit_append_buf(0x48, 0x81, 0xc3, B1(rela_ptr),B2(rela_ptr),B3(rela_ptr),B4(rela_ptr)); // add $rela_ptr,%rbx
                        jit_append_buf(0x00, 0x04, 0x3b); // add    %al,(%rbx,%rdi,1)
                        // add, not mov!
                    }
                    else if (c=='>') rela_ptr++;
                    else if (c=='<') rela_ptr--;
                    i++;
                }
                jit_append_buf(0xc6, 0x04, 0x3e, 0x00); // movb $0x00, (%rsi,%rdi,1)
                
                i++; // skip ]
                
                simple_opt = 1;
                
            } while(0);
            if(simple_opt) continue;

#endif
            uint64_t addr = _bfjit_mem_ptr;
            uint64_t placeholder = _bfjit_mem_ptr+1;
            jit_append_buf(0xe9, 0xde, 0xad, 0xbe, 0xef); // jmpq [condition]
            // [condition] is where the matching ']' is in asm space
            addr_node_append(i, addr, placeholder);
        } else if (c==']') { // end while loop
            // while loop jump condition: *ptr != 0
            uint64_t addr = _bfjit_mem_ptr;
            jit_append_buf(0x8a, 0x04, 0x3e, // mov (%rsi,%rdi,1),%al
                           0x3c, 0x00);       // cmp $0x0, %al
            uint64_t placeholder = _bfjit_mem_ptr+2;
            jit_append_buf(0x0f, 0x85, 0xde, 0xad, 0xbe, 0xef); // jne [while contents]
            // [while contents] is where the matching '[' is in asm space
            addr_node_append(i, addr, placeholder);
        }
        i++;
    }

#ifdef DEBUG
    jit_append_buf(0x48, 0x89, 0xf0); //mov    %rsi,%rax
#endif
    jit_append_buf(0xc3); // retq
    
    jit_fill_placeholders(str);
#ifdef DEBUG
    printf("Execute...\n");
    bp();
    uint64_t ptr = _bfjit(tape, 0); // %rdi = tape, %rsi = 0;
#else
    bp();
    _bfjit(tape, 0);
#endif
    
#ifdef DEBUG
    printf("\n\n(ptr: %ju) ", ptr);
    for(int i = 0; i < 10; i++) {
        printf("%d ", tape[i]);
    }
#endif
    
    return 0;
}
