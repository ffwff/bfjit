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
#define TAPE_SIZE 0xffff
uint8_t tape[TAPE_SIZE];

void init_tape() {
    memset(tape, 0, TAPE_SIZE);
}

// file
#define is_legal_char(ch) (ch == '+' || ch == '-' || ch == '<' || ch == '>' || ch == '[' || ch == ']' || ch == '.' || ch == ',' || ch == '#')
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
uint64_t (*_bfjit)(uint8_t *tape);
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
do{ char buf[] = { __VA_ARGS__ }; \
    jit_append(buf, sizeof(buf)); } while(0)

static inline void jit_append_variable_length_addr(int n) {
    // i didn't want to do this
    // but goddamn intel and their variable length instructions!!!
    // why isnt x86 a simple architecture??
    uint16_t a = B1(n), b = B2(n);
    if(n < 0) {
        //printf("%x\n", n);
        n = -n;
        if(n < 0xff) {
            jit_append_buf(0xff-n+1);
        } else {
            jit_append_buf(0xff-a,0xff-b,0xff,0xff);
        }
    } else {
        jit_append_buf(a,b,0x00,0x00);
    }
}

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
    
    jit_append_buf(0x48, 0x31, 0xc9); // xor %rcx, %rcx
    
    int postpone_ptr = 0; // relative
    unsigned int i = 0;
    char c;
    if((c = str[i]) == '[') {
        // skip dead code or comments
        i++;
        int count = 1;
        while(count && (c = str[i])) {
            i++;
            if(str[i] == '[') count++;
            if(str[i] == ']') count--;
        }
    }
    while((c = str[i])) {
        // https://www.nayuki.io/page/optimizing-brainfuck-compiler
        // http://www.wilfred.me.uk/blog/2015/08/29/an-optimising-bf-compiler/
        // http://calmerthanyouare.org/2015/01/07/optimizing-brainfuck.html
        //printf("C: %c\n",c);
        char next_ch = str[i+1], next_ch1 = next_ch ? str[i+2] : 0;
        
        // BUG: somehow rdi = 0
        // sar    $0xff,%edi
        // FIXME: B1,B2 not work for negative

#define flush_ptr() if(postpone_ptr!=0){ \
        uint16_t sign = (postpone_ptr<0?0xe9:0xc1); \
        postpone_ptr = (postpone_ptr<0?-postpone_ptr:postpone_ptr); \
        jit_append_buf(0x66, 0x81, sign, B1(postpone_ptr), B2(postpone_ptr)); /* addw $postpone_ptr, %cx */ \
        postpone_ptr = 0; \
}

        //printf("C:%c\n",c);
        if(c=='#') {
            //flush_ptr();
            jit_append_buf(0x90);
            /*#ifdef DEBUG
            jit_append_buf(0x48, 0x89, 0xc8); //mov    %rcx,%rax
            #endif
            jit_append_buf(0xc3);*/
        }

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
            if(postpone_ptr) {
                jit_append_buf(0x80, postpone_ptr<0?0x44:0x84, 0x39);
                jit_append_variable_length_addr(postpone_ptr);
                jit_append_buf(value_delta); // addb $delta, (%rcx,%rdi,1)
            } else
                jit_append_buf(0x80, 0x04, 0x39, value_delta); // addb $delta, (%rcx,%rdi,1)
            
            continue;
        }
        
        // fusing ptr movement
        if((c == '>' || c == '<') && (next_ch == '>' || next_ch == '<')) {
            while((c = str[i])) {
                if(c == '>') postpone_ptr++;
                else if(c == '<') postpone_ptr--;
                else break;
                i++;
            }
            continue;
        }
        
        // clear loops
        if(c == '[' && next_ch == '-' && next_ch1 == ']' && 0) {
            i += 3;
            c = str[i];
            uint8_t value_delta = 0;
            while((c = str[i])) {
                if(c == '+') value_delta++;
                else if(c == '-') value_delta--;
                else break;
                i++;
            }
            flush_ptr();
            jit_append_buf(0xc6, 0x04, 0x39, value_delta);
            /*
            if(postpone_ptr) {
                int tmp = 0;
                if(postpone_ptr > 0 && postpone_ptr<0xff) tmp = 0x44;
                else if(postpone_ptr < 0 && (-postpone_ptr)>0xff) tmp = 0x44;
                else tmp = 0x84;
                jit_append_buf(0xc6, tmp, 0x39);
                if(postpone_ptr < 0 && (-postpone_ptr)>0xff) {
                    printf("%d", postpone_ptr);
                    jit_append_buf(0xff-postpone_ptr+1);
                }
                else if(postpone_ptr < 0xff)
                    jit_append_buf(postpone_ptr);
                else
                    jit_append_variable_length_addr(postpone_ptr);
                jit_append_buf(value_delta); // movb $0x0, $...(%rsi,%rdi,1)
            } else
                jit_append_buf(0xc6, 0x04, 0x39, value_delta); // movb $0x0, (%rsi,%rdi,1)
            */
            
            // chained clear loops
            if(str[i] == '>' && str[i+1] == '[' && str[i+2] == '-' && str[i+3] == ']') { // forwards
                int j = 0;
                uint64_t arg = 0x00ffffff;
                // 1: arg=0x00ffffff
                // 2: arg=0x0000ffff
                // 3: arg=0x000000ff
                // 4: arg=0x00000000
                while(str[i]) {
                    if(j < 3 && str[i] == '>' && str[i+1] == '[' && str[i+2] == '-' && str[i+3] == ']') {
                        arg = arg >> 8;
                        j++;
                        i+= 4;
                    } else break;
                }
                //printf("0x%08x\n", arg);
                if(postpone_ptr) {
                    uint16_t b2;
                    uint64_t tmp = (uint64_t)postpone_ptr;
                    if(tmp < 0xff) b2 = 0x64;
                    else b2 = 0xa4;
                    jit_append_buf(0x81, 0xa4, 0x39);
                    jit_append_variable_length_addr(postpone_ptr);
                    jit_append_buf(B4(arg),B3(arg),B2(arg),B1(arg));
                    postpone_ptr += j;
                } else {
                    jit_append_buf(0x81,0x24,0x39,B4(arg),B3(arg),B2(arg),B1(arg)); // andl $arg,(%rcx,%rdi,1)
                    jit_append_buf(0x66, 0x83, 0xc1, j); // add    $j,%cx
                }
                continue;
            } else if(str[i] == '<' && str[i+1] == '[' && str[i+2] == '-' && str[i+3] == ']' && 0) { // backwards
                int j = 0;
                uint64_t arg = 0xffffff00;
                // 1: arg=0xffffff00
                // 2: arg=0xffff0000
                // 3: arg=0xff000000
                // 4: arg=0x00000000
                while(str[i]) {
                    if(j < 3 && str[i] == '<' && str[i+1] == '[' && str[i+2] == '-' && str[i+3] == ']') {
                        arg = (arg << 8) & 0xffffffff;
                        j++;
                        i+= 4;
                    } else break;
                }
                //printf("0x%08x\n", arg);
                jit_append_buf(0x66, 0x83, 0xe9, j); // sub $j,%cx
                jit_append_buf(0x81,0x24,0x39,B1(arg),B2(arg),B3(arg),B4(arg)); // andl $arg,(%rcx,%rdi,1)
                continue;
            }

            continue;
        }
#endif
        
        if(c == '>') {
            postpone_ptr++;
        } else if(c == '<') {
            postpone_ptr--;
        } else if(c == '+') {
            if(postpone_ptr) {
                jit_append_buf(0xfe, postpone_ptr<0?0x44:0x84, 0x39); //incb   0x1337(%rcx,%rdi,1)
                jit_append_variable_length_addr(postpone_ptr);
            } else
                jit_append_buf(0xfe, 0x04, 0x39); // incb (%rcx,%rdi,1)
        } else if(c == '-') {
            //fe 8c 39 c9 ec ff ff    decb   -0x1337(%rcx,%rdi,1)
            if(postpone_ptr) {
                jit_append_buf(0xfe, postpone_ptr<0?0x4c:0x8c, 0x39); //decb 0x1337(%rcx,%rdi,1)
#ifdef DEBUG
                printf("postpone %d\n",postpone_ptr); // somehow, if postpone_ptr < -1 then prints out 0x0
#endif
                jit_append_variable_length_addr(postpone_ptr);
            } else
                jit_append_buf(0xfe, 0x0c, 0x39); // decb (%rcx,%rdi,1)
        } else if(c == '.') {
            /*    111d:       48 c7 c0 01 00 00 00    mov    $0x1,%rax
             *    1124:       48 89 fb                mov    %rdi,%rbx
             *    1127:       48 01 cf                add    %rcx,%rdi
             *    112a:       48 89 fe                mov    %rdi,%rsi
             *    112d:       48 c7 c7 01 00 00 00    mov    $0x1,%rdi
             *    1134:       48 c7 c2 01 00 00 00    mov    $0x1,%rdx
             *    113b:       51                      push   %rcx
             *    113c:       0f 05                   syscall
             *    113e:       59                      pop    %rcx
             *    113f:       48 89 df                mov    %rbx,%rdi
             * 
             */
            flush_ptr();
            jit_append_buf(
                0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
                0x48, 0x89, 0xfb,
                0x48, 0x01, 0xcf,
                0x48, 0x89, 0xfe,
                0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
                0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,
                0x51,
                0x0f, 0x05,
                0x59,
                0x48, 0x89, 0xdf
            );
        } else if (c==',') {
            /*    111d:       48 31 c0                xor    %rax,%rax
             *    1124:       48 89 fb                mov    %rdi,%rbx
             *    1127:       48 01 cf                add    %rcx,%rdi
             *    112a:       48 89 fe                mov    %rdi,%rsi
             *    112d:       48 c7 c7 01 00 00 00    mov    $0x1,%rdi
             *    1134:       48 c7 c2 01 00 00 00    mov    $0x1,%rdx
             *    113b:       51                      push   %rcx
             *    113c:       0f 05                   syscall
             *    113e:       59                      pop    %rcx
             *    113f:       48 89 df                mov    %rbx,%rdi
             * 
             */
            flush_ptr();
            jit_append_buf(
                0x48, 0x31, 0xc0,
                0x48, 0x89, 0xfb,
                0x48, 0x01, 0xcf,
                0x48, 0x89, 0xfe,
                0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
                0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,
                0x51,
                0x0f, 0x05,
                0x59,
                0x48, 0x89, 0xdf
            );
        } else if (c=='[') { // start while loop
            flush_ptr();
            
            // empty while loop
            if(next_ch == ']') {
                /*
                 *  111d:       8a 04 39                mov    (%rcx,%rdi,1),%al #
                 *  1120:       3c 00                   cmp    $0x0,%al
                 *  
                 *  0000000000001122 <l>:
                 *  1122:       90                      nop
                 *  1123:       75 fd                   jne    1122 <l>
                 */
                jit_append_buf(
                    0x8a, 0x04, 0x39,
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
                        jit_append_buf(0x8a,0x1c,0x39); //mov    (%rcx,%rdi,1),%bl
                        jit_append_buf(0xf6, 0xe3); // mul %bl
                        
                        jit_append_buf(0x48, 0x89, 0xcb); // mov %rcx, %rbx
                        jit_append_buf(0x48, 0x81, 0xc3, B1(rela_ptr),B2(rela_ptr),B3(rela_ptr),B4(rela_ptr)); // add $rela_ptr,%rbx
                        jit_append_buf(0x00, 0x04, 0x3b); // add    %al,(%rbx,%rdi,1)
                        // add, not mov!
                    }
                    else if (c=='>') rela_ptr++;
                    else if (c=='<') rela_ptr--;
                    i++;
                }
                jit_append_buf(0xc6, 0x04, 0x39, 0x00); // movb $0x00, (%rcx,%rdi,1)
                
                i++; // skip ]
                
                simple_opt = 1;
                
            } while(0);
            if(simple_opt) continue;

            uint64_t addr = _bfjit_mem_ptr;
            uint64_t placeholder = _bfjit_mem_ptr+1;
            jit_append_buf(0xe9, 0xde, 0xad, 0xbe, 0xef); // jmpq [condition]
            // [condition] is where the matching ']' is in asm space
            addr_node_append(i, addr, placeholder);
        } else if (c==']') { // end while loop
            flush_ptr();
            // while loop jump condition: *ptr != 0
            uint64_t addr = _bfjit_mem_ptr;
            jit_append_buf(0x8a, 0x04, 0x39, // mov (%rcx,%rdi,1),%al
                           0x3c, 0x00);       // cmp $0x0, %al
            uint64_t placeholder = _bfjit_mem_ptr+2;
            jit_append_buf(0x0f, 0x85, 0xde, 0xad, 0xbe, 0xef); // jne [while contents]
            // [while contents] is where the matching '[' is in asm space
            addr_node_append(i, addr, placeholder);
        }
        i++;
    }
    flush_ptr();

#ifdef DEBUG
    jit_append_buf(0x48, 0x89, 0xc8); //mov    %rcx,%rax
#endif
    jit_append_buf(0xc3); // retq
    
    jit_fill_placeholders(str);
#ifdef DEBUG
    printf("Execute...\n");
    bp();
    uint64_t ptr = _bfjit(tape); // %rdi = tape;
#else
    bp();
    _bfjit(tape);
#endif
    
#ifdef DEBUG
    printf("\n\n(ptr: %ju) ", ptr);
    for(int i = 0; i < 10; i++) {
        printf("%d ", tape[i]);
    }
#endif
    
    return 0;
}
