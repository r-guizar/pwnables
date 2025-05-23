#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000)

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){    // check that there is one cl arg
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY);   // open library file
    if( fstat(fd,&st) < 0){                                     // get file info of library file
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;                                      // set size of library file in st struct

    // map the library file
    // to BASE addr
    // of length len_file
    // with rwx permissions
    // as a private mapping
    // with its fd
    // at offset 0
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){ 
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){           // loop through all chars of argv[1]
        if( !is_ascii(argv[1][i]) ){            // check that each char is ascii
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);                              // call vuln with argv[1]

}




