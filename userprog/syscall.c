#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"

#include "filesys/filesys.h"

#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    /* printf("System call number: %d\n", args[0]); */

    if (args[0] == SYS_EXIT) {
        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);
        thread_exit();
    }
    else if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }
    /*else if(args[0] == SYS_WRITE) {
        putbuf(args[2], args[3]);
        f->eax = args[3];
    }*/
    else if(args[0] == SYS_CREATE) {
        f->eax = filesys_create(args[1], args[2]);
    }
    else if(args[0] == SYS_REMOVE) {
        f->eax = filesys_remove(args[1]);
    }
    else if(args[0] == SYS_OPEN) {
        if(args[1] == NULL)
            f->eax = -1;
        struct thread* current_thread = thread_current();
        bool valid = false;
        for(int i = 0; i < 128; i++) {
            if(current_thread->fdt[i] == NULL){
                current_thread->fdt[i] = filesys_open(args[1]);
                if(current_thread->fdt[i] == NULL)
                    f->eax=-1;
                else{
                    f->eax = i+2;
                    valid = true;
                    i = 128;
                }
            }
        }
        if(!valid)
            f->eax = -1;
    }
    else if(args[0] == SYS_FILESIZE) {
        if(args[1] < 2 || args[1] > 129)
            f->eax = -1;

        struct thread* current_thread = thread_current();
        if(current_thread->fdt[args[1] - 2] == NULL)
            f->eax = -1;
        else
            f->eax = file_length(current_thread->fdt[args[1] - 2]);
    }
    else if(args[0] == SYS_READ) {
        if(args[1] -2 < 0 || args[1] - 2 > 127)
            f->eax = -1;
        else {
            struct thread* current_thread = thread_current();
            if(current_thread->fdt[args[1] - 2] == NULL)
                f->eax = -1;
            else
                f->eax = file_read(current_thread->fdt[args[1]-2], args[2], args[3]);
        }
    }
    else if(args[0] == SYS_WRITE) {
        if(args[1] == 1) {
            putbuf(args[2], args[3]);
            f->eax = args[3];
        }
        else {
            if(args[1] -2 < 0 || args[1] - 2 > 127)
                f->eax = -1;
            else {
                struct thread* current_thread = thread_current();
                if(current_thread->fdt[args[1] - 2] == NULL)
                    f->eax = -1;
                else
                    f->eax = file_write(current_thread->fdt[args[1]-2], args[2], args[3]);
            }
        }
    }
    else if(args[0] == SYS_SEEK) {
        if(args[1] -2 < 0 || args[1] - 2 > 127)
            f->eax = -1;
        struct thread* current_thread = thread_current();
        if(current_thread->fdt[args[1] - 2] == NULL)
            f->eax = -1;
        else {
            file_seek(current_thread->fdt[args[1]-2], args[2]);
            f->eax = NULL;
        }
    }
    else if(args[0] == SYS_TELL) {
        if(args[1] -2 < 0 || args[1] - 2 > 127)
            f->eax = -1;
        struct thread* current_thread = thread_current();
        if(current_thread->fdt[args[1] - 2] == NULL)
            f->eax = -1;
        else
            f->eax = file_tell(current_thread->fdt[args[1]-2]);
    }
    else if(args[0] == SYS_CLOSE) {
        if(args[0] == 0 || args[0] == 1)
            ;
        else {
            if(args[1] -2 < 0 || args[1] - 2 > 127)
                f->eax = -1;
            else {
                struct thread* current_thread = thread_current();
                if(current_thread->fdt[args[1] - 2] == NULL)
                    f->eax = -1;
                else {
                    file_close(current_thread->fdt[args[1]-2]);
                    current_thread->fdt[args[1]-2] = NULL;
                    f->eax = NULL;
                }
            }
        }
    }
    else if(args[0] == SYS_HALT) {
        shutdown_power_off();
    }
}
