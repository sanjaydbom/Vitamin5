#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#include "filesys/filesys.h"

#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
bool validate_user_buffer(void *pointer, size_t length, bool check_writable);
bool validate_user_string(const char *string);
bool is_valid_user_read(const void *uaddr, size_t size) ;

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);
    if (!is_valid_user_read(args, sizeof(uint32_t) * 2)) {
        printf("%s: exit(-1)\n", thread_current()->name);
        if(thread_current()->parent_process != NULL){
            thread_current()->parent_process->exit_status = -1;
            thread_current()->parent_process->is_alive = false;
            sema_up(&(thread_current()->parent_process->lock));
        }
        thread_exit();
}

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
        if(thread_current()->parent_process != NULL){
            thread_current()->parent_process->exit_status = f->eax;
            thread_current()->parent_process->is_alive = false;
            sema_up(&(thread_current()->parent_process->lock));
        }
        thread_exit();
    }
    else if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }
    else if(args[0] == SYS_CREATE) {
        if(validate_user_string(args[1]))
            f->eax = filesys_create(args[1], args[2]);
        else {
            f->eax = -1;
            printf("%s: exit(-1)\n", thread_current()->name);
            if(thread_current()->parent_process != NULL){
                thread_current()->parent_process->exit_status = f->eax;
                thread_current()->parent_process->is_alive = false;
                sema_up(&(thread_current()->parent_process->lock));
            }
            thread_exit();
        }
            
    }
    else if(args[0] == SYS_REMOVE) {
        if(validate_user_string(args[1]))
            f->eax = filesys_remove(args[1]);
        else {
            f->eax = -1;
            printf("%s: exit(-1)\n", thread_current()->name);
            if(thread_current()->parent_process != NULL){
                thread_current()->parent_process->exit_status = f->eax;
                thread_current()->parent_process->is_alive = false;
                sema_up(&(thread_current()->parent_process->lock));
            }
            thread_exit();
        }
    }
    else if(args[0] == SYS_OPEN) {
        if(validate_user_string(args[1])) {
            struct thread* current_thread = thread_current();
            bool valid = false;
            for(int i = 0; i < 128; i++) {
                if(current_thread->fdt[i] == NULL){
                    current_thread->fdt[i] = filesys_open(args[1]);
                    if(current_thread->fdt[i] == NULL) {
                        f->eax = -1;
                    }
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
        else{
            f->eax = -1;
            printf("%s: exit(-1)\n", thread_current()->name);
            if(thread_current()->parent_process != NULL){
                thread_current()->parent_process->exit_status = f->eax;
                thread_current()->parent_process->is_alive = false;
                sema_up(&(thread_current()->parent_process->lock));
            }
            thread_exit();
        }
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
            if(validate_user_buffer(args[2],args[3],false)) {
                struct thread* current_thread = thread_current();
                if(current_thread->fdt[args[1] - 2] == NULL)
                    f->eax = -1;
                else
                    f->eax = file_read(current_thread->fdt[args[1]-2], args[2], args[3]);
            }
            else{  
                f->eax = -1;
                printf("%s: exit(-1)\n", thread_current()->name);
                if(thread_current()->parent_process != NULL){
                    thread_current()->parent_process->exit_status = f->eax;
                    thread_current()->parent_process->is_alive = false;
                    sema_up(&(thread_current()->parent_process->lock));
                }
                thread_exit();
            }
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
                if(validate_user_buffer(args[2],args[3],false)) {
                    struct thread* current_thread = thread_current();
                    if(current_thread->fdt[args[1] - 2] == NULL)
                        f->eax = -1;
                    else
                        f->eax = file_write(current_thread->fdt[args[1]-2], args[2], args[3]);
                }
                else{
                    f->eax = -1;
                    printf("%s: exit(-1)\n", thread_current()->name);
                    if(thread_current()->parent_process != NULL){
                        thread_current()->parent_process->exit_status = f->eax;
                        thread_current()->parent_process->is_alive = false;
                        sema_up(&(thread_current()->parent_process->lock));
                    }
                    thread_exit();
                }
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
    else if(args[0] == SYS_EXEC) {
        if(!validate_user_string(args[1])){
            f->eax = -1;
            printf("%s: exit(-1)\n", thread_current()->name);
            if(thread_current()->parent_process != NULL){
                thread_current()->parent_process->exit_status = f->eax;
                thread_current()->parent_process->is_alive = false;
                sema_up(&(thread_current()->parent_process->lock));
            }
            thread_exit();
        } else {
            f->eax = child_process_execute(args[1]);
        }
    }
    else if(args[0] == SYS_WAIT) {
        struct thread* ct = thread_current();
        for (struct list_elem* e = list_begin (&(ct->child_processes)); e != list_end (&(ct->child_processes)); e = list_next (e)){
            struct child_struct* g = list_entry (e, struct child_struct, elem);
            if(g->pid == args[1])
            {
                if(g->is_waited_on){
                    f->eax = -1;
                    return;
                }
                else if(!g->is_alive){
                    f->eax = g->exit_status;
                    list_remove(&(g->elem));
                    free(g);
                    return;
                }
                else {
                    g->is_waited_on = true;
                    sema_down(&(g->lock));
                    f->eax = g->exit_status;
                    list_remove(&(g->elem));
                    free(g);
                    return;
                }
            }
        }
        f->eax = -1;
    }
}

bool validate_user_buffer(void *pointer, size_t length, bool check_writable) {
    void* addr;
    for(int i = 0; i <= length; i += PGSIZE) {
        addr = pagedir_get_page(thread_current()->pagedir, pg_round_down(pointer + i));
        if(addr == NULL)
            return false;
    }
    return true;
}

bool validate_user_string(const char *string) {
    for (const char *ptr = string; ; ptr++) {
        if (!is_user_vaddr(ptr)) {
            return false;
        }

        if (pagedir_get_page(thread_current()->pagedir, pg_round_down(ptr)) == NULL) {
            return false;
        }
        if (*ptr == '\0') {
            return true;
        }
    }
}

bool is_valid_user_read(const void *uaddr, size_t size) {
    const char *ptr = (const char *)uaddr;
    const char *end_ptr = ptr + size;
    if (!is_user_vaddr(ptr)) {
        return false;
    }
    const char *page_start = (const char *)pg_round_down(ptr);
    
    for (const char *curr_page = page_start; curr_page < end_ptr; curr_page += PGSIZE) {
        
        if (!is_user_vaddr(curr_page)) {
             return false;
        }
        if (pagedir_get_page(thread_current()->pagedir, curr_page) == NULL) {
            return false;
        }
    }

    if (!is_user_vaddr(end_ptr)) {
        return false;
    }

    return true;
}