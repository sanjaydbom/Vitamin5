#include "userprog/syscall.h"
#include "userprog/pagedir.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "filesys/filesys.h"

#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
bool validate_user_buffer(void *pointer, size_t length, bool check_writable);
bool validate_user_string(const char *string);

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
        if(validate_user_string(args[1]))
            f->eax = filesys_create(args[1], args[2]);
        else {
            f->eax = -1;
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
            
    }
    else if(args[0] == SYS_REMOVE) {
        if(validate_user_string(args[1]))
            f->eax = filesys_remove(args[1]);
        else {
            f->eax = -1;
            printf("%s: exit(-1)\n", thread_current()->name);
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
                else f->eax = -1;
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
    // 0. Preliminary Check (Required for safety and to handle NULL/Kernel addresses)
    if (string == NULL || !is_user_vaddr(string)) {
        return false;
    }

    uint32_t *pd = thread_current()->pagedir;
    const char *current_page_start = string;

    while (true) {
        // 1. Check if the current page is mapped (present).
        // This is the expensive check, done only at the start of a new page.
        if (pagedir_get_page(pd, (void *)current_page_start) == NULL) {
            return false; // Unmapped page found.
        }

        // 2. Iterate through bytes in the current mapped page to find '\0'.
        // We use the pointer (string) and search until we hit the next page boundary,
        // which is pg_round_down(string) + PGSIZE.
        const char *page_end = (const char *)pg_round_down((uintptr_t)current_page_start) + PGSIZE;
        
        // This loop searches from the start of the *unsearched* portion of the page.
        // It's safer to use an index within the page boundaries to avoid overshooting.
        
        for (const char *p = current_page_start; p < page_end; p++) {
            // Check for kernel boundary again (redundant but safe after pointer arithmetic)
            if (!is_user_vaddr(p)) {
                return false; // String runs into kernel space mid-page.
            }

            // Check the byte (this read is now safe because we called pagedir_get_page above)
            if (*p == '\0') {
                return true; // Found the terminator on a validated page!
            }
        }
        
        // 3. Prepare for next iteration (Advance to the next page).
        current_page_start = page_end;

        // 4. Check if the next page is still below PHYS_BASE.
        if (!is_user_vaddr(current_page_start)) {
            return false; // String runs off user memory.
        }
        
        // If we reach here, the string spans the whole page, and we proceed to validate the next page in the loop.
    }
}
