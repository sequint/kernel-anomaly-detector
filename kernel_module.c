#include <linux/module.h>
#include <linux/printk.h>

int init_module(void)
{
    pr_info("Kernel Module Loaded\n");
    return 0;
}

void cleanup_module(void)
{
    pr_info("Kernel Module Unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Quintana, Mason Wilson IV");
MODULE_DESCRIPTION("Anomoly Detection Kernel Module");
MODULE_VERSION("1.0");