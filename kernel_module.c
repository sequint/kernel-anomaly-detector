#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/seq_file.h>

// Temporary threshold definitions
#define CPU_THRESHOLD 80
#define MEM_THRESHOLD (100 * 1024) // 100MB

void monitorProcesses(void);

int init_module(void)
{
    pr_info("Kernel Module Loaded\n");
    return 0;
}

void cleanup_module(void)
{
    pr_info("Kernel Module Unloaded\n");
}

void monitorProcesses(void)
{
    struct task_stuct *task;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Quintana, Mason Wilson IV");
MODULE_DESCRIPTION("Anomoly Detection Kernel Module");
MODULE_VERSION("1.1");