#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>

// Static threshold definitions
#define CPU_THRESHOLD 80
#define MEM_THRESHOLD (100 * 1024) // 100MB

static void monitorProcesses(void)
{
    struct task_struct *task; // Set a task struct pointer to use for each process
    bool anomaly_found = false;

    for_each_process(task)
    {
        unsigned long cpu_usage = task->utime + task->stime;  // CPU usage based on sum of user and system time for a process
        unsigned long mem_usage = (task->mm) ? get_mm_rss(task->mm) * PAGE_SIZE / 1024 : 0;  // Memory usage for the process converted from KB to MB

        if (cpu_usage > CPU_THRESHOLD || mem_usage > MEM_THRESHOLD)
        {
            // Use time stamp to get current time
            struct timespec64 ts;
            struct tm tm;
            ktime_get_real_ts64(&ts);
            time64_to_tm(ts.tv_sec, 0, &tm);
            
            printk(KERN_INFO "[%04ld-%02d-%02d %02d:%02d:%02d] Flagged Anomaly for Process: %s, PID: %d\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                task->comm, task->pid);

            // Log all anomalies found for this process
            if (cpu_usage > CPU_THRESHOLD)
            {
                printk(KERN_INFO "CPU Usage: %lu\n", cpu_usage);
            }
            if (mem_usage > MEM_THRESHOLD)
            {
                printk(KERN_INFO "Memory Usage: %lu\n", mem_usage);
            }

            anomaly_found = true;
        }
    }

    if (!anomaly_found)
    {
        printk(KERN_INFO "No process anomalies found\n");
    }
}

static int __init anomaly_module_init(void)
{

    pr_info("Kernel Module Loaded\n");
    monitorProcesses();
    return 0;
}

static void __exit anomaly_module_exit(void)
{
    pr_info("Kernel Module Unloaded\n");
}

module_init(anomaly_module_init);
module_exit(anomaly_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Quintana, Mason Wilson IV");
MODULE_DESCRIPTION("Anomoly Detection Kernel Module");
MODULE_VERSION("1.1");