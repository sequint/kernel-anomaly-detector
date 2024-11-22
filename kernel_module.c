#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/net.h>
#include <linux/fdtable.h>
#include <linux/socket.h>
#include <net/sock.h>

// Static threshold definitions
#define CPU_THRESHOLD 80  // sec
#define MEM_THRESHOLD (100 * 1024)  // MB
#define NET_SEND_THRESHOLD 10  // MB
#define NET_REC_THRESHOLD 50  //MB

static void monitorProcesses(void)
{
    struct task_struct *task; // Set a task struct pointer to use for each process
    bool anomaly_found = false;

    for_each_process(task)
    {
        unsigned long cpu_usage = (task->utime + task->stime) / HZ;  // CPU usage in sec based on sum of user and system time for a process
        unsigned long mem_usage = (task->mm) ? get_mm_rss(task->mm) * PAGE_SIZE / 1024 : 0;  // Memory usage for the process converted from KB to MB
        unsigned int send_bandwidth = 0;
        unsigned int rec_bandwidth = 0;
        
        struct files_struct *files;
        struct fdtable *fdt;
        struct socket *sock;
        struct sock *sk;

        rcu_read_lock();
        files = task->files;
        if (files)
        {
            fdt = files_fdtable(files);
            if (fdt)
            {
                for (int fd = 0; fd < fdt->max_fds; fd++)
                {
                    struct file *file = fdt->fd[fd];
                    if (!file || !S_ISSOCK(file->f_path.dentry->d_inode->i_mode))
                    {
                        continue; // Skip non-socket files
                    }
                    sock = (struct socket *)file->private_data;
                    if (sock && sock->sk)
                    {
                        sk = sock->sk;
                        send_bandwidth += sk->sk_wmem_queued / (1024 * 1024); // Convert bytes to MB
                        rec_bandwidth += sk->sk_rmem_alloc.counter / (1024 * 1024); // Convert bytes to MB
                    }
                }
            }
        }
        rcu_read_unlock();

        if (cpu_usage > CPU_THRESHOLD || mem_usage > MEM_THRESHOLD || send_bandwidth > NET_SEND_THRESHOLD || rec_bandwidth > NET_REC_THRESHOLD)
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
                printk(KERN_INFO "CPU Usage: %lu seconds\n", cpu_usage);
            }
            if (mem_usage > MEM_THRESHOLD)
            {
                printk(KERN_INFO "Memory Usage: %lu MB\n", mem_usage);
            }
            if (send_bandwidth > NET_SEND_THRESHOLD)
            {
                printk(KERN_INFO "Network Send Bandwidth: %u MB\n", send_bandwidth);
            }
            if (rec_bandwidth > NET_REC_THRESHOLD)
            {
                printk(KERN_INFO "Network Receive Bandwidth: %u MB\n", rec_bandwidth);
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
    monitorProcesses();
    pr_info("Kernel Module Loaded\n");
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