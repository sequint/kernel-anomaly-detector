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
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/signal.h>

// Static threshold definitions
#define CPU_THRESHOLD 80  // sec
#define MEM_THRESHOLD (100 * 1024)  // MB
#define NET_SEND_THRESHOLD 10  // MB
#define NET_REC_THRESHOLD 50  //MB

static struct task_struct *monitor_thread;  // For timed process delays and loop

static void monitorProcesses(void)
{
    pr_info("\nANOMALY MONITOR - BEGIN\n");
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

            printk(KERN_INFO "ANOMALY MONITOR - [%04ld-%02d-%02d %02d:%02d:%02d] Flagged Anomaly for Process: %s, PID: %d\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                task->comm, task->pid);

            // Log all anomalies found for this process
            if (cpu_usage > CPU_THRESHOLD)
            {
                printk(KERN_INFO "ANOMALY MONITOR - CPU Usage: %lu seconds\n", cpu_usage);
            }
            if (mem_usage > MEM_THRESHOLD)
            {
                printk(KERN_INFO "ANOMALY MONITOR - Memory Usage: %lu MB\n", mem_usage);
            }
            if (send_bandwidth > NET_SEND_THRESHOLD)
            {
                printk(KERN_INFO "ANOMALY MONITOR - Network Send Bandwidth: %u MB\n", send_bandwidth);
            }
            if (rec_bandwidth > NET_REC_THRESHOLD)
            {
                printk(KERN_INFO "ANOMALY MONITOR - Network Receive Bandwidth: %u MB\n", rec_bandwidth);
            }

            anomaly_found = true;
        }
    }

    if (!anomaly_found)
    {
        printk(KERN_INFO "ANOMALY MONITOR - No process anomalies found\n");
    }

    pr_info("\nANOMALY MONITOR - END\n");
}

static int monitor_thread_func(void *data)
{
    // While the kernel thread does not need to stop, run monitorProcesses every 30 seconds
    while (!kthread_should_stop())
    {
        monitorProcesses();
        ssleep(30);
    }

    return 0;
}

static int __init anomaly_module_init(void)
{
    // Create the kthread for monitoring
    monitor_thread = kthread_run(monitor_thread_func, NULL, "monitor_thread");
    if (IS_ERR(monitor_thread))
    {
        pr_err("Failed to create monitoring thread\n");
        return PTR_ERR(monitor_thread);
    }

    return 0;
}

static void __exit anomaly_module_exit(void)
{
    // Stop the monitoring thread before unloading the module
    if (monitor_thread)
    {
        kthread_stop(monitor_thread);
        pr_info("Monitoring thread stopped\n");
    }

    pr_info("Kernel Module Unloaded\n");
}

module_init(anomaly_module_init);
module_exit(anomaly_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Quintana, Mason Wilson IV");
MODULE_DESCRIPTION("Anomoly Detection Kernel Module");
MODULE_VERSION("1.1");