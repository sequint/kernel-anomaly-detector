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
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define LOG_FILE "/var/log/anomaly_monitor.log"

// Default threshold values
static unsigned long CPU_THRESHOLD = 80;      // sec
static unsigned long MEM_THRESHOLD = 100 * 1024; // MB
static unsigned int NET_SEND_THRESHOLD = 10;  // MB
static unsigned int NET_REC_THRESHOLD = 50;   // MB

// Variable threshold values
static unsigned long total_cpu_threshold = 0;
static unsigned long total_mem_threshold = 0;
static unsigned long total_net_send_threshold = 0;
static unsigned long total_net_rec_threshold = 0;
static unsigned int update_count = 0;

static struct task_struct *monitor_thread;

static void log_to_file(const char *message)
{
    struct file *file;
    loff_t pos = 0;
    int ret;

    file = filp_open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file)) {
        pr_err("ANOMALY MONITOR - Failed to open log file: %ld\n", PTR_ERR(file));
        return;
    }

    /* Write to the file */
    ret = kernel_write(file, message, strlen(message), &pos);
    if (ret < 0)
        pr_err("ANOMALY MONITOR - Failed to write to log file: %d\n", ret);

    filp_close(file, NULL);
}

// Updates threshold values based on mean at every iteration
static void update_thresholds(unsigned long new_cpu, unsigned long new_mem, unsigned int new_send, unsigned int new_rec)
{
    // If this is the first process run, set inititial thresholds to current values
    if (update_count == 0)
    {
        CPU_THRESHOLD = new_cpu;
        MEM_THRESHOLD = new_mem;
        NET_SEND_THRESHOLD = new_send;
        NET_REC_THRESHOLD = new_rec;
    }
    // Otherwise sum the thresholds running total and update thresholds to their mean values
    else
    {
        total_cpu_threshold += new_cpu;
        total_mem_threshold += new_mem;
        total_net_send_threshold += new_send;
        total_net_rec_threshold += new_rec;

        CPU_THRESHOLD = total_cpu_threshold / update_count;
        MEM_THRESHOLD = total_mem_threshold / update_count;
        NET_SEND_THRESHOLD = total_net_send_threshold / update_count;
        NET_REC_THRESHOLD = total_net_rec_threshold / update_count;
    }

    update_count++;
}

static void monitorProcesses(void)
{
    struct task_struct *task;
    char log_message[256];
    bool anomaly_found = false;

    pr_info("ANOMALY MONITOR - BEGIN\n");

    for_each_process(task)
    {
        unsigned long cpu_usage = (task->utime + task->stime) / HZ;
        unsigned long mem_usage = (task->mm) ? get_mm_rss(task->mm) * PAGE_SIZE / 1024 : 0;
        unsigned int send_bandwidth = 0, rec_bandwidth = 0;

        // Lock read while traversing through process sockets to avoid race conditions
        rcu_read_lock();
        struct files_struct *files = task->files;
        if (files)
        {
            struct fdtable *fdt = files_fdtable(files);
            if (fdt)
            {
                for (int fd = 0; fd < fdt->max_fds; fd++)
                {
                    struct file *file = fdt->fd[fd];
                    if (!file || !S_ISSOCK(file->f_path.dentry->d_inode->i_mode))
                    {
                        continue;
                    }

                    struct socket *sock = (struct socket *)file->private_data;
                    if (sock && sock->sk)
                    {
                        struct sock *sk = sock->sk;
                        send_bandwidth += sk->sk_wmem_queued / (1024 * 1024);
                        rec_bandwidth += sk->sk_rmem_alloc.counter / (1024 * 1024);
                    }
                }
            }
        }
        rcu_read_unlock();

        if (cpu_usage > CPU_THRESHOLD || mem_usage > MEM_THRESHOLD ||
            send_bandwidth > NET_SEND_THRESHOLD || rec_bandwidth > NET_REC_THRESHOLD)
        {
            struct timespec64 ts;
            struct tm tm;
            ktime_get_real_ts64(&ts);
            time64_to_tm(ts.tv_sec, 0, &tm);

            // Create anomaly log message, then log to file and print the log
            snprintf(log_message, sizeof(log_message),
                     "[%04ld-%02d-%02d %02d:%02d:%02d] PID:%d COMM:%s CPU:%lu MEM:%lu SEND:%u RECV:%u\n",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                     task->pid, task->comm, cpu_usage, mem_usage, send_bandwidth, rec_bandwidth);
            log_to_file(log_message);
            pr_info("%s", log_message);

            anomaly_found = true;
        }

        // Update global thresholds based on each process
        update_thresholds(cpu_usage, mem_usage, send_bandwidth, rec_bandwidth);
    }

    if (!anomaly_found)
    {
        pr_info("ANOMALY MONITOR - No anomalies detected\n");
    }

    pr_info("ANOMALY MONITOR - END\n");
}

static int monitor_thread_func(void *data)
{
    while (!kthread_should_stop()) {
        monitorProcesses();
        ssleep(30);
    }
    return 0;
}

static int __init anomaly_module_init(void)
{
    monitor_thread = kthread_run(monitor_thread_func, NULL, "monitor_thread");
    if (IS_ERR(monitor_thread))
    {
        return PTR_ERR(monitor_thread);
    }

    pr_info("ANOMALY MONITOR - Module Loaded\n");
    return 0;
}

static void __exit anomaly_module_exit(void)
{
    if (monitor_thread)
    {
        kthread_stop(monitor_thread);
    }

    pr_info("ANOMALY MONITOR - Module Unloaded\n");
}

module_init(anomaly_module_init);
module_exit(anomaly_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Quintana, Mason Wilson IV");
MODULE_DESCRIPTION("Anomaly Detection Kernel Module with Dynamic Thresholds");
MODULE_VERSION("2.1");