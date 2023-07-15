/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Alin-Ionuț Andrei <alin_ionut.andrei99@stud.acs.upb.ro>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>

#include "tracer.h"

#define KMALLOC_FUNC "__kmalloc"
#define KFREE_FUNC "kfree"
#define MUTEX_LOCK_FUNC "mutex_lock_nested"
#define MUTEX_UNLOCK_FUNC "mutex_unlock"
#define UP_FUNC "up"
#define SCHEDULE_FUNC "schedule"
#define DOWN_INTERRUPTIBLE_FUNC "down_interruptible"
#define TRACER "tracer"
#define MAX_ACTIVE 32

static struct proc_dir_entry *tracer_read;
/* Srtuctura pentru elementele listei */
struct process_info
{
	/* pid-ul procesului, numarul de apeluri ale functiilor si memoria alocata
	 */
	pid_t pid;
	int kmalloc;
	int kfree;
	int kmalloc_mem;
	int kfree_mem;
	int schedule;
	int up;
	int down_interruptible;
	int mutex_lock;
	int mutex_unlock;
	struct list_head list;
};

LIST_HEAD(processList);

static int add_process(pid_t pid)
{
	/* Adaugarea unui proces in lista de procese monitorizate */
	struct process_info *newEntry = kmalloc(sizeof *newEntry, GFP_KERNEL);
	if (!newEntry)
		return -ENOMEM;

	newEntry->pid = pid;
	newEntry->kmalloc = 0;
	newEntry->kmalloc_mem = 0;
	newEntry->kfree = 0;
	newEntry->kfree_mem = 0;
	newEntry->schedule = 0;
	newEntry->up = 0;
	newEntry->down_interruptible = 0;
	newEntry->mutex_lock = 0;
	newEntry->mutex_unlock = 0;

	list_add(&newEntry->list, &processList);

	return 0;
}
static int remove_process(pid_t pid)
{
	/* Stergerea unui proces din lista de procese monitorizate */
	struct list_head *i, *tmp;
	struct process_info *itr;

	list_for_each_safe(i, tmp, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == pid)
		{
			list_del(i);
			kfree(itr);
		}
	}

	return 0;
}
static int kmalloc_entry_handler(struct kretprobe_instance *ri,
								 struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de kmalloc */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->kmalloc++;
		}
	}
	return 0;
}

static int kfree_entry_handler(struct kretprobe_instance *ri,
							   struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de kfree */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->kfree++;
		}
	}
	return 0;
}
static int schedule_entry_handler(struct kretprobe_instance *ri,
								  struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de schedule */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->schedule++;
		}
	}
	return 0;
}
static int up_entry_handler(struct kretprobe_instance *ri,
							struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de up */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->up++;
		}
	}
	return 0;
}
static int down_interruptible_entry_handler(struct kretprobe_instance *ri,
											struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de down_interruptible */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->down_interruptible++;
		}
	}
	return 0;
}
static int mutex_lock_entry_handler(struct kretprobe_instance *ri,
									struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de mutex_lock */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->mutex_lock++;
		}
	}
	return 0;
}
static int mutex_unlock_entry_handler(struct kretprobe_instance *ri,
									  struct pt_regs *regs)
{
	/* Functie ce contorizeaza numarul de apeluri de mutex_unlock */
	struct list_head *i;
	struct process_info *itr;

	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		if (itr->pid == current->pid)
		{
			itr->mutex_unlock++;
		}
	}
	return 0;
}

static int tracer_device_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int tracer_device_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int list_proc_show(struct seq_file *m, void *v)
{
	/* Functie ce afiseaza informatiile despre procese */
	struct list_head *i;
	struct process_info *itr;
	seq_printf(
		m,
		"PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock\n");
	list_for_each(i, &processList)
	{
		itr = list_entry(i, struct process_info, list);
		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n",
				   itr->pid, itr->kmalloc, itr->kfree, itr->kmalloc_mem,
				   itr->kfree_mem, itr->schedule, itr->up,
				   itr->down_interruptible, itr->mutex_lock, itr->mutex_unlock);
	}
	return 0;
}
static int tracer_read_open(struct inode *inode, struct file *file)
{
	/* Functie ce deschide fisierul /proc/tracer */
	return single_open(file, list_proc_show, NULL);
}
static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* Functie ce implementeaza ioctl pentru tracer si adauga sau sterge
	 * procesele din lista de monitorizare
	 */
	int ret = 0;
	if (cmd == TRACER_ADD_PROCESS)
	{
		ret = add_process(arg);
	}
	if (cmd == TRACER_REMOVE_PROCESS)
	{
		ret = remove_process(arg);
	}
	if (ret < 0)
		pr_err("Command unknow: %d  err: %d\n", cmd, ret);

	return ret;
}

static const struct proc_ops tracer_pops = {
	/* Structura ce contine functiile de citire si deschidere pentru fisierul
	 * /proc/tracer
	 */
	.proc_open = tracer_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};
static const struct file_operations tracer_fops = {
	/* Structura ce contine functiile de deschidere si ioctl pentru fisierul
	 * /dev/tracer
	 */
	.owner = THIS_MODULE,
	.open = tracer_device_open,
	.release = tracer_device_release,
	.unlocked_ioctl = tracer_ioctl,
};

static struct miscdevice tracer_device = {
	/* Structura ce contine informatiile despre fisierul /dev/tracer */
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops,
};
static struct kretprobe kmalloc_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia kmalloc */
	.entry_handler = kmalloc_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = KMALLOC_FUNC},
};
static struct kretprobe kfree_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia kfree */
	.entry_handler = kfree_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = KFREE_FUNC},
};
static struct kretprobe schedule_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia schedule */
	.entry_handler = schedule_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = SCHEDULE_FUNC},
};
static struct kretprobe up_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia up */
	.entry_handler = up_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = UP_FUNC},
};
static struct kretprobe down_interruptible_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia
	 * down_interruptible
	 */
	.entry_handler = down_interruptible_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = DOWN_INTERRUPTIBLE_FUNC},
};
static struct kretprobe mutex_lock_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia mutex_lock */
	.entry_handler = mutex_lock_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = MUTEX_LOCK_FUNC},
};
static struct kretprobe mutex_unlock_kretprobe = {
	/* Structura ce contine hendlerul de intrare pentru functia mutex_unlock */
	.entry_handler = mutex_unlock_entry_handler,
	.maxactive = MAX_ACTIVE,
	.kp = {.symbol_name = MUTEX_UNLOCK_FUNC},
};

static int __init tracer_init(void)
{
	/* Functie ce initializeaza modulul */
	int err;

	/* Initializare kretprobe pentru functiile kmalloc, kfree, schedule, up,
	 * down_interruptible, mutex_lock, mutex_unlock apelate de procese
	 */
	err = register_kretprobe(&kmalloc_kretprobe);
	if (err < 0)
	{
		pr_err("kmalloc_kretprobe register error: %d\n", err);
		return err;
	}
	err = register_kretprobe(&kfree_kretprobe);
	if (err < 0)
	{
		pr_err("kfree_kretprobe register error: %d\n", err);
		return err;
	}
	err = register_kretprobe(&schedule_kretprobe);
	if (err < 0)
	{
		pr_err("schedule_kretprobe register error: %d\n", err);
		return err;
	}
	err = register_kretprobe(&up_kretprobe);
	if (err < 0)
	{
		pr_err("up_kretprobe register error: %d\n", err);
		return err;
	}
	err = register_kretprobe(&down_interruptible_kretprobe);
	if (err < 0)
	{
		pr_err("down_interruptible_kretprobe register error: %d\n", err);
		return err;
	}
	err = register_kretprobe(&mutex_lock_kretprobe);
	if (err < 0)
	{
		pr_err("mutex_lock_kretprobe register error: %d\n", err);
		return err;
	}
	err = register_kretprobe(&mutex_unlock_kretprobe);
	if (err < 0)
	{
		pr_err("mutex_unlock_kretprobe register error: %d\n", err);
		return err;
	}

	/* Se creaza fisierul /dev/tracer */
	err = misc_register(&tracer_device);
	if (err)
	{
		printk(KERN_ERR "register error tracer misc device\n");
		return err;
	}
	/* Se creaza fisierul /proc/tracer */
	tracer_read = proc_create(TRACER, 0000, NULL, &tracer_pops);
	if (!tracer_read)
	{
		printk(KERN_ERR "create tracer error\n");
		return err;
	}
	return 0;
}
static void __exit tracer_exit(void)
{
	/* Functie ce elibereaza resursele modulului */
	unregister_kretprobe(&kmalloc_kretprobe);
	unregister_kretprobe(&kfree_kretprobe);
	unregister_kretprobe(&schedule_kretprobe);
	unregister_kretprobe(&up_kretprobe);
	unregister_kretprobe(&down_interruptible_kretprobe);
	unregister_kretprobe(&mutex_lock_kretprobe);
	unregister_kretprobe(&mutex_unlock_kretprobe);

	misc_deregister(&tracer_device);
	remove_proc_entry(TRACER, NULL);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Alin-Ionuț Andrei alin_ionut.andrei99@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");