// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * TODO 1/0: Fill in name / email
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

#define PROCFS_MAX_SIZE 512

#define procfs_dir_name "list"
#define procfs_file_read "preview"
#define procfs_file_write "management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/* TODO 2: define your list! */

/* structura pentru elementele listei */
struct name_list
{
	char name[100];
	struct list_head list;
};

LIST_HEAD(my_list);

static int list_proc_show(struct seq_file *m, void *v)
{
	/* TODO 3: print your list. One element / line. */

	struct list_head *i;
	struct name_list *itr;

	/* parcurg lista si afisez fiecare element */
	list_for_each(i, &my_list)
	{
		/* extrag structura din lista */
		itr = list_entry(i, struct name_list, list);
		/* afisez numele din structura */
		seq_printf(m, "%s\n", itr->name);
	}
	return 0;
}

static int list_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
						  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */

	/* voi folosi command ca sa extrag comanda si name pentru numele pe
	 * care se va executa aceeasta
	 */
	char command[5];
	char name[100];
	/* extrag comanda si numele din buffer */
	sscanf(local_buffer, "%s %s", command, name);

	/* daca comanda este addf atunci adaug elementul la inceputul listei */
	if (strcmp(command, "addf") == 0)
	{
		/* aloc un element nou */
		struct name_list *new = kmalloc(sizeof *new, GFP_KERNEL);
		/* verific daca alocarea a reusit */
		if (!new)
			return -ENOMEM;
		/* copiez numele in elementul nou */
		strcpy(new->name, name);
		/* adaug elementul nou in lista */
		list_add(&new->list, &my_list);
	}

	/* daca comanda este adde atunci adaug elementul la sfarsitul listei */
	if (strcmp(command, "adde") == 0)
	{
		/* aloc un element nou */
		struct name_list *new = kmalloc(sizeof *new, GFP_KERNEL);
		/* verific daca alocarea a reusit */
		if (!new)
			return -ENOMEM;
		/* copiez numele in elementul nou */
		strcpy(new->name, name);
		list_add_tail(&new->list, &my_list);
	}

	/* daca comanda este delf atunci sterg primul element cu numele name */
	if (strcmp(command, "delf") == 0)
	{
		struct list_head *i, *tmp;
		struct name_list *itr;
		/* parcurg lista */
		list_for_each_safe(i, tmp, &my_list)
		{
			/* extrag structura din lista */
			itr = list_entry(i, struct name_list, list);
			/* verific daca numele din structura este egal cu numele
			 * dat ca parametru */
			if (strcmp(itr->name, name) == 0)
			{
				/* sterg elementul din lista */
				list_del(i);
				kfree(itr);
				break;
			}
		}
	}
	/* daca comanda este dela atunci sterg toate elementele cu numele name */
	if (strcmp(command, "dela") == 0)
	{
		struct list_head *i, *tmp;
		struct name_list *itr;
		/* parcurg lista */
		list_for_each_safe(i, tmp, &my_list)
		{
			/* extrag structura din lista */
			itr = list_entry(i, struct name_list, list);
			/* verific daca numele din structura este egal cu numele
			 * dat ca parametru */
			if (strcmp(itr->name, name) == 0)
			{
				/* sterg elementul din lista */
				list_del(i);
				kfree(itr);
			}
		}
	}

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open = list_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static const struct proc_ops w_pops = {
	.proc_open = list_write_open,
	.proc_write = list_write,
	.proc_release = single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
								 &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
								  &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("Alin-Ionuț Andrei <alin_ionut.andrei99@stud.acs.upb.ro>");
MODULE_LICENSE("GPL v2");
