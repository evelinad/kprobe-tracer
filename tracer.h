/*
 * SO2 kprobe based tracer header file
 * 2013, Operating Systems 2 - Ixia Challenge
 * 
 * this is shared with user space
 */

#ifndef TRACER_H__
#define TRACER_H__ 1
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/list.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/uaccess.h>


#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

#define TRACER_DEV_MINOR 42
#define TRACER_DEV_NAME "tracer"

#define TRACER_ADD_PROCESS	_IOW(_IOC_WRITE, 42, pid_t)
#define TRACER_REMOVE_PROCESS	_IOW(_IOC_WRITE, 43, pid_t)


struct process {
  pid_t pid;
  unsigned kmalloc;
  unsigned kfree;
  unsigned kmalloc_mem;
  unsigned kfree_mem;
  unsigned sched;
  unsigned up;
  unsigned down;
  unsigned lock;
  unsigned unlock;
};

struct proc_list {
  struct process *data;
  struct list_head list;
};

struct allocated_list {
  unsigned size;
  void *address;
  struct list_head list;
};

#endif /* TRACER_H_ */
