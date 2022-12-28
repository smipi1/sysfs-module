#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pieter Smith");
MODULE_DESCRIPTION("iMX CAAM Secure Memory sysfs API.");
MODULE_VERSION("0.1");

static struct kobject *sm_sysfs_kobject;

static char *name = "world";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");

#define KEY_LEN		(32)

struct key_data {
	char const* write_filename;
	u8 write_buf[KEY_LEN];
};

struct key_data clear_key_data;
struct key_data black_key_data;

void init_key_data(struct key_data* kd, char const* name)
{
	memset(kd, 0, sizeof(*kd));
	kd->write_filename = name;
}

int blacken(u8* dest, u8 const* src, size_t len)
{
	memcpy(dest, src, KEY_LEN);
	return 0;
}

int clear(u8* dest, u8 const* src, size_t len)
{
	memcpy(dest, src, KEY_LEN);
	return 0;
}

ssize_t write_kb(struct key_data* const kd, struct file *file,
		struct kobject *kobj, struct bin_attribute *attr, char *buf,
		loff_t offset, size_t count)
{
	size_t len = offset + count;
	if((size_t) offset > sizeof(kd->write_buf)) {
		pr_err("sm_sysfs: %s: writing past start\n", kd->write_filename);
		return -EFAULT;
	}
	if(len > sizeof(kd->write_buf)) {
		pr_err("sm_sysfs: %s: buffer overflow\n", kd->write_filename);
		return -EOVERFLOW;
	}
	memcpy(kd->write_buf + offset, buf, count);
	return count;
}

ssize_t write_clear(struct file *file, struct kobject *kobj, struct bin_attribute *attr,
		char *buf, loff_t offset, size_t count)
{
	return write_kb(&clear_key_data, file, kobj, attr, buf, offset, count);
}

ssize_t write_black(struct file *file, struct kobject *kobj, struct bin_attribute *attr,
		char *buf, loff_t offset, size_t count)
{
	return write_kb(&black_key_data, file, kobj, attr, buf, offset, count);
}

ssize_t read_buf(u8* src, ssize_t len, struct file *file,
		struct kobject *kobj, struct bin_attribute *attr, char *buf,
		loff_t offset, size_t count)
{
	size_t max_count = len - offset;
	if(offset >= len) {
		return 0;
	}
	count = min(count, max_count);
	memcpy(buf, src + offset, count);
	return count;
}

ssize_t read_clear(struct file *file, struct kobject *kobj, struct bin_attribute *attr,
		char *buf, loff_t offset, size_t count)
{
	u8 dest[sizeof(black_key_data.write_buf)];
	int const error = clear(dest, black_key_data.write_buf, sizeof(dest));
	if(error) {
		pr_err("sm_sysfs: clear: cannot decrypt black\n");
		return error;
	}
	return read_buf(dest, sizeof(dest), file, kobj, attr, buf, offset, count);
}

ssize_t read_black(struct file *file, struct kobject *kobj, struct bin_attribute *attr,
		char *buf, loff_t offset, size_t count)
{
	u8 dest[sizeof(clear_key_data.write_buf)];
	int const error = blacken(dest, clear_key_data.write_buf, sizeof(dest));
	if(error) {
		pr_err("sm_sysfs: black: cannot encrypt clear\n");
		return error;
	}
	return read_buf(dest, sizeof(dest), file, kobj, attr, buf, offset, count);
}

static struct bin_attribute black_attr =__BIN_ATTR(
    black, 0660, read_black, write_black, KEY_LEN);

static struct bin_attribute clear_attr =__BIN_ATTR(
    clear, 0660, read_clear, write_clear, KEY_LEN);

static int __init sm_sysfs_init(void){
	int error = 0;

	pr_err("Module initialized successfully \n");

	sm_sysfs_kobject = kobject_create_and_add("sm_sysfs",
			kernel_kobj);
	if(!sm_sysfs_kobject)
	return -ENOMEM;

	error = sysfs_create_bin_file(sm_sysfs_kobject, &black_attr);
	if (error) {
		pr_debug("cannot create the black file in /sys/kernel/kobject_example \n");
		goto out;
	}

	error = sysfs_create_bin_file(sm_sysfs_kobject, &clear_attr);
	if (error) {
		pr_debug("cannot to create the clear file in /sys/kernel/kobject_example \n");
		goto out;
	}

	init_key_data(&clear_key_data, "clear");
	init_key_data(&black_key_data, "black");

out:
	if(error) {
		kobject_put(sm_sysfs_kobject);
	}
	return error;
}

static void __exit sm_sysfs_exit(void){
	pr_err("Module un initialized successfully \n");

	sysfs_remove_bin_file(sm_sysfs_kobject, &clear_attr);
	sysfs_remove_bin_file(sm_sysfs_kobject, &black_attr);

	kobject_put(sm_sysfs_kobject);
}

module_init(sm_sysfs_init);
module_exit(sm_sysfs_exit);
