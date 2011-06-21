/*
 * Virtual V4L2 camera
 *
 * Copyright (C) 2011 Mohammed Sameer <msameer@foolab.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/videodev2.h>
#include <media/v4l2-device.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-common.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf-vmalloc.h>
#include <linux/miscdevice.h>
#include <linux/stat.h>
#include <linux/sched.h> // needed for wake_up();
#include <linux/wait.h>
#include "fmt.h"

#define MODULE_NAME "vcamera"

static DEFINE_MUTEX(mutex);

struct vcamera_data {
  struct list_head active;
  struct videobuf_queue queue;

  int width;
  int height;
  int bytes_per_pixel;
  int n_buffers;
  unsigned long fmt;
  size_t size;
  volatile unsigned long used;
  spinlock_t lock;
  int reg;
};

static struct vcamera_data vcamera_data = {
  .active = LIST_HEAD_INIT(vcamera_data.active),
  .width = 0,
  .height = 0,
  .bytes_per_pixel = 0,
  .fmt = 0,
  .n_buffers = 0,
  .size = 0,
  .used = 0,
  .reg = 0,
};

static void vcamera_fill_fmt(struct v4l2_format *fmt)
{
  fmt->fmt.pix.width        = vcamera_data.width;
  fmt->fmt.pix.height       = vcamera_data.height;
  fmt->fmt.pix.field        = V4L2_FIELD_INTERLACED;
  fmt->fmt.pix.pixelformat  = vcamera_data.fmt;
  fmt->fmt.pix.bytesperline = fmt->fmt.pix.width * 2;
  fmt->fmt.pix.sizeimage = fmt->fmt.pix.width * vcamera_data.height * 2;
}

static int vidioc_g_fmt_vid_cap(struct file *file, void *priv,
				struct v4l2_format *fmt)
{
  vcamera_fill_fmt(fmt);

  return 0;
}

static int vcamera_char_open(struct inode *inode, struct file *file) {
  int ret = 0;
  mutex_lock(&mutex);

  if (test_and_set_bit(0, &vcamera_data.used)) {
    ret = -EBUSY;
  }

  mutex_unlock(&mutex);

  return ret;
}

static int vcamera_char_release(struct inode *inode, struct file *file) {
  mutex_lock(&mutex);

  clear_bit(0, &vcamera_data.used);

  mutex_unlock(&mutex);

  return 0;
}

static loff_t vcamera_char_llseek(struct file *file, loff_t offset, int whence) {
  loff_t pos;

  mutex_lock(&mutex);

  switch (whence) {
  case 0: // SEEK_SET
    pos = offset;
    break;
  case 1: // SEEK_CUR
    pos = file->f_pos + offset;
    break;
  case 2: // SEEK_END
    pos = vcamera_data.n_buffers * vcamera_data.size;
    break;
  default:
    mutex_unlock(&mutex);
    return -EINVAL;
  }

  file->f_pos = pos;

  mutex_lock(&mutex);

  return pos;
}
#if 0
static ssize_t vcamera_misc_read(struct file *file, char __user *data, size_t len, loff_t *off) {
  struct vcamera_buffer *buffer = 0;
  int index = 0;

  // TODO: cast :(
  if (len !=  vcamera_data.size || ((int)file->f_pos % vcamera_data.size) != 0) {
    return -EINVAL;
  }

  // TODO: cast :(
  index = (int)file->f_pos / vcamera_data.size;
  if (index >= vcamera_data.n_buffers) {
    return -EINVAL;
  }

  list_for_each_entry(buffer, &vcamera_data.buffers, list) {
    if (buffer->locked == 0) {
      buffer->locked = 1;
    }
    else {
      continue;
    }

    if (buffer->index != index) {
      buffer->locked = 0;
      continue;
    }

    if (copy_to_user(data, buffer->data, vcamera_data.size)) {
      buffer->locked = 0;
      return -EFAULT;
    }

    buffer->locked = 0;
    *off += vcamera_data.size;
    return vcamera_data.size;
  }

  return -EAGAIN;
}
#endif

static ssize_t vcamera_char_write(struct file *file, const char __user *data, size_t len,
				loff_t *off) {

  struct videobuf_buffer *buf = NULL;
  int ret = 0;

  if (test_bit(1, &vcamera_data.used) == 0) {
    return -EINVAL;
  }

  pr_info("pre lock");
  mutex_lock(&mutex);
  pr_info("post lock");

  pr_info("len: in %i, have %i", len, vcamera_data.size);
  if (vcamera_data.size != len) {
    pr_info("invalid size");
    ret = -EINVAL;
    goto unlock;
  }

  if (list_empty(&vcamera_data.active)) {
    pr_info("no buffers");
    ret = -EAGAIN;
    goto unlock;
  }

  // TODO: why next ?
  buf = list_entry(vcamera_data.active.next, struct videobuf_buffer, queue);

  if (!waitqueue_active(&buf->done)) {
    pr_info("no active");
    ret = -EAGAIN;
    goto unlock;
  }

  pr_info("pre del");

  list_del(&buf->queue);
  pr_info("post del");
  buf->state = VIDEOBUF_ACTIVE;

  pr_info("pre copy");

  if (copy_from_user(videobuf_to_vmalloc(buf), data, len)) {
    // TODO: what to do here ??!
    pr_info("copy failed");
    ret = -EFAULT;
    goto unlock;
  }

  //  memset(
  pr_info("post copy");

  buf->size = len;
  do_gettimeofday(&buf->ts);
  buf->field_count++;
  buf->state = VIDEOBUF_DONE;
  pr_info("pre wake");
  wake_up(&buf->done);
  pr_info("post wake");
  ret = len;

 unlock:
  mutex_unlock(&mutex);
  return ret;

#if 0
  struct vcamera_buffer *buffer = NULL;

  // TODO: cast ?! in the kernel ?!!
  loff_t index = (int)file->f_pos / vcamera_data.size;
  printk(KERN_INFO "pos: %lli, index: %lli, size: %i", file->f_pos, index, vcamera_data.size);

  if (index >= vcamera_data.n_buffers) {
    return -EINVAL;
  }

  // TODO: cast :(
  if (len != vcamera_data.size || ((int)file->f_pos % vcamera_data.size) != 0) {
    return -EINVAL;
  }

  list_for_each_entry(buffer, &vcamera_data.buffers, list) {
    if (buffer->locked == 0) {
      buffer->locked = 1;
    }
    else {
      continue;
    }

    if (buffer->index != index) {
      buffer->locked = 0;
      continue;
    }

    if (copy_from_user(buffer->data, data, len)) {
      buffer->locked = 0;
      return -EFAULT;
    }
    else {
      *off = (index + 1) * vcamera_data.size;
      buffer->locked = 0;

      printk(KERN_INFO "Wrote: %i %lli", buffer->index, index);
      return vcamera_data.size;
    }
  }

  return -EAGAIN;
#endif
}

static long vcamera_char_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  struct v4l2_format fmt;
  struct v4l2_requestbuffers bufs;

  int ret = 0;

  mutex_lock(&mutex);

  switch (cmd) {
  case VIDIOC_REQBUFS:
    bufs.count = vcamera_data.n_buffers;
    if (copy_to_user((struct v4l2_requestbuffers __user *)arg,
		     &bufs, sizeof(struct v4l2_requestbuffers))) {
      ret = -EFAULT;
      goto out;
    }

    break;
  case VIDIOC_G_FMT:
    vcamera_fill_fmt(&fmt);
    if (copy_to_user((struct v4l2_format __user *)arg, &fmt, sizeof(struct v4l2_format))) {
      ret = -EFAULT;
      goto out;
    }

    break;
  default:
    ret = -EINVAL;
    goto out;
  }

 out:
  mutex_unlock(&mutex);
  return ret;
}

static struct file_operations vcamera_char_fops = {
  .owner = THIS_MODULE,
  //  .mmap = vcamera_char_mmap,
  .write = vcamera_char_write,
  //  .read = vcamera_char_read,
  .unlocked_ioctl = vcamera_char_ioctl,
  .open = vcamera_char_open,
  .llseek = vcamera_char_llseek,
  .release = vcamera_char_release,
};

static struct miscdevice vcamera_char_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = MODULE_NAME,
  .fops = &vcamera_char_fops,
  .mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
};

static int vcamera_format_supported(struct v4l2_format *fmt) {
  int x;

  if (fmt->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
    return -EINVAL;
  }

  if (fmt->fmt.pix.field == V4L2_FIELD_ANY) {
    fmt->fmt.pix.field = V4L2_FIELD_INTERLACED;
  }

  if (fmt->fmt.pix.field != V4L2_FIELD_INTERLACED) {
    return -EINVAL;
  }

  for (x = 0; x < ARRAY_SIZE(vcamera_fmt); x++) {
    if (fmt->fmt.pix.pixelformat == vcamera_fmt[x].fourcc) {
      return 0;
    }
  }

  return -EINVAL;
}

static int vcamera_register_chardev(void)
{
  int ret;

  if (vcamera_data.reg == 1) {
    return 0;
  }

  ret = misc_register(&vcamera_char_dev);
  if (ret < 0) {
    return ret;
  }

  vcamera_data.reg = 1;

  return ret;
}

static void vcamera_deregister_chardev(void)
{
  if (vcamera_data.reg == 1) {
    misc_deregister(&vcamera_char_dev);
    vcamera_data.reg = 0;
  }
}

static int vcamera_v4l_mmap(struct file *file, struct vm_area_struct *vma)
{
  return videobuf_mmap_mapper(&vcamera_data.queue, vma);
}

static unsigned int
vcamera_v4l_poll(struct file *file, struct poll_table_struct *wait)
{
  return videobuf_poll_stream(file, &vcamera_data.queue, wait);
}

static ssize_t
vcamera_v4l_read(struct file *file, char __user *data, size_t count, loff_t *ppos)
{
  int ret = vcamera_register_chardev();

  if (ret < 0) {
    return ret;
  }

  return videobuf_read_stream(&vcamera_data.queue, data, count, ppos, 0,
			      file->f_flags & O_NONBLOCK);
}

static int vcamera_v4l_open(struct file *file) {
  if (test_and_set_bit(1, &vcamera_data.used)) {
    return -EBUSY;
  }

  return 0;
}

static int vcamera_v4l_release(struct file *file) {
  clear_bit(1, &vcamera_data.used);
  // TODO: chardev
  return 0;
}

static struct v4l2_file_operations vcamera_v4l_fops = {
  .owner          = THIS_MODULE,
  .open           = vcamera_v4l_open,
  .release        = vcamera_v4l_release,
  .read           = vcamera_v4l_read,
  .poll           = vcamera_v4l_poll,
  .ioctl          = video_ioctl2,
  .mmap           = vcamera_v4l_mmap,
};

static int vidioc_querycap(struct file *file, void *fh, struct v4l2_capability *cap)
{
  strcpy(cap->driver, MODULE_NAME);
  strcpy(cap->card, "Virtual V4L2 camera");

  cap->version = 1;
  cap->capabilities = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING | V4L2_CAP_READWRITE;

  return 0;
}

static int vidioc_s_fmt_vid_cap(struct file *filp, void *priv, struct v4l2_format *fmt)
{
  int ret = vcamera_format_supported(fmt);

  if (ret < 0) {
    return -ret;
  }

  // TODO: check we are not streaming
  // TODO: reasonable width and height v4l_bound_align_image()

  fmt->fmt.pix.bytesperline = fmt->fmt.pix.width * 2;
  fmt->fmt.pix.sizeimage = fmt->fmt.pix.width * fmt->fmt.pix.height * 2;

  vcamera_data.width = fmt->fmt.pix.width;
  vcamera_data.height = fmt->fmt.pix.height;
  vcamera_data.fmt = fmt->fmt.pix.pixelformat;
  vcamera_data.size = fmt->fmt.pix.sizeimage;

  return 0;
}

static int vidioc_reqbufs(struct file *file, void *priv, struct v4l2_requestbuffers *p) {
  // TODO: we get called with a locked mutex and the function we call
  // will also lock it. How come we don't deadlock ?!
  return videobuf_reqbufs(&vcamera_data.queue, p);
}

static int vidioc_querybuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
  return videobuf_querybuf(&vcamera_data.queue, p);
}

static int vidioc_qbuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
  return videobuf_qbuf(&vcamera_data.queue, p);
}

static int vidioc_dqbuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
  return videobuf_dqbuf(&vcamera_data.queue, p,
			file->f_flags & O_NONBLOCK);
}

static int vidioc_streamon(struct file *file, void *priv, enum v4l2_buf_type i)
{
  int ret;

  if (i != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
    return -EINVAL;
  }

  ret = videobuf_streamon(&vcamera_data.queue);

  if (ret < 0) {
    return ret;
  }

  ret = vcamera_register_chardev();

  if (ret < 0) {
    videobuf_streamoff(&vcamera_data.queue);
    return ret;
  }

  return ret;
}

static int vidioc_streamoff(struct file *file, void *priv, enum v4l2_buf_type i)
{
  if (i != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
    return -EINVAL;
  }

  return videobuf_streamoff(&vcamera_data.queue);
}

static const struct v4l2_ioctl_ops vcamera_v4l_ioctl_ops = {
  .vidioc_querycap      = vidioc_querycap,
  .vidioc_s_fmt_vid_cap     = vidioc_s_fmt_vid_cap,
  .vidioc_reqbufs       = vidioc_reqbufs,
  .vidioc_g_fmt_vid_cap     = vidioc_g_fmt_vid_cap,
  .vidioc_querybuf      = vidioc_querybuf,
  .vidioc_qbuf          = vidioc_qbuf,
  .vidioc_dqbuf         = vidioc_dqbuf,
  .vidioc_streamon      = vidioc_streamon,
  .vidioc_streamoff     = vidioc_streamoff,
  /*
  .vidioc_enum_fmt_vid_cap  = vidioc_enum_fmt_vid_cap,
  .vidioc_try_fmt_vid_cap   = vidioc_try_fmt_vid_cap,


  .vidioc_s_std         = vidioc_s_std,
  .vidioc_enum_input    = vidioc_enum_input,
  .vidioc_g_input       = vidioc_g_input,
  .vidioc_s_input       = vidioc_s_input,
  .vidioc_queryctrl     = vidioc_queryctrl,
  .vidioc_g_ctrl        = vidioc_g_ctrl,
  .vidioc_s_ctrl        = vidioc_s_ctrl,
  */
};

static struct v4l2_device vcamera_v4l2_device = {
  .name = MODULE_NAME,
};

static struct video_device vcamera_video_device = {
  .name = MODULE_NAME,
  .release = video_device_release_empty,
  .fops = &vcamera_v4l_fops,
  .ioctl_ops = &vcamera_v4l_ioctl_ops,
  .lock = &mutex,
  .v4l2_dev = &vcamera_v4l2_device,
  //  .debug = V4L2_DEBUG_IOCTL |  V4L2_DEBUG_IOCTL_ARG,
};

static int buffer_setup(struct videobuf_queue *q,
			unsigned int *count, unsigned int *size)
{
  // TODO: make sure we are not allocating a huge amount of memory

  *size = vcamera_data.size;

  *count = 4;

  vcamera_data.n_buffers = *size;

  return 0;
}

static void buffer_release(struct videobuf_queue *q,
			   struct videobuf_buffer *vb)
{
  videobuf_vmalloc_free(vb);
  vb->state = VIDEOBUF_NEEDS_INIT;
}

static int buffer_prepare(struct videobuf_queue *q,
			  struct videobuf_buffer *vb,
			  enum v4l2_field field)
{
  vb->width  = vcamera_data.width;
  vb->height = vcamera_data.height;
  vb->field  = field;
  vb->size = vcamera_data.width * vcamera_data.height * 2;

  pr_info("Size: %li", vb->size);

  if (vb->state == VIDEOBUF_NEEDS_INIT) {
    int ret = videobuf_iolock(q, vb, NULL);
    if (ret < 0) {
      buffer_release(q, vb);
      return ret;
    }
  }

  vb->state = VIDEOBUF_PREPARED;

  return 0;
}

static void buffer_queue(struct videobuf_queue *q,
			 struct videobuf_buffer *vb)
{
  vb->state = VIDEOBUF_QUEUED;

  list_add_tail(&vb->queue, &vcamera_data.active);

  // TODO:
}

static struct videobuf_queue_ops vcamera_videobuf_queue_ops = {
  .buf_setup      = buffer_setup,
  .buf_prepare    = buffer_prepare,
  .buf_queue      = buffer_queue,
  .buf_release    = buffer_release,
};

static int __init vcamera_init(void)
{
  int ret = 0;

  spin_lock_init(&vcamera_data.lock);

  videobuf_queue_vmalloc_init(&vcamera_data.queue, &vcamera_videobuf_queue_ops,
			      NULL, &vcamera_data.lock, V4L2_BUF_TYPE_VIDEO_CAPTURE,
			      V4L2_FIELD_INTERLACED, sizeof(struct videobuf_buffer),
			      NULL, &mutex);

  ret = v4l2_device_register(NULL, &vcamera_v4l2_device);
  if (ret < 0) {
    goto out;
  }

  ret = video_register_device(&vcamera_video_device, VFL_TYPE_GRABBER, -1);
  if (ret < 0) {
    goto unreg;
  }

  pr_info("Registered vcamera");

  return ret;

 unreg:
  v4l2_device_unregister(&vcamera_v4l2_device);
 out:
  return ret;
}

static void __exit vcamera_exit(void)
{
  vcamera_deregister_chardev();

  video_unregister_device(&vcamera_video_device);
  v4l2_device_unregister(&vcamera_v4l2_device);
}

module_init(vcamera_init);
module_exit(vcamera_exit);

MODULE_AUTHOR("Mohammed Sameer <msameer@foolab.org>");
MODULE_DESCRIPTION("Virtual V4L2 camera");
MODULE_LICENSE("GPL");
