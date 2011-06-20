#ifndef FMT_H
#define FMT_H

// Idea stolen from vivi ;-)
struct fmt {
  u32 fourcc;
  int depth;
};

static struct fmt vcamera_fmt[] = {
  { V4L2_PIX_FMT_YUYV, 16 },
  { V4L2_PIX_FMT_UYVY, 16 },
};

#endif /* FMT_H */
