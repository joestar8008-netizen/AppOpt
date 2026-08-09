/* SPDX-License-Identifier: GPL-2.0 */
/* 通用 StatsMap 后端：只在内核 map 中累计目标 Surface 帧数。
 * 不依赖 RingBuf 或 PerfEventArray，供 Android 旧内核优先使用。 */
#define APPOPT_STATS_ONLY_BPF 1
#define APPOPT_FRAME_STATS_MAX_ENTRIES 4096
#include "queuebuffer_probe_perf.bpf.c"
