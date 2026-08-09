use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    error::Error,
    ffi::{CStr, CString},
    fs,
    io::Read,
    num::NonZeroU32,
    ops::ControlFlow,
    os::raw::{c_char, c_double, c_int},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    ptr,
    sync::Mutex,
};

use aya::{
    Ebpf, Pod,
    maps::{
        Array as AyaArray, HashMap as AyaHashMap, MapData, PerfEventArray, RingBuf,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::{
        UProbe,
        uprobe::{UProbeLinkId, UProbeScope},
    },
    util::online_cpus,
};
use object::{Object, ObjectSection, ObjectSymbol};

mod adaptive_boost;
mod adaptive_governor;
mod fps_stream;
pub use adaptive_boost::{
    AppOptFrameMetrics, AppOptJankCtx, appopt_jank_create, appopt_jank_last_event,
    appopt_jank_recover, appopt_jank_stop, appopt_jank_update,
};
use fps_stream::{FpsStream, FrameStreamKey, MAX_STREAMS, STREAM_STALE_NS};

// Rust daemon 通过 C ABI 调用这个 bridge。
// 这里负责加载 aya eBPF 对象、附加 libgui uprobe、读取 RingBuf/StatsMap/PerfEvent 帧数据，
// 并把当前 FPS、后端名称、命中的符号和错误信息暴露给 daemon 日志。
static LAST_START_ERROR: Mutex<Option<CString>> = Mutex::new(None);

// Android 不同版本和厂商 ROM 的 libgui queueBuffer 符号不完全一致。
// 每次只挂一个候选，必须实际产生稳定 FPS 才确认；无帧时再切换下一个，避免同时挂载造成重复计帧。
const LIBGUI_FRAME_SYMBOLS: &[&str] = &[
    "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi",
    "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE",
    "_ZN7android7Surface16hook_queueBufferEP13ANativeWindowP19ANativeWindowBufferi",
    "_ZN7android7Surface19queueBufferInternalEP13ANativeWindowP19ANativeWindowBufferi",
    "_ZN7android7Surface27hook_queueBuffer_DEPRECATEDEP13ANativeWindowP19ANativeWindowBuffer",
    // Android 17 的 queueBuffer 改用 GraphicBuffer/Fence 和新的输入结构体。
    // 放在旧候选之后作为兼容兜底，避免改变 Android 12-16 的探测顺序。
    "_ZN7android7Surface11queueBufferERKNS_2spINS_13GraphicBufferEEERKNS1_INS_5FenceEEEPNS_24SurfaceQueueBufferOutputE",
    "_ZN7android7Surface11queueBufferERKNS_2spINS_13GraphicBufferEEERKNS_23SurfaceQueueBufferInputEPNS_24SurfaceQueueBufferOutputE",
];
const LIBGUI_FRAME_SYMBOL_NAMES: &[&str] = &[
    "Surface::queueBuffer",
    "Surface::queueBuffer(Output)",
    "Surface::hook_queueBuffer",
    "Surface::queueBufferInternal",
    "Surface::hook_queueBuffer_DEPRECATED",
    "Surface::queueBuffer(GraphicBuffer,Fence)",
    "Surface::queueBuffer(GraphicBuffer,QueueInput)",
];
const LIBGUI_FRAME_SYMBOL_NAME_CSTRS: &[&[u8]] = &[
    b"Surface::queueBuffer\0",
    b"Surface::queueBuffer(Output)\0",
    b"Surface::hook_queueBuffer\0",
    b"Surface::queueBufferInternal\0",
    b"Surface::hook_queueBuffer_DEPRECATED\0",
    b"Surface::queueBuffer(GraphicBuffer,Fence)\0",
    b"Surface::queueBuffer(GraphicBuffer,QueueInput)\0",
];
const UNKNOWN_FRAME_SYMBOL_CSTR: &[u8] =
    b"Surface::queueBuffer(\xE6\x9C\xAA\xE7\x9F\xA5\xE7\xAC\xA6\xE5\x8F\xB7)\0";
const SYMBOL_PROBE_NS: u64 = 3_000_000_000;
const FRAME_STATS_RETENTION_NS: u64 = 10_000_000_000;
const FRAME_STATS_POLL_INTERVAL_NS: u64 = 250_000_000;
const FRAME_STATS_PRUNE_INTERVAL_NS: u64 = 1_000_000_000;
const MAX_RING_EVENTS_PER_POLL: usize = 2048;
const MAX_PERF_BUFFERS_PER_POLL: usize = 8;
const MAX_PERF_EVENTS_PER_POLL: usize = 4096;
const PERF_LOST_LOG_INTERVAL_NS: u64 = 30_000_000_000;
const RINGBUF_DROP_LOG_INTERVAL_NS: u64 = 30_000_000_000;
const FRAME_STATS_DROP_LOG_INTERVAL_NS: u64 = 30_000_000_000;
const MAX_ERROR_DETAILS: usize = 8;
const RINGBUF_MIN_KERNEL: (u32, u32) = (5, 8);

#[repr(C)]
#[derive(Clone, Copy)]
struct FrameEvent {
    // 必须和 bpf/queuebuffer_probe*.bpf.c 中写入 events map 的结构体布局一致。
    timestamp_ns: u64,
    pid: u32,
    tid: u32,
    surface_ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
struct FrameStatsKey {
    pid: u32,
    tid: u32,
    surface_ptr: u64,
}

unsafe impl Pod for FrameStatsKey {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FrameStatsValue {
    last_ts: u64,
    total_frames: u64,
}

unsafe impl Pod for FrameStatsValue {}

#[derive(Clone, Copy, Default)]
struct FrameStatsSnapshot {
    last_ts: u64,
    total_frames: u64,
}

#[derive(Clone, Copy)]
struct PidSymbolProbe {
    candidate_index: usize,
    candidate_started_ns: u64,
    round_started_ns: u64,
    confirmed: bool,
    confirmed_once: bool,
    exhausted: bool,
    attachable_mask: u32,
    no_frame_mask: u32,
    stalled_mask: u32,
    unavailable_mask: u32,
}

enum EventBackend {
    // 优先使用 RingBuf；旧内核使用只读计数 map，PerfEvent 保留为最后一条 eBPF 兼容链。
    RingBuf(RingBuf<MapData>),
    StatsMap,
    PerfEvent(Vec<PerfEventArrayBuffer<MapData>>),
}

#[derive(Clone, Copy)]
enum BackendKind {
    RingBuf,
    StatsMap,
    PerfEvent,
}

impl BackendKind {
    fn label(self) -> &'static str {
        match self {
            Self::RingBuf => "RingBuf",
            Self::StatsMap => "StatsMap",
            Self::PerfEvent => "PerfEvent",
        }
    }
}

#[repr(C)]
pub struct AppOptEbpfCtx {
    // bpf 必须和 backend/program 一起持有，ctx 生命周期结束前不能释放。
    bpf: Ebpf,
    backend: EventBackend,
    target_tgids: AyaHashMap<MapData, u32, u32>,
    frame_stats: Option<AyaHashMap<MapData, FrameStatsKey, FrameStatsValue>>,
    use_frame_stats: bool,
    // StatsMap 溢出时，PerfEvent 后端可以关闭省流开关并回到逐帧事件。
    perf_stats_only: Option<AyaArray<MapData, u32>>,
    frame_stats_drops: Option<AyaArray<MapData, u32>>,
    frame_stats_drops_seen: u32,
    frame_stats_drops_pending: u64,
    frame_stats_drops_last_log_ns: u64,
    ringbuf_drops: Option<AyaArray<MapData, u32>>,
    ringbuf_drops_seen: u32,
    ringbuf_drops_pending: u64,
    ringbuf_drops_last_log_ns: u64,
    // 每个目标 PID 单独挂载 uprobe，target_tgids 再在内核侧做一次身份过滤。
    target_pids: HashSet<u32>,
    pid: i32,
    streams: HashMap<FrameStreamKey, FpsStream>,
    selected_stream: Option<FrameStreamKey>,
    pending_stream: Option<FrameStreamKey>,
    pending_stream_since_ns: u64,
    stat_snapshots: HashMap<FrameStatsKey, FrameStatsSnapshot>,
    frame_stats_updates: Vec<(FrameStatsKey, FrameStatsValue)>,
    frame_stats_last_poll_ns: u64,
    frame_stats_last_prune_ns: u64,
    pid_links: HashMap<u32, HashMap<u32, Vec<UProbeLinkId>>>,
    pid_starttimes: HashMap<u32, u64>,
    pid_task_starttimes: HashMap<u32, HashMap<u32, u64>>,
    pid_libgui_paths: HashMap<u32, PathBuf>,
    libgui_symbol_offsets: HashMap<PathBuf, Vec<Option<u64>>>,
    pid_symbols: HashMap<u32, CString>,
    pid_symbol_offsets: HashMap<u32, u64>,
    pid_symbol_probes: HashMap<u32, PidSymbolProbe>,
    detailed_logging: bool,
    frame_mode_reported: bool,
    perf_lost_pending: u64,
    perf_lost_last_log_ns: u64,
    perf_buffer_cursor: usize,
    cur_fps: f64,
    symbol: CString,
    backend_label: CString,
    backend_selection_note: CString,
    startup_note: CString,
    last_error: CString,
    target_pkg: Option<String>,
}

fn cstring_lossy(s: impl AsRef<str>) -> CString {
    let cleaned = s.as_ref().replace('\0', " ");
    CString::new(cleaned).unwrap_or_else(|_| CString::new("unknown").unwrap())
}

fn set_last_start_error(err: impl AsRef<str>) {
    if let Ok(mut last) = LAST_START_ERROR.lock() {
        *last = Some(cstring_lossy(err));
    }
}

fn candidate_bit(index: usize) -> u32 {
    1u32.checked_shl(index as u32).unwrap_or(0)
}

fn candidate_range_mask(start: usize, end: usize) -> u32 {
    (start.min(LIBGUI_FRAME_SYMBOLS.len())..end.min(LIBGUI_FRAME_SYMBOLS.len()))
        .fold(0, |mask, index| mask | candidate_bit(index))
}

fn readable_symbol_name(index: usize) -> &'static str {
    LIBGUI_FRAME_SYMBOL_NAMES
        .get(index)
        .copied()
        .unwrap_or("Surface::queueBuffer(未知候选)")
}

fn readable_symbol_from_raw(raw: &str) -> &'static str {
    LIBGUI_FRAME_SYMBOLS
        .iter()
        .position(|candidate| *candidate == raw)
        .map(readable_symbol_name)
        .unwrap_or("Surface::queueBuffer(未知符号)")
}

fn compact_symbol_name(index: usize) -> &'static str {
    readable_symbol_name(index)
        .strip_prefix("Surface::")
        .unwrap_or_else(|| readable_symbol_name(index))
}

fn readable_symbol_cstr_from_raw(raw: &str) -> *const c_char {
    LIBGUI_FRAME_SYMBOLS
        .iter()
        .position(|candidate| *candidate == raw)
        .and_then(|index| LIBGUI_FRAME_SYMBOL_NAME_CSTRS.get(index))
        .map_or(
            UNKNOWN_FRAME_SYMBOL_CSTR.as_ptr() as *const c_char,
            |value| value.as_ptr() as *const c_char,
        )
}

fn probe_candidate_results(probe: PidSymbolProbe) -> String {
    let mut results = Vec::new();
    for index in 0..LIBGUI_FRAME_SYMBOLS.len() {
        let bit = candidate_bit(index);
        if probe.no_frame_mask & bit != 0 {
            results.push(format!("{}=0", compact_symbol_name(index)));
        } else if probe.stalled_mask & bit != 0 {
            results.push(format!("{}=停帧", compact_symbol_name(index)));
        }
    }
    if results.is_empty() {
        "没有形成有效帧率的可挂载候选".to_string()
    } else {
        results.join(" | ")
    }
}

fn pid_role_label(pid: u32, target_pkg: Option<&str>) -> String {
    let Some(pkg) = target_pkg.filter(|pkg| !pkg.is_empty()) else {
        return "目标进程".to_string();
    };
    let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return "同包进程".to_string();
    };
    let name = raw.split(|byte| *byte == 0).next().unwrap_or_default();
    let Ok(name) = std::str::from_utf8(name) else {
        return "同包进程".to_string();
    };
    let name = name.rsplit('/').next().unwrap_or(name);
    if name == pkg {
        "主进程".to_string()
    } else if let Some(suffix) = name
        .strip_prefix(pkg)
        .and_then(|rest| rest.strip_prefix(':'))
    {
        if suffix.is_empty() {
            "子进程".to_string()
        } else {
            format!("子进程:{suffix}")
        }
    } else {
        "同包进程".to_string()
    }
}

fn single_line_error(error: &str) -> String {
    error.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn compact_error_details(errors: &[String]) -> String {
    let mut message = errors
        .iter()
        .take(MAX_ERROR_DETAILS)
        .map(|error| single_line_error(error))
        .collect::<Vec<_>>()
        .join("; ");
    let suppressed = errors.len().saturating_sub(MAX_ERROR_DETAILS);
    if suppressed > 0 {
        if !message.is_empty() {
            message.push_str("; ");
        }
        message.push_str(&format!("另有 {suppressed} 条同类错误已省略"));
    }
    message
}

fn backend_selection_report(
    ring_status: &str,
    ring_error: Option<&str>,
    stats_status: &str,
    stats_error: Option<&str>,
    perf_status: &str,
) -> String {
    let status = |name: &str, value: &str, error: Option<&str>| match error {
        Some(error) => format!("{name}={value}（{}）", single_line_error(error)),
        None => format!("{name}={value}"),
    };
    format!(
        "{} | {} | {} | SurfaceFlinger=待命",
        status("RingBuf", ring_status, ring_error),
        status("StatsMap", stats_status, stats_error),
        status("PerfEvent", perf_status, None),
    )
}

fn error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        let detail = error.to_string();
        if !detail.is_empty() && !message.ends_with(&detail) {
            message.push_str(": ");
            message.push_str(&detail);
        }
        source = error.source();
    }
    message
}

fn ptr_as_mut<'a>(ctx: *mut AppOptEbpfCtx) -> Option<&'a mut AppOptEbpfCtx> {
    if ctx.is_null() {
        None
    } else {
        Some(unsafe { &mut *ctx })
    }
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn parse_kernel_release_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts
        .next()?
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()?;
    Some((major, minor))
}

fn ringbuf_kernel_note() -> Option<String> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let version = parse_kernel_release_version(release.as_deref()?)?;
    if version < RINGBUF_MIN_KERNEL {
        return Some(format!(
            "内核 {} 不支持 RingBuf（需要 >= {}.{}），已跳过 RingBuf 探测",
            release.as_deref().unwrap_or("unknown"),
            RINGBUF_MIN_KERNEL.0,
            RINGBUF_MIN_KERNEL.1
        ));
    }
    None
}

unsafe fn read_frame_event(buf: &[u8]) -> Option<FrameEvent> {
    // eBPF map 里是 packed bytes，不能假设对齐，所以用 read_unaligned。
    if buf.len() < std::mem::size_of::<FrameEvent>() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned(buf.as_ptr().cast::<FrameEvent>()) })
}

fn read_split_frame_event(head: &[u8], tail: &[u8]) -> Option<FrameEvent> {
    // PerfEvent 可能把一条 sample 分成 head/tail 两段，需要拼回完整 FrameEvent。
    let size = std::mem::size_of::<FrameEvent>();
    if head.len().saturating_add(tail.len()) < size {
        return None;
    }
    if head.len() >= size {
        return unsafe { read_frame_event(head) };
    }

    let mut buf = [0u8; std::mem::size_of::<FrameEvent>()];
    let head_len = head.len();
    buf[..head_len].copy_from_slice(head);
    buf[head_len..].copy_from_slice(&tail[..(size - head_len)]);
    unsafe { read_frame_event(&buf) }
}

fn pid_matches_pkg(pid: u32, pkg: &str) -> bool {
    // 目标集合更新时做一次身份确认；逐帧路径只依赖内核 target_tgids map。
    if pkg.is_empty() {
        return true;
    }

    let path = format!("/proc/{pid}/cmdline");
    let Ok(cmdline) = fs::read(path) else {
        return false;
    };
    let name = cmdline.split(|b| *b == 0).next().unwrap_or_default();
    let name = match std::str::from_utf8(name) {
        Ok(s) => s.rsplit('/').next().unwrap_or(s),
        Err(_) => return false,
    };

    name == pkg
        || name
            .strip_prefix(pkg)
            .is_some_and(|suffix| suffix.starts_with(':'))
}

fn stream_key(event: FrameEvent) -> FrameStreamKey {
    stream_key_from_parts(event.pid, event.tid, event.surface_ptr)
}

fn stream_key_from_parts(pid: u32, tid: u32, surface_ptr: u64) -> FrameStreamKey {
    FrameStreamKey {
        pid,
        tid: if surface_ptr == 0 { tid } else { 0 },
        surface_ptr,
    }
}

fn refresh_current_fps(ctx: &mut AppOptEbpfCtx, now_ns: u64) {
    const STREAM_SWITCH_SCORE_MARGIN: f64 = 120.0;
    const STREAM_SWITCH_HOLD_NS: u64 = 600_000_000;
    ctx.streams.retain(|key, stream| {
        ctx.target_pids.contains(&key.pid)
            && now_ns.saturating_sub(stream.last_seen_ns) <= STREAM_STALE_NS
    });

    if ctx.streams.len() > MAX_STREAMS {
        let mut streams = ctx
            .streams
            .iter()
            .map(|(key, stream)| (*key, stream.last_seen_ns))
            .collect::<Vec<_>>();
        streams.sort_by_key(|(_, last_seen_ns)| *last_seen_ns);
        for (key, _) in streams.into_iter().take(ctx.streams.len() - MAX_STREAMS) {
            ctx.streams.remove(&key);
        }
    }

    let best = ctx
        .streams
        .iter()
        .filter_map(|(key, stream)| {
            let score = stream.selection_score(now_ns);
            score.is_finite().then_some((*key, score))
        })
        .max_by(|left, right| {
            left.1
                .partial_cmp(&right.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

    let current = ctx.selected_stream.and_then(|key| {
        ctx.streams
            .get(&key)
            .map(|stream| (key, stream.selection_score(now_ns)))
            .filter(|(_, score)| score.is_finite())
    });
    ctx.selected_stream = match (current, best) {
        (_, None) => None,
        (None, Some((key, _))) => {
            ctx.pending_stream = None;
            ctx.pending_stream_since_ns = 0;
            Some(key)
        }
        (Some((current_key, _)), Some((best_key, _))) if current_key == best_key => {
            ctx.pending_stream = None;
            ctx.pending_stream_since_ns = 0;
            Some(current_key)
        }
        (Some((current_key, current_score)), Some((best_key, best_score))) => {
            if best_score < current_score + STREAM_SWITCH_SCORE_MARGIN {
                ctx.pending_stream = None;
                ctx.pending_stream_since_ns = 0;
                Some(current_key)
            } else if ctx.pending_stream == Some(best_key) {
                if now_ns.saturating_sub(ctx.pending_stream_since_ns) >= STREAM_SWITCH_HOLD_NS {
                    ctx.pending_stream = None;
                    ctx.pending_stream_since_ns = 0;
                    Some(best_key)
                } else {
                    Some(current_key)
                }
            } else {
                ctx.pending_stream = Some(best_key);
                ctx.pending_stream_since_ns = now_ns;
                Some(current_key)
            }
        }
    };
    ctx.cur_fps = ctx
        .selected_stream
        .and_then(|key| ctx.streams.get(&key))
        .map_or(0.0, |stream| stream.cur_fps);
    ctx.pid = ctx.selected_stream.map_or_else(
        || {
            if ctx.pid > 0 && ctx.target_pids.contains(&(ctx.pid as u32)) {
                ctx.pid
            } else {
                ctx.target_pids
                    .iter()
                    .copied()
                    .next()
                    .map_or(-1, |pid| pid as i32)
            }
        },
        |key| key.pid as i32,
    );
    if let Some(symbol) = ctx
        .selected_stream
        .and_then(|key| ctx.pid_symbols.get(&key.pid))
        .cloned()
    {
        ctx.symbol = symbol;
    }
}

fn on_frame(ctx: &mut AppOptEbpfCtx, event: FrameEvent) -> bool {
    // 内核 map 已经过滤一次；用户态再核对集合，防止目标切换时消费排队的旧事件。
    if !ctx.target_pids.contains(&event.pid) {
        return false;
    }

    let key = stream_key(event);
    ctx.streams
        .entry(key)
        .or_insert_with(|| FpsStream::new(event.timestamp_ns))
        .on_frame(event.timestamp_ns);
    true
}

fn prune_frame_stats(ctx: &mut AppOptEbpfCtx) {
    if ctx.frame_stats.is_none() {
        return;
    }
    let now_ns = monotonic_ns();
    if now_ns > 0
        && ctx.frame_stats_last_prune_ns > 0
        && now_ns.saturating_sub(ctx.frame_stats_last_prune_ns) < FRAME_STATS_PRUNE_INTERVAL_NS
    {
        return;
    }
    if now_ns > 0 {
        ctx.frame_stats_last_prune_ns = now_ns;
    }

    let stale_keys = {
        let Some(stats) = ctx.frame_stats.as_ref() else {
            return;
        };
        stats
            .iter()
            .filter_map(Result::ok)
            .filter(|(key, value)| {
                !ctx.target_pids.contains(&key.pid)
                    || value.total_frames == 0
                    || value.last_ts == 0
                    || (now_ns > 0
                        && now_ns.saturating_sub(value.last_ts) > FRAME_STATS_RETENTION_NS)
            })
            .map(|(key, _)| key)
            .collect::<Vec<_>>()
    };
    if let Some(stats) = ctx.frame_stats.as_mut() {
        for key in &stale_keys {
            let _ = stats.remove(key);
        }
    }
    for key in stale_keys {
        ctx.stat_snapshots.remove(&key);
        let stream = stream_key_from_parts(key.pid, key.tid, key.surface_ptr);
        ctx.streams.remove(&stream);
        if ctx.selected_stream == Some(stream) {
            ctx.selected_stream = None;
            ctx.cur_fps = 0.0;
        }
    }
}

fn poll_frame_stats(ctx: &mut AppOptEbpfCtx) -> Result<i32, String> {
    let now_ns = monotonic_ns();
    if now_ns > 0
        && ctx.frame_stats_last_poll_ns > 0
        && now_ns.saturating_sub(ctx.frame_stats_last_poll_ns) < FRAME_STATS_POLL_INTERVAL_NS
    {
        return Ok(0);
    }
    if now_ns > 0 {
        ctx.frame_stats_last_poll_ns = now_ns;
    }
    prune_frame_stats(ctx);
    let Some(stats) = ctx.frame_stats.as_ref() else {
        return Ok(0);
    };
    let mut updates = std::mem::take(&mut ctx.frame_stats_updates);
    updates.clear();
    for item in stats.iter() {
        let (key, value) = item.map_err(|e| e.to_string())?;
        if value.total_frames == 0 || value.last_ts == 0 {
            continue;
        }
        if !ctx.target_pids.contains(&key.pid) {
            continue;
        }
        updates.push((key, value));
    }
    let mut accepted = 0i32;
    let mut latest_ts = 0u64;

    for (key, value) in updates.iter().copied() {
        let prev = ctx.stat_snapshots.get(&key).copied().unwrap_or_default();
        ctx.stat_snapshots.insert(
            key,
            FrameStatsSnapshot {
                last_ts: value.last_ts,
                total_frames: value.total_frames,
            },
        );

        let stream_key = stream_key_from_parts(key.pid, key.tid, key.surface_ptr);
        if prev.total_frames == 0 || prev.last_ts == 0 {
            ctx.streams
                .entry(stream_key)
                .or_insert_with(|| FpsStream::new(value.last_ts));
            accepted = accepted.saturating_add(1);
            latest_ts = latest_ts.max(value.last_ts);
            continue;
        }

        if value.total_frames <= prev.total_frames || value.last_ts <= prev.last_ts {
            continue;
        }

        let frames = value.total_frames - prev.total_frames;
        ctx.streams
            .entry(stream_key)
            .or_insert_with(|| FpsStream::new(prev.last_ts))
            .on_frame_batch(prev.last_ts, value.last_ts, frames);
        accepted = accepted.saturating_add(frames.min(i32::MAX as u64) as i32);
        latest_ts = latest_ts.max(value.last_ts);
    }

    if accepted > 0 {
        if latest_ts > 0 {
            refresh_current_fps(ctx, latest_ts);
        }
    }

    updates.clear();
    ctx.frame_stats_updates = updates;
    Ok(accepted)
}

fn poll_ringbuf_drop_count(ctx: &mut AppOptEbpfCtx) -> Result<(), String> {
    let Some(drops) = ctx.ringbuf_drops.as_ref() else {
        return Ok(());
    };
    let total = drops.get(&0, 0).map_err(|error| error.to_string())?;
    if total > ctx.ringbuf_drops_seen {
        ctx.ringbuf_drops_pending = ctx
            .ringbuf_drops_pending
            .saturating_add(u64::from(total - ctx.ringbuf_drops_seen));
        ctx.ringbuf_drops_seen = total;
    }
    let now_ns = monotonic_ns();
    if ctx.detailed_logging
        && ctx.ringbuf_drops_pending > 0
        && (ctx.ringbuf_drops_last_log_ns == 0
            || now_ns == 0
            || now_ns.saturating_sub(ctx.ringbuf_drops_last_log_ns) >= RINGBUF_DROP_LOG_INTERVAL_NS)
    {
        eprintln!(
            "[FPS] RingBuf 缓冲区已满，丢弃帧事件={}；当前 FPS 可能短时偏低",
            ctx.ringbuf_drops_pending
        );
        ctx.ringbuf_drops_pending = 0;
        ctx.ringbuf_drops_last_log_ns = now_ns;
    }
    Ok(())
}

fn poll_frame_stats_drop_count(ctx: &mut AppOptEbpfCtx) -> Result<(), String> {
    let Some(drops) = ctx.frame_stats_drops.as_ref() else {
        return Ok(());
    };
    let total = drops.get(&0, 0).map_err(|error| error.to_string())?;
    let delta = total.wrapping_sub(ctx.frame_stats_drops_seen);
    if delta == 0 {
        return Ok(());
    }
    ctx.frame_stats_drops_seen = total;
    ctx.frame_stats_drops_pending = ctx
        .frame_stats_drops_pending
        .saturating_add(u64::from(delta));

    // PerfEvent 对象原本会在 frame_stats 可读后关闭逐帧事件。若 map 已满，
    // 立即恢复事件通道，避免继续静默丢帧；StatsMap 后端则继续依赖过期键清理。
    if matches!(ctx.backend, EventBackend::PerfEvent(_))
        && ctx.use_frame_stats
        && let Some(mode) = ctx.perf_stats_only.as_mut()
    {
        if mode.set(0, 0, 0).is_ok() {
            ctx.use_frame_stats = false;
            ctx.frame_mode_reported = false;
            if ctx.detailed_logging {
                println!(
                    "[FPS] frame_stats map 已满: 丢失={}；PerfEvent 已恢复逐帧事件",
                    ctx.frame_stats_drops_pending
                );
            }
        }
    }

    let now_ns = monotonic_ns();
    if ctx.detailed_logging
        && ctx.frame_stats_drops_pending > 0
        && (ctx.frame_stats_drops_last_log_ns == 0
            || now_ns == 0
            || now_ns.saturating_sub(ctx.frame_stats_drops_last_log_ns)
                >= FRAME_STATS_DROP_LOG_INTERVAL_NS)
    {
        eprintln!(
            "[FPS] frame_stats map 记录失败={}；已清理过期帧源，当前 FPS 可能短时偏低",
            ctx.frame_stats_drops_pending
        );
        ctx.frame_stats_drops_pending = 0;
        ctx.frame_stats_drops_last_log_ns = now_ns;
    }
    Ok(())
}

fn poll_inner(ctx: &mut AppOptEbpfCtx) -> Result<i32, String> {
    // RingBuf/PerfEvent 逐帧模式也会让内核同步维护 frame_stats；定期清理
    // 已退出 PID、失效 Surface 和长时间停帧的键，避免动态线程 churn 填满 map。
    prune_frame_stats(ctx);
    let mut events = Vec::new();
    let prefer_stats = matches!(ctx.backend, EventBackend::StatsMap)
        || (matches!(ctx.backend, EventBackend::PerfEvent(_)) && ctx.use_frame_stats);
    let prefer_stats = prefer_stats && ctx.frame_stats.is_some();
    let ringbuf_backend = matches!(&ctx.backend, EventBackend::RingBuf(_));

    if !ctx.frame_mode_reported {
        if ctx.detailed_logging {
            let source = match &ctx.backend {
                EventBackend::RingBuf(_) => "eBPF RingBuf逐帧事件",
                EventBackend::StatsMap => "eBPF frame_stats map",
                EventBackend::PerfEvent(_) if prefer_stats => {
                    "eBPF frame_stats map（PerfEvent省流）"
                }
                EventBackend::PerfEvent(_) => "eBPF PerfEvent逐帧事件",
            };
            println!(
                "[FPS] 计帧模式: 后端={} 来源={source}",
                ctx.backend_label.to_string_lossy()
            );
        }
        ctx.frame_mode_reported = true;
    }

    match &mut ctx.backend {
        EventBackend::RingBuf(ring) => {
            // RingBuf 是首选后端，事件直接从共享 ring 中取出。
            for _ in 0..MAX_RING_EVENTS_PER_POLL {
                let Some(item) = ring.next() else {
                    break;
                };
                if let Some(event) = unsafe { read_frame_event(&item) } {
                    events.push(event);
                }
            }
        }
        EventBackend::StatsMap => {}
        EventBackend::PerfEvent(perf_buffers) => {
            // PerfEvent 是 Android/内核不支持 RingBuf mmap 时的备用后端。
            // 省流模式下 BPF 已停止写 events，只读 frame_stats 即可。继续扫描
            // 每个空 per-CPU buffer 会在 FPS 线程中制造没有收益的固定轮询开销。
            if prefer_stats {
                let result = poll_frame_stats(ctx);
                if let Err(error) = poll_frame_stats_drop_count(ctx) {
                    if ctx.detailed_logging {
                        eprintln!("[FPS] frame_stats 丢失计数读取失败，已停用该诊断: {error}");
                    }
                    ctx.frame_stats_drops = None;
                }
                return result;
            }
            // 逐帧兼容模式下每个 online CPU 都有一个 buffer，需要逐个 drain。
            let mut lost_samples = 0u64;
            let mut remaining_events = MAX_PERF_EVENTS_PER_POLL;
            let buffer_count = perf_buffers.len();
            let poll_count = buffer_count.min(MAX_PERF_BUFFERS_PER_POLL);
            let start = if buffer_count == 0 {
                0
            } else {
                ctx.perf_buffer_cursor % buffer_count
            };
            for offset in 0..poll_count {
                let index = (start + offset) % buffer_count;
                let Some(perf_buf) = perf_buffers.get_mut(index) else {
                    continue;
                };
                if remaining_events == 0 {
                    break;
                }
                let _ = perf_buf.try_fold((), |(), event| {
                    if remaining_events == 0 {
                        return ControlFlow::Break(());
                    }
                    remaining_events = remaining_events.saturating_sub(1);
                    match event {
                        PerfEvent::Sample { head, tail } => {
                            if let Some(frame) = read_split_frame_event(head, tail) {
                                events.push(frame);
                            }
                        }
                        PerfEvent::Lost { count } => {
                            lost_samples = lost_samples.saturating_add(count);
                        }
                    }
                    ControlFlow::Continue(())
                });
            }
            if buffer_count > 0 {
                ctx.perf_buffer_cursor = (start + poll_count) % buffer_count;
            }
            if lost_samples > 0 {
                ctx.perf_lost_pending = ctx.perf_lost_pending.saturating_add(lost_samples);
                let now_ns = monotonic_ns();
                if ctx.perf_lost_last_log_ns == 0
                    || now_ns == 0
                    || now_ns.saturating_sub(ctx.perf_lost_last_log_ns) >= PERF_LOST_LOG_INTERVAL_NS
                {
                    eprintln!("[FPS] PerfEvent 丢弃样本: {}", ctx.perf_lost_pending);
                    ctx.perf_lost_pending = 0;
                    ctx.perf_lost_last_log_ns = now_ns;
                }
            }
        }
    }

    if ringbuf_backend {
        if let Err(error) = poll_ringbuf_drop_count(ctx) {
            if ctx.detailed_logging {
                eprintln!("[FPS] RingBuf 丢帧计数读取失败，已停用该诊断: {error}");
            }
            ctx.ringbuf_drops = None;
        }
    }

    if let Err(error) = poll_frame_stats_drop_count(ctx) {
        if ctx.detailed_logging {
            eprintln!("[FPS] frame_stats 丢失计数读取失败，已停用该诊断: {error}");
        }
        ctx.frame_stats_drops = None;
    }

    if prefer_stats {
        return poll_frame_stats(ctx);
    }

    // PerfEvent 是 per-CPU 队列，按 CPU 读取会破坏全局时间顺序；先按时间戳合并，
    // 再进入 Surface/TID 分流的滑动窗口。RingBuf 原本就是有序的，排序不会改变语义。
    events.sort_by_key(|event| event.timestamp_ns);

    let mut accepted = 0;
    let mut latest_ts = 0u64;
    for event in events {
        if on_frame(ctx, event) {
            accepted += 1;
            latest_ts = latest_ts.max(event.timestamp_ns);
        }
    }
    if latest_ts > 0 {
        // 一轮积压事件全部入窗后只重算一次活动 Surface，避免 event × stream
        // 的重复评分把高帧率场景变成用户态 CPU 热点。
        refresh_current_fps(ctx, latest_ts);
    }

    Ok(accepted)
}

fn resolve_libgui_path(pid: i32) -> Result<PathBuf, String> {
    if pid > 0 {
        if let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps")) {
            for line in maps.lines() {
                let Some(raw_path) = line.split_whitespace().nth(5) else {
                    continue;
                };
                if !raw_path.ends_with("/libgui.so") {
                    continue;
                }
                let direct = PathBuf::from(raw_path);
                if direct.is_file() {
                    return Ok(fs::canonicalize(&direct).unwrap_or(direct));
                }
                let namespaced = PathBuf::from(format!("/proc/{pid}/root{raw_path}"));
                if namespaced.is_file() {
                    return Ok(fs::canonicalize(&namespaced).unwrap_or(namespaced));
                }
            }
        }
    }

    let paths_64_first = [
        "/system/lib64/libgui.so",
        "/system_ext/lib64/libgui.so",
        "/system/lib/libgui.so",
        "/system_ext/lib/libgui.so",
    ];
    let paths_32_first = [
        "/system/lib/libgui.so",
        "/system_ext/lib/libgui.so",
        "/system/lib64/libgui.so",
        "/system_ext/lib64/libgui.so",
    ];
    let paths = if process_is_64_bit(pid).is_some_and(|is_64_bit| !is_64_bit) {
        &paths_32_first
    } else {
        &paths_64_first
    };
    paths
        .iter()
        .copied()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .map(|path| fs::canonicalize(&path).unwrap_or(path))
        .ok_or_else(|| format!("未找到目标 PID {pid} 映射的 libgui.so"))
}

fn process_is_64_bit(pid: i32) -> Option<bool> {
    if pid <= 0 {
        return None;
    }
    let mut file = fs::File::open(format!("/proc/{pid}/exe")).ok()?;
    let mut header = [0u8; 5];
    file.read_exact(&mut header).ok()?;
    if header[..4] != *b"\x7fELF" {
        return None;
    }
    match header[4] {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

fn load_uprobe_program(bpf: &mut Ebpf) -> Result<(), String> {
    let program: &mut UProbe = bpf
        .program_mut("on_queue_buffer")
        .ok_or_else(|| "missing BPF program: on_queue_buffer".to_string())?
        .try_into()
        .map_err(|e: aya::programs::ProgramError| e.to_string())?;

    program.load().map_err(|e| e.to_string())
}

fn uprobe_program(bpf: &mut Ebpf) -> Result<&mut UProbe, String> {
    bpf.program_mut("on_queue_buffer")
        .ok_or_else(|| "missing BPF program: on_queue_buffer".to_string())?
        .try_into()
        .map_err(|e: aya::programs::ProgramError| e.to_string())
}

fn attach_symbol_for_task(
    bpf: &mut Ebpf,
    tgid: u32,
    tid: u32,
    path: &Path,
    symbol: &str,
    offset: u64,
) -> Result<UProbeLinkId, String> {
    let scope = UProbeScope::OneProcess(
        NonZeroU32::new(tid).ok_or_else(|| "invalid target tid".to_string())?,
    );
    let program = uprobe_program(bpf)?;
    program.attach(offset, path, scope).map_err(|err| {
        format!(
            "pid={tgid} tid={tid} symbol={symbol} {}: {err}",
            path.display()
        )
    })
}

fn detach_task_links(bpf: &mut Ebpf, tgid: u32, tid: u32, links: Vec<UProbeLinkId>) -> Vec<String> {
    let program = match uprobe_program(bpf) {
        Ok(program) => program,
        Err(err) => {
            return vec![format!("pid={tgid} tid={tid} 获取 uprobe 程序失败: {err}")];
        }
    };
    let mut errors = Vec::new();
    for link_id in links {
        if let Err(err) = program.detach(link_id) {
            errors.push(format!("pid={tgid} tid={tid} 解除 uprobe 失败: {err}"));
        }
    }
    errors
}

fn detach_pid_links(
    bpf: &mut Ebpf,
    tgid: u32,
    task_links: HashMap<u32, Vec<UProbeLinkId>>,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (tid, links) in task_links {
        errors.extend(detach_task_links(bpf, tgid, tid, links));
    }
    errors
}

fn collect_task_ids(pid: u32) -> Result<HashSet<u32>, String> {
    let entries = fs::read_dir(format!("/proc/{pid}/task"))
        .map_err(|err| format!("读取 pid={pid} 线程列表失败: {err}"))?;
    let mut tids = HashSet::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Ok(tid) = name.parse::<u32>() {
            if tid > 0 {
                tids.insert(tid);
            }
        }
    }
    if tids.is_empty() {
        return Err(format!("pid={pid} 没有可挂载线程"));
    }
    Ok(tids)
}

fn read_proc_starttime(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let close = content.rfind(") ")?;
    // /proc/<pid>/stat: after comm, field 3 is state; starttime is field 22,
    // therefore it is item 19 in the whitespace-separated tail.
    content[close + 2..]
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
}

fn process_starttime(pid: u32) -> Option<u64> {
    read_proc_starttime(Path::new(&format!("/proc/{pid}/stat")))
}

fn task_starttime(pid: u32, tid: u32) -> Option<u64> {
    read_proc_starttime(Path::new(&format!("/proc/{pid}/task/{tid}/stat")))
}

fn task_starttime_snapshot(pid: u32, tids: impl Iterator<Item = u32>) -> HashMap<u32, u64> {
    tids.filter_map(|tid| task_starttime(pid, tid).map(|start| (tid, start)))
        .collect()
}

fn resolve_candidate_offsets(path: &Path) -> Result<Vec<Option<u64>>, String> {
    let data = fs::read(path).map_err(|err| format!("读取 {} 失败: {err}", path.display()))?;
    let object = object::read::File::parse(data.as_slice())
        .map_err(|err| format!("解析 {} 失败: {err}", path.display()))?;
    let mut offsets = vec![None; LIBGUI_FRAME_SYMBOLS.len()];

    for symbol in object.dynamic_symbols().chain(object.symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };
        let Some(index) = LIBGUI_FRAME_SYMBOLS
            .iter()
            .position(|candidate| *candidate == name)
        else {
            continue;
        };
        let Some(section_index) = symbol.section_index() else {
            continue;
        };
        let section = object
            .section_by_index(section_index)
            .map_err(|err| format!("读取 {name} 段信息失败: {err}"))?;
        let Some((section_offset, _)) = section.file_range() else {
            continue;
        };
        let Some(relative) = symbol.address().checked_sub(section.address()) else {
            continue;
        };
        offsets[index] = relative.checked_add(section_offset);
    }

    Ok(offsets)
}

fn cached_candidate_offsets(
    ctx: &mut AppOptEbpfCtx,
    path: &Path,
) -> Result<Vec<Option<u64>>, String> {
    if let Some(offsets) = ctx.libgui_symbol_offsets.get(path) {
        return Ok(offsets.clone());
    }
    let offsets = resolve_candidate_offsets(path)?;
    ctx.libgui_symbol_offsets
        .insert(path.to_path_buf(), offsets.clone());
    Ok(offsets)
}

fn attach_process_candidate(
    bpf: &mut Ebpf,
    pid: u32,
    path: &Path,
    offsets: &[Option<u64>],
    start_index: usize,
) -> Result<(usize, CString, u64, HashMap<u32, Vec<UProbeLinkId>>), String> {
    let tids = collect_task_ids(pid)?;
    let mut symbol_errors = Vec::new();
    for (candidate_index, symbol) in LIBGUI_FRAME_SYMBOLS.iter().enumerate().skip(start_index) {
        let Some(offset) = offsets.get(candidate_index).copied().flatten() else {
            continue;
        };
        let mut task_links = HashMap::new();
        let mut attach_errors = Vec::new();
        let mut suppressed_errors = 0usize;
        for tid in tids.iter().copied() {
            match attach_symbol_for_task(bpf, pid, tid, path, symbol, offset) {
                Ok(link) => {
                    task_links.insert(tid, vec![link]);
                }
                Err(err) => {
                    if attach_errors.len() < MAX_ERROR_DETAILS {
                        attach_errors.push(err);
                    } else {
                        suppressed_errors = suppressed_errors.saturating_add(1);
                    }
                }
            }
        }
        if !task_links.is_empty() {
            return Ok((candidate_index, cstring_lossy(symbol), offset, task_links));
        }
        symbol_errors.extend(attach_errors);
        if suppressed_errors > 0 {
            symbol_errors.push(format!("另有 {suppressed_errors} 个线程挂载失败"));
        }
    }
    Err(if symbol_errors.is_empty() {
        format!("pid={pid} 没有剩余可挂载的 queueBuffer 候选")
    } else {
        compact_error_details(&symbol_errors)
    })
}

struct TaskSyncResult {
    errors: Vec<String>,
}

fn sync_process_tasks(
    bpf: &mut Ebpf,
    pid: u32,
    path: &Path,
    symbol: &str,
    offset: u64,
    task_links: &mut HashMap<u32, Vec<UProbeLinkId>>,
    task_starttimes: &mut HashMap<u32, u64>,
) -> TaskSyncResult {
    let desired = match collect_task_ids(pid) {
        Ok(tids) => tids,
        Err(err) => {
            return TaskSyncResult { errors: vec![err] };
        }
    };
    let current = task_links.keys().copied().collect::<HashSet<_>>();
    let mut errors = Vec::new();
    let mut suppressed_errors = 0usize;
    for tid in current.difference(&desired).copied().collect::<Vec<_>>() {
        if let Some(links) = task_links.remove(&tid) {
            for error in detach_task_links(bpf, pid, tid, links) {
                if errors.len() < MAX_ERROR_DETAILS {
                    errors.push(error);
                } else {
                    suppressed_errors = suppressed_errors.saturating_add(1);
                }
            }
        }
        task_starttimes.remove(&tid);
    }
    // A numeric TID can be reused while the old uprobe link remains in our
    // bookkeeping.  Re-attach only when /proc proves a new starttime; a
    // transiently unreadable stat is deliberately left untouched.
    let reused = desired
        .intersection(&current)
        .copied()
        .filter(|tid| {
            task_starttimes
                .get(tid)
                .zip(task_starttime(pid, *tid))
                .is_some_and(|(old, new)| old != &new)
        })
        .collect::<Vec<_>>();
    for tid in reused {
        if let Some(links) = task_links.remove(&tid) {
            errors.extend(detach_task_links(bpf, pid, tid, links));
        }
        task_starttimes.remove(&tid);
    }
    let mut attach = desired.difference(&current).copied().collect::<Vec<_>>();
    attach.extend(
        desired
            .intersection(&current)
            .copied()
            .filter(|tid| !task_links.contains_key(tid)),
    );
    for tid in attach {
        match attach_symbol_for_task(bpf, pid, tid, path, symbol, offset) {
            Ok(link) => {
                task_links.insert(tid, vec![link]);
                if let Some(starttime) = task_starttime(pid, tid) {
                    task_starttimes.insert(tid, starttime);
                }
            }
            Err(err) => {
                if errors.len() < MAX_ERROR_DETAILS {
                    errors.push(err);
                } else {
                    suppressed_errors = suppressed_errors.saturating_add(1);
                }
            }
        }
    }
    if suppressed_errors > 0 {
        errors.push(format!("另有 {suppressed_errors} 个线程同步错误已省略"));
    }
    TaskSyncResult { errors }
}

fn clear_pid_samples(ctx: &mut AppOptEbpfCtx, pid: u32) {
    ctx.frame_stats_last_poll_ns = 0;
    ctx.frame_stats_last_prune_ns = 0;
    ctx.streams.retain(|key, _| key.pid != pid);
    ctx.stat_snapshots.retain(|key, _| key.pid != pid);
    if let Some(stats) = ctx.frame_stats.as_mut() {
        let keys = stats
            .keys()
            .filter_map(Result::ok)
            .filter(|key| key.pid == pid)
            .collect::<Vec<_>>();
        for key in keys {
            let _ = stats.remove(&key);
        }
    }
    if ctx.selected_stream.is_some_and(|key| key.pid == pid) {
        ctx.selected_stream = None;
        ctx.cur_fps = 0.0;
    }
}

fn switch_pid_symbol(ctx: &mut AppOptEbpfCtx, pid: u32, now_ns: u64) -> Result<bool, String> {
    let Some(probe) = ctx.pid_symbol_probes.get(&pid).copied() else {
        return Ok(false);
    };
    if probe.confirmed || probe.exhausted {
        return Ok(false);
    }

    let next_start_index = probe.candidate_index.saturating_add(1);
    let relocking_confirmed_source = probe.confirmed_once;
    let mut detach_errors = ctx
        .pid_links
        .remove(&pid)
        .map(|links| detach_pid_links(&mut ctx.bpf, pid, links))
        .unwrap_or_default();
    ctx.pid_task_starttimes.remove(&pid);
    clear_pid_samples(ctx, pid);

    let path = ctx
        .pid_libgui_paths
        .get(&pid)
        .cloned()
        .map_or_else(|| resolve_libgui_path(pid as i32), Ok)?;
    ctx.pid_libgui_paths.insert(pid, path.clone());
    let offsets = cached_candidate_offsets(ctx, &path)?;
    match attach_process_candidate(&mut ctx.bpf, pid, &path, &offsets, next_start_index) {
        Ok((candidate_index, symbol, offset, task_links)) => {
            let task_starttimes = task_starttime_snapshot(pid, task_links.keys().copied());
            let mut next_probe = probe;
            if probe.confirmed_once {
                next_probe.stalled_mask |= candidate_bit(probe.candidate_index);
            } else {
                next_probe.no_frame_mask |= candidate_bit(probe.candidate_index);
            }
            next_probe.candidate_index = candidate_index;
            next_probe.candidate_started_ns = now_ns;
            next_probe.confirmed = false;
            next_probe.attachable_mask |= candidate_bit(candidate_index);
            next_probe.unavailable_mask |= candidate_range_mask(next_start_index, candidate_index);
            ctx.pid_links.insert(pid, task_links);
            ctx.pid_task_starttimes.insert(pid, task_starttimes);
            ctx.pid_symbols.insert(pid, symbol.clone());
            ctx.pid_symbol_offsets.insert(pid, offset);
            ctx.pid_symbol_probes.insert(pid, next_probe);
            ctx.symbol = symbol;
            if relocking_confirmed_source {
                println!(
                    "[FPS] 符号重锁: PID={pid} 剩余候选={} 当前尝试={}",
                    LIBGUI_FRAME_SYMBOLS
                        .len()
                        .saturating_sub(candidate_index + 1),
                    readable_symbol_name(candidate_index),
                );
            }
            if !detach_errors.is_empty() {
                ctx.last_error = cstring_lossy(compact_error_details(&detach_errors));
            }
            Ok(true)
        }
        Err(err) => {
            let mut exhausted_probe = probe;
            if probe.confirmed_once {
                exhausted_probe.stalled_mask |= candidate_bit(probe.candidate_index);
            } else {
                exhausted_probe.no_frame_mask |= candidate_bit(probe.candidate_index);
            }
            exhausted_probe.unavailable_mask |=
                candidate_range_mask(next_start_index, LIBGUI_FRAME_SYMBOLS.len());
            exhausted_probe.exhausted = true;
            ctx.pid_symbol_probes.insert(pid, exhausted_probe);
            ctx.pid_symbols.remove(&pid);
            ctx.pid_symbol_offsets.remove(&pid);
            detach_errors.push(err);
            let error = compact_error_details(&detach_errors);
            ctx.last_error = cstring_lossy(&error);
            let role = pid_role_label(pid, ctx.target_pkg.as_deref());
            let active_pid = ctx
                .selected_stream
                .map(|key| key.pid)
                .filter(|active| *active != pid);
            let action = active_pid.map_or_else(
                || "处理=等待其他帧源或降级判断".to_string(),
                |active| format!("处理=忽略；当前帧源PID={active}继续工作"),
            );
            let duration = now_ns.saturating_sub(probe.round_started_ns) as f64 / 1_000_000_000.0;
            if ctx.detailed_logging {
                println!(
                    "[FPS] 进程探测完成: PID={pid} 角色={role} 结果={} 可挂载候选={}/{} 耗时={duration:.1}秒 {action}",
                    if probe.confirmed_once {
                        "重锁失败"
                    } else {
                        "无帧"
                    },
                    exhausted_probe.attachable_mask.count_ones(),
                    LIBGUI_FRAME_SYMBOLS.len(),
                );
                println!("[FPS]   {}", probe_candidate_results(exhausted_probe));
                if let Some(active_pid) = active_pid {
                    println!(
                        "[FPS] 多进程状态: 主帧源PID={active_pid}继续工作；无帧子进程PID={pid}已忽略，不影响当前FPS"
                    );
                }
            }
            Ok(false)
        }
    }
}

fn confirm_observed_symbols(ctx: &mut AppOptEbpfCtx) {
    // 必须形成通过预热、样本量和异常帧过滤的稳定 FPS 才确认候选。
    // 这样 probe_state=2 时 daemon 可以直接输出，不会在窗口尚未形成时抢先写入 0。
    let now_ns = monotonic_ns();
    let observed = ctx
        .pid_symbol_probes
        .keys()
        .copied()
        .filter_map(|pid| {
            let selected = ctx
                .selected_stream
                .filter(|key| key.pid == pid)
                .and_then(|key| ctx.streams.get(&key));
            let best = selected.or_else(|| {
                ctx.streams
                    .iter()
                    .filter(|(key, _)| key.pid == pid)
                    .max_by(|(_, left), (_, right)| {
                        left.selection_score(now_ns)
                            .partial_cmp(&right.selection_score(now_ns))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(_, stream)| stream)
            })?;
            best.selection_score(now_ns)
                .is_finite()
                .then_some((pid, best.cur_fps))
        })
        .collect::<Vec<_>>();
    for (pid, fps) in observed {
        let Some(probe) = ctx.pid_symbol_probes.get_mut(&pid) else {
            continue;
        };
        if probe.confirmed {
            continue;
        }
        let recovered = probe.confirmed_once;
        probe.confirmed = true;
        probe.confirmed_once = true;
        probe.exhausted = false;
        if let Some(symbol) = ctx.pid_symbols.get(&pid).cloned() {
            ctx.symbol = symbol.clone();
            let raw_symbol = symbol.to_string_lossy();
            if recovered {
                println!(
                    "[FPS] 帧源恢复: PID={pid} 角色={} 候选={}/{} 符号={} FPS={fps:.1} 降级=未触发",
                    pid_role_label(pid, ctx.target_pkg.as_deref()),
                    probe.candidate_index + 1,
                    LIBGUI_FRAME_SYMBOLS.len(),
                    readable_symbol_from_raw(raw_symbol.as_ref()),
                );
            } else {
                println!(
                    "[FPS] 帧源确认: PID={pid} 角色={} 候选={}/{} 符号={} FPS={fps:.1}",
                    pid_role_label(pid, ctx.target_pkg.as_deref()),
                    probe.candidate_index + 1,
                    LIBGUI_FRAME_SYMBOLS.len(),
                    readable_symbol_from_raw(raw_symbol.as_ref()),
                );
            }
            println!("[FPS]   原始符号={raw_symbol}");
        }
    }
    if let Some(symbol) = ctx
        .selected_stream
        .and_then(|key| ctx.pid_symbols.get(&key.pid))
        .cloned()
    {
        ctx.symbol = symbol;
    }
}

fn advance_symbol_probes(ctx: &mut AppOptEbpfCtx, now_ns: u64) -> Result<(), String> {
    if now_ns == 0 {
        return Ok(());
    }
    let expired = ctx
        .pid_symbol_probes
        .iter()
        .filter_map(|(pid, probe)| {
            (!probe.confirmed
                && !probe.exhausted
                && now_ns.saturating_sub(probe.candidate_started_ns) >= SYMBOL_PROBE_NS)
                .then_some(*pid)
        })
        .collect::<Vec<_>>();
    let mut errors = Vec::new();
    for pid in expired {
        if let Err(err) = switch_pid_symbol(ctx, pid, now_ns) {
            if let Some(probe) = ctx.pid_symbol_probes.get_mut(&pid) {
                probe.exhausted = true;
            }
            errors.push(err);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn retry_confirmed_symbols(ctx: &mut AppOptEbpfCtx) -> Result<usize, String> {
    let now_ns = monotonic_ns();
    let confirmed = ctx
        .pid_symbol_probes
        .iter()
        .filter_map(|(pid, probe)| probe.confirmed.then_some(*pid))
        .collect::<Vec<_>>();
    let mut switched = 0usize;
    let mut errors = Vec::new();
    for pid in confirmed {
        if let Some(probe) = ctx.pid_symbol_probes.get_mut(&pid) {
            probe.confirmed = false;
            probe.round_started_ns = now_ns;
        }
        match switch_pid_symbol(ctx, pid, now_ns) {
            Ok(true) => switched += 1,
            Ok(false) => {}
            Err(err) => {
                if let Some(probe) = ctx.pid_symbol_probes.get_mut(&pid) {
                    probe.exhausted = true;
                }
                errors.push(err);
            }
        }
    }
    if errors.is_empty() {
        Ok(switched)
    } else {
        Err(errors.join("; "))
    }
}

fn open_ring_buffer(bpf: &mut Ebpf) -> Result<RingBuf<MapData>, String> {
    RingBuf::try_from(
        bpf.take_map("events")
            .ok_or_else(|| "missing BPF map: events".to_string())?,
    )
    .map_err(|error| error_chain(&error))
}

fn open_perf_buffers(bpf: &mut Ebpf) -> Result<Vec<PerfEventArrayBuffer<MapData>>, String> {
    let mut perf_array = PerfEventArray::try_from(
        bpf.take_map("events")
            .ok_or_else(|| "missing BPF map: events".to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let cpus = online_cpus().map_err(|(_, err)| err.to_string())?;
    let mut buffers = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buffer = perf_array
            .open(cpu, Some(8))
            .map_err(|e| format!("open perf buffer cpu {cpu}: {e}"))?;
        buffers.push(buffer);
    }

    if buffers.is_empty() {
        return Err("no online CPUs for perf event array".to_string());
    }
    Ok(buffers)
}

fn perf_fallback_path(path: &Path) -> PathBuf {
    path.with_file_name("queuebuffer_probe_perf.bpf.o")
}

fn stats_fallback_path(path: &Path) -> PathBuf {
    path.with_file_name("queuebuffer_probe_stats.bpf.o")
}

fn start_backend(
    path: &Path,
    kind: BackendKind,
    pid: c_int,
    target_pkg: Option<String>,
) -> Result<Box<AppOptEbpfCtx>, String> {
    // 每次启动只加载一种 BPF 对象。三种对象的事件 map 类型不同，不能在同一个
    // bpf.o 内运行时互换；StatsMap 对象完全不创建事件传输 map。
    let mut bpf = Ebpf::load_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let backend = match kind {
        BackendKind::RingBuf => EventBackend::RingBuf(open_ring_buffer(&mut bpf)?),
        BackendKind::StatsMap => EventBackend::StatsMap,
        BackendKind::PerfEvent => EventBackend::PerfEvent(open_perf_buffers(&mut bpf)?),
    };
    let target_pid = u32::try_from(pid).map_err(|_| format!("invalid target pid: {pid}"))?;
    if target_pid == 0 {
        return Err(format!("invalid target pid: {pid}"));
    }
    let libgui_path = resolve_libgui_path(pid)?;
    let libgui_offsets = resolve_candidate_offsets(&libgui_path)?;
    // 程序装载前不能 take/drop 它引用的 map。Aya 已把 map FD 重定位进指令，若此时
    // 提前关闭 perf_stats_only 等 FD，旧内核 verifier 会报 not pointing to valid bpf_map。
    load_uprobe_program(&mut bpf)?;
    let frame_stats = match bpf.take_map("frame_stats") {
        Some(map) => Some(AyaHashMap::try_from(map).map_err(|e| e.to_string())?),
        None => None,
    };
    if matches!(kind, BackendKind::StatsMap) && frame_stats.is_none() {
        return Err("missing BPF map: frame_stats".to_string());
    }
    let frame_stats_drops = bpf
        .take_map("frame_stats_drops")
        .map(|map| AyaArray::<_, u32>::try_from(map).map_err(|e| e.to_string()))
        .transpose()?;
    let ringbuf_drops = if matches!(kind, BackendKind::RingBuf) {
        Some(
            AyaArray::<_, u32>::try_from(
                bpf.take_map("ringbuf_drops")
                    .ok_or_else(|| "missing BPF map: ringbuf_drops".to_string())?,
            )
            .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let mut use_frame_stats = frame_stats.is_some();
    let mut perf_mode_note = None;
    let mut perf_stats_only = None;
    if matches!(kind, BackendKind::PerfEvent) && frame_stats.is_some() {
        let stats_mode = match bpf.take_map("perf_stats_only") {
            Some(map) => match AyaArray::<_, u32>::try_from(map) {
                Ok(mut mode) => match mode.set(0, perf_stats_mode_value(true), 0) {
                    Ok(()) => {
                        perf_stats_only = Some(mode);
                        Ok(())
                    }
                    Err(error) => Err(error.to_string()),
                },
                Err(error) => Err(error.to_string()),
            },
            None => Err("missing BPF map: perf_stats_only".to_string()),
        };
        if let Err(error) = stats_mode {
            // 程序已经成功装载；配置 map 异常时继续消费 PerfEvent 逐帧事件。
            use_frame_stats = false;
            perf_mode_note = Some(format!("frame_stats 省流模式不可用，保留逐帧事件: {error}"));
        }
    }
    let (candidate_index, symbol, symbol_offset, task_links) =
        attach_process_candidate(&mut bpf, target_pid, &libgui_path, &libgui_offsets, 0)?;
    let mut target_tgids = AyaHashMap::try_from(
        bpf.take_map("target_tgids")
            .ok_or_else(|| "missing BPF map: target_tgids".to_string())?,
    )
    .map_err(|e| e.to_string())?;
    target_tgids
        .insert(target_pid, 1, 0)
        .map_err(|e| format!("target_tgids[{target_pid}]: {e}"))?;
    let target_pids = HashSet::from([target_pid]);
    let task_count = task_links.len();
    let task_starttimes = task_starttime_snapshot(target_pid, task_links.keys().copied());
    let probe_started_ns = monotonic_ns();
    let frame_mode = match kind {
        BackendKind::RingBuf => "计帧=RingBuf逐帧事件",
        BackendKind::StatsMap => "计帧=frame_stats map",
        BackendKind::PerfEvent if use_frame_stats => "计帧=frame_stats map（PerfEvent省流）",
        BackendKind::PerfEvent => "计帧=PerfEvent逐帧事件",
    };
    let pid_links = HashMap::from([(target_pid, task_links)]);
    let pid_starttimes = process_starttime(target_pid)
        .map(|starttime| HashMap::from([(target_pid, starttime)]))
        .unwrap_or_default();
    let pid_task_starttimes = HashMap::from([(target_pid, task_starttimes)]);
    let pid_libgui_paths = HashMap::from([(target_pid, libgui_path.clone())]);
    let libgui_symbol_offsets = HashMap::from([(libgui_path.clone(), libgui_offsets)]);
    let pid_symbols = HashMap::from([(target_pid, symbol.clone())]);
    let pid_symbol_offsets = HashMap::from([(target_pid, symbol_offset)]);
    let pid_symbol_probes = HashMap::from([(
        target_pid,
        PidSymbolProbe {
            candidate_index,
            candidate_started_ns: probe_started_ns,
            round_started_ns: probe_started_ns,
            confirmed: false,
            confirmed_once: false,
            exhausted: false,
            attachable_mask: candidate_bit(candidate_index),
            no_frame_mask: 0,
            stalled_mask: 0,
            unavailable_mask: candidate_range_mask(0, candidate_index),
        },
    )]);

    Ok(Box::new(AppOptEbpfCtx {
        bpf,
        backend,
        frame_stats,
        use_frame_stats,
        perf_stats_only,
        frame_stats_drops,
        frame_stats_drops_seen: 0,
        frame_stats_drops_pending: 0,
        frame_stats_drops_last_log_ns: 0,
        ringbuf_drops,
        ringbuf_drops_seen: 0,
        ringbuf_drops_pending: 0,
        ringbuf_drops_last_log_ns: 0,
        target_tgids,
        target_pids,
        pid,
        streams: HashMap::new(),
        selected_stream: None,
        pending_stream: None,
        pending_stream_since_ns: 0,
        stat_snapshots: HashMap::new(),
        frame_stats_updates: Vec::new(),
        frame_stats_last_poll_ns: 0,
        frame_stats_last_prune_ns: 0,
        pid_links,
        pid_starttimes,
        pid_task_starttimes,
        pid_libgui_paths,
        libgui_symbol_offsets,
        pid_symbols,
        pid_symbol_offsets,
        pid_symbol_probes,
        detailed_logging: true,
        frame_mode_reported: false,
        perf_lost_pending: 0,
        perf_lost_last_log_ns: 0,
        perf_buffer_cursor: 0,
        cur_fps: 0.0,
        symbol,
        backend_label: cstring_lossy(kind.label()),
        backend_selection_note: cstring_lossy("后端选择尚未完成"),
        startup_note: cstring_lossy(format!(
            "对象={} lib={} PID={} 挂载TID={} 候选符号={} {}{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("queuebuffer_probe.bpf.o"),
            libgui_path.display(),
            target_pid,
            task_count,
            LIBGUI_FRAME_SYMBOLS.len(),
            frame_mode,
            perf_mode_note
                .as_deref()
                .map(|note| format!("；{note}"))
                .unwrap_or_default()
        )),
        last_error: cstring_lossy(""),
        target_pkg,
    }))
}

fn perf_stats_mode_value(frame_stats_available: bool) -> u32 {
    u32::from(frame_stats_available)
}

fn start_impl(
    pid: c_int,
    bpf_obj_path: *const c_char,
    target_pkg: *const c_char,
) -> *mut AppOptEbpfCtx {
    match catch_unwind(AssertUnwindSafe(|| {
        if bpf_obj_path.is_null() {
            return Err("null bpf object path".to_string());
        }

        let path = unsafe { CStr::from_ptr(bpf_obj_path) }
            .to_str()
            .map_err(|e| e.to_string())?;
        let target_pkg = if target_pkg.is_null() {
            None
        } else {
            let pkg = unsafe { CStr::from_ptr(target_pkg) }
                .to_str()
                .map_err(|e| e.to_string())?
                .to_string();
            if pkg.is_empty() { None } else { Some(pkg) }
        };

        let ring_path = Path::new(path);
        let ring_skip_note = ringbuf_kernel_note();
        let ring_attempt = match ring_skip_note.clone() {
            Some(note) => Err(note),
            None => start_backend(ring_path, BackendKind::RingBuf, pid, target_pkg.clone()),
        };
        let ctx = match ring_attempt {
            Ok(mut ctx) => {
                ctx.backend_selection_note = cstring_lossy(backend_selection_report(
                    "成功",
                    None,
                    "未尝试",
                    None,
                    "未尝试",
                ));
                ctx
            }
            Err(ring_err) => {
                // 4.19 等旧内核不支持 RingBuf，先尝试只依赖 HashMap 的 StatsMap。
                let stats_path = stats_fallback_path(ring_path);
                match start_backend(&stats_path, BackendKind::StatsMap, pid, target_pkg.clone()) {
                    Ok(mut ctx) => {
                        let ring_state = if ring_skip_note.is_some() {
                            "跳过"
                        } else {
                            "失败"
                        };
                        ctx.backend_selection_note = cstring_lossy(backend_selection_report(
                            ring_state,
                            Some(&ring_err),
                            "成功",
                            None,
                            "未尝试",
                        ));
                        ctx
                    }
                    Err(stats_err) => {
                        let perf_path = perf_fallback_path(ring_path);
                        match start_backend(&perf_path, BackendKind::PerfEvent, pid, target_pkg) {
                            Ok(mut ctx) => {
                                let ring_state = if ring_skip_note.is_some() {
                                    "跳过"
                                } else {
                                    "失败"
                                };
                                ctx.backend_selection_note =
                                    cstring_lossy(backend_selection_report(
                                        ring_state,
                                        Some(&ring_err),
                                        "失败",
                                        Some(&stats_err),
                                        "成功",
                                    ));
                                ctx
                            }
                            Err(perf_err) => {
                                return Err(format!(
                                    "RingBuf failed: {ring_err}; StatsMap failed: {stats_err}; PerfEvent failed: {perf_err}"
                                ));
                            }
                        }
                    }
                }
            }
        };

        set_last_start_error("");
        Ok::<_, String>(ctx)
    })) {
        Ok(Ok(ctx)) => Box::into_raw(ctx),
        Ok(Err(err)) => {
            set_last_start_error(err);
            ptr::null_mut()
        }
        Err(_) => {
            set_last_start_error("panic while starting eBPF bridge");
            ptr::null_mut()
        }
    }
}

fn sync_target_pids(ctx: &mut AppOptEbpfCtx, pids: &[c_int]) -> Result<usize, String> {
    let mut desired = HashSet::new();
    for pid in pids.iter().copied().filter(|pid| *pid > 0) {
        let pid = pid as u32;
        if ctx
            .target_pkg
            .as_deref()
            .is_some_and(|pkg| !pid_matches_pkg(pid, pkg))
        {
            continue;
        }
        desired.insert(pid);
    }

    let previous = ctx.target_pids.clone();
    for pid in previous.intersection(&desired).copied() {
        if !ctx.pid_starttimes.contains_key(&pid)
            && let Some(starttime) = process_starttime(pid)
        {
            ctx.pid_starttimes.insert(pid, starttime);
        }
    }
    let reused = previous
        .intersection(&desired)
        .copied()
        .filter(|pid| {
            ctx.pid_starttimes
                .get(pid)
                .zip(process_starttime(*pid))
                .is_some_and(|(old, current)| old != &current)
        })
        .collect::<HashSet<_>>();
    let mut removed = previous.difference(&desired).copied().collect::<Vec<_>>();
    removed.extend(reused.iter().copied());
    let mut update_errors = Vec::new();
    for pid in &removed {
        if let Err(err) = ctx.target_tgids.remove(pid) {
            update_errors.push(format!("移除 target_tgids[{pid}] 失败: {err}"));
        }
        if let Some(links) = ctx.pid_links.remove(pid) {
            update_errors.extend(detach_pid_links(&mut ctx.bpf, *pid, links));
        }
        ctx.pid_libgui_paths.remove(pid);
        ctx.pid_starttimes.remove(pid);
        ctx.pid_task_starttimes.remove(pid);
        ctx.pid_symbols.remove(pid);
        ctx.pid_symbol_offsets.remove(pid);
        ctx.pid_symbol_probes.remove(pid);
    }

    let mut effective = previous
        .intersection(&desired)
        .copied()
        .filter(|pid| !reused.contains(pid))
        .collect::<HashSet<_>>();
    for pid in effective.iter().copied().collect::<Vec<_>>() {
        if !ctx.pid_libgui_paths.contains_key(&pid) {
            match resolve_libgui_path(pid as i32) {
                Ok(path) => {
                    ctx.pid_libgui_paths.insert(pid, path);
                }
                Err(err) => {
                    update_errors.push(err);
                    continue;
                }
            }
        }
        let Some(path) = ctx.pid_libgui_paths.get(&pid) else {
            continue;
        };
        if let Some(task_links) = ctx.pid_links.get_mut(&pid) {
            let selected_symbol = ctx
                .pid_symbols
                .get(&pid)
                .unwrap_or(&ctx.symbol)
                .to_string_lossy()
                .into_owned();
            let Some(offset) = ctx.pid_symbol_offsets.get(&pid).copied() else {
                update_errors.push(format!("pid={pid} 缺少已解析的 uprobe 符号偏移"));
                continue;
            };
            let task_starttimes = ctx.pid_task_starttimes.entry(pid).or_default();
            let sync = sync_process_tasks(
                &mut ctx.bpf,
                pid,
                path,
                &selected_symbol,
                offset,
                task_links,
                task_starttimes,
            );
            // 新线程沿用当前候选符号即可；不能因为线程 churn 反复重置候选
            // 计时，否则错误符号在持续创建线程的游戏里会永不轮换。
            update_errors.extend(sync.errors);
        }
    }
    let added_pids = desired.difference(&effective).copied().collect::<Vec<_>>();
    for pid in added_pids {
        let path = match resolve_libgui_path(pid as i32) {
            Ok(path) => path,
            Err(err) => {
                update_errors.push(err);
                continue;
            }
        };
        let offsets = match cached_candidate_offsets(ctx, &path) {
            Ok(offsets) => offsets,
            Err(err) => {
                update_errors.push(err);
                continue;
            }
        };
        let (candidate_index, pid_symbol, symbol_offset, task_links) =
            match attach_process_candidate(&mut ctx.bpf, pid, &path, &offsets, 0) {
                Ok(attached) => attached,
                Err(err) => {
                    update_errors.push(err);
                    continue;
                }
            };
        if let Err(err) = ctx.target_tgids.insert(pid, 1, 0) {
            update_errors.push(format!("更新 target_tgids[{pid}] 失败: {err}"));
            update_errors.extend(detach_pid_links(&mut ctx.bpf, pid, task_links));
            continue;
        }
        ctx.pid_libgui_paths.insert(pid, path);
        ctx.pid_links.insert(pid, task_links);
        if let Some(starttime) = process_starttime(pid) {
            ctx.pid_starttimes.insert(pid, starttime);
        }
        ctx.pid_task_starttimes.insert(
            pid,
            task_starttime_snapshot(pid, ctx.pid_links[&pid].keys().copied()),
        );
        ctx.pid_symbols.insert(pid, pid_symbol);
        ctx.pid_symbol_offsets.insert(pid, symbol_offset);
        let probe_started_ns = monotonic_ns();
        ctx.pid_symbol_probes.insert(
            pid,
            PidSymbolProbe {
                candidate_index,
                candidate_started_ns: probe_started_ns,
                round_started_ns: probe_started_ns,
                confirmed: false,
                confirmed_once: false,
                exhausted: false,
                attachable_mask: candidate_bit(candidate_index),
                no_frame_mask: 0,
                stalled_mask: 0,
                unavailable_mask: candidate_range_mask(0, candidate_index),
            },
        );
        effective.insert(pid);
    }

    ctx.target_pids = effective;
    ctx.streams
        .retain(|key, _| ctx.target_pids.contains(&key.pid));
    ctx.stat_snapshots
        .retain(|key, _| ctx.target_pids.contains(&key.pid));
    if let Some(stats) = ctx.frame_stats.as_mut() {
        let stale_keys = stats
            .keys()
            .filter_map(Result::ok)
            .filter(|key| !ctx.target_pids.contains(&key.pid))
            .collect::<Vec<_>>();
        for key in stale_keys {
            let _ = stats.remove(&key);
        }
    }
    if ctx
        .selected_stream
        .is_some_and(|key| !ctx.target_pids.contains(&key.pid))
    {
        ctx.selected_stream = None;
        ctx.pending_stream = None;
        ctx.pending_stream_since_ns = 0;
        ctx.cur_fps = 0.0;
        ctx.pid = -1;
    }
    if ctx.selected_stream.is_none()
        && (ctx.pid <= 0 || !ctx.target_pids.contains(&(ctx.pid as u32)))
    {
        ctx.pid = ctx
            .target_pids
            .iter()
            .copied()
            .next()
            .map_or(-1, |pid| pid as i32);
    }

    if update_errors.is_empty() {
        ctx.last_error = cstring_lossy("");
    } else {
        let message = compact_error_details(&update_errors);
        ctx.last_error = cstring_lossy(&message);
    }
    // Thread-level attach/read failures are partial, retryable observations.
    // Return the effective PID count so the daemon does not treat a single
    // short-lived thread as a total target-sync failure and repeat the entire
    // /proc walk every poll.
    Ok(ctx.target_pids.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_start(pid: c_int, bpf_obj_path: *const c_char) -> *mut AppOptEbpfCtx {
    start_impl(pid, bpf_obj_path, ptr::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_start_for_package(
    pid: c_int,
    bpf_obj_path: *const c_char,
    target_pkg: *const c_char,
) -> *mut AppOptEbpfCtx {
    start_impl(pid, bpf_obj_path, target_pkg)
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_last_start_error() -> *const c_char {
    match LAST_START_ERROR.lock() {
        Ok(last) => last.as_ref().map_or(ptr::null(), |err| err.as_ptr()),
        Err(_) => ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_set_target_pids(
    ctx: *mut AppOptEbpfCtx,
    pids: *const c_int,
    len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = ptr_as_mut(ctx) else {
            return -1;
        };
        if len > 128 || (len > 0 && pids.is_null()) {
            ctx.last_error = cstring_lossy("目标 PID 参数无效");
            return -1;
        }
        let pids = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(pids, len) }
        };
        match sync_target_pids(ctx, pids) {
            Ok(count) => count.min(c_int::MAX as usize) as c_int,
            Err(err) => {
                ctx.last_error = cstring_lossy(err);
                -1
            }
        }
    }))
    .unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_poll(ctx: *mut AppOptEbpfCtx) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = ptr_as_mut(ctx) else {
            return -1;
        };

        match poll_inner(ctx) {
            Ok(consumed) => {
                confirm_observed_symbols(ctx);
                match advance_symbol_probes(ctx, monotonic_ns()) {
                    Ok(()) => consumed,
                    Err(err) => {
                        ctx.last_error = cstring_lossy(err);
                        -1
                    }
                }
            }
            Err(err) => {
                ctx.last_error = cstring_lossy(err);
                -1
            }
        }
    }))
    .unwrap_or(-1)
}

// 0=无目标，1=仍在验证候选，2=已有真实帧确认，3=所有目标候选均已试完。
#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_probe_state(ctx: *const AppOptEbpfCtx) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let ctx = unsafe { &*ctx };
    if ctx.pid_symbol_probes.is_empty() {
        return 0;
    }
    if ctx.pid_symbol_probes.values().any(|probe| probe.confirmed) {
        return 2;
    }
    if ctx.pid_symbol_probes.values().any(|probe| !probe.exhausted) {
        return 1;
    }
    3
}

// 已确认的符号后续停止出帧时，由 daemon 请求继续尝试剩余候选。
// 返回值：>0 已切换的目标数，0 没有剩余候选，-1 切换失败。
#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_retry_symbols(ctx: *mut AppOptEbpfCtx) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = ptr_as_mut(ctx) else {
            return -1;
        };
        match retry_confirmed_symbols(ctx) {
            Ok(count) => count.min(c_int::MAX as usize) as c_int,
            Err(err) => {
                ctx.last_error = cstring_lossy(err);
                -1
            }
        }
    }))
    .unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_get(ctx: *const AppOptEbpfCtx) -> c_double {
    if ctx.is_null() {
        return 0.0;
    }
    let ctx = unsafe { &*ctx };
    ctx.cur_fps
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_metrics(
    ctx: *const AppOptEbpfCtx,
    out: *mut AppOptFrameMetrics,
) -> c_int {
    if ctx.is_null() || out.is_null() {
        return 0;
    }
    let ctx = unsafe { &*ctx };
    let Some(stream) = ctx.selected_stream.and_then(|key| ctx.streams.get(&key)) else {
        return 0;
    };
    if stream.frame_times.is_empty() {
        return 0;
    }
    let mut intervals = stream.frame_times.iter().copied().collect::<Vec<_>>();
    intervals.sort_unstable();
    let percentile = |percent: usize| -> u64 {
        let index = ((intervals.len() - 1) * percent + 99) / 100;
        intervals[index.min(intervals.len() - 1)]
    };
    unsafe {
        *out = AppOptFrameMetrics {
            fps: stream.cur_fps,
            median_interval_ns: percentile(50),
            p95_interval_ns: percentile(95),
            max_interval_ns: intervals.last().copied().unwrap_or(0),
            frame_count: intervals.len().min(u32::MAX as usize) as u32,
            flags: if (matches!(&ctx.backend, EventBackend::StatsMap)
                || (matches!(&ctx.backend, EventBackend::PerfEvent(_)) && ctx.use_frame_stats))
                && ctx.frame_stats.is_some()
            {
                1
            } else {
                0
            },
        };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_pid(ctx: *const AppOptEbpfCtx) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    ctx.pid
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_symbol(ctx: *const AppOptEbpfCtx) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    if let Some(symbol) = ctx
        .selected_stream
        .and_then(|key| ctx.pid_symbols.get(&key.pid))
    {
        return symbol.as_ptr();
    }
    ctx.symbol.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_symbol_display(ctx: *const AppOptEbpfCtx) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let symbol = ctx
        .selected_stream
        .and_then(|key| ctx.pid_symbols.get(&key.pid))
        .unwrap_or(&ctx.symbol);
    readable_symbol_cstr_from_raw(symbol.to_str().unwrap_or_default())
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_backend(ctx: *const AppOptEbpfCtx) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.backend_label.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_backend_note(ctx: *const AppOptEbpfCtx) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.backend_selection_note.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_set_detailed_logging(
    ctx: *mut AppOptEbpfCtx,
    enabled: c_int,
) -> c_int {
    let Some(ctx) = ptr_as_mut(ctx) else {
        return -1;
    };
    ctx.detailed_logging = enabled != 0;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_startup_note(ctx: *const AppOptEbpfCtx) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.startup_note.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_last_error(ctx: *const AppOptEbpfCtx) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.last_error.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn appopt_ebpf_stop(ctx: *mut AppOptEbpfCtx) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(ctx));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_events_remain_enabled_without_stats_map() {
        assert_eq!(perf_stats_mode_value(false), 0);
    }

    #[test]
    fn perf_events_are_suppressed_after_stats_map_is_confirmed() {
        assert_eq!(perf_stats_mode_value(true), 1);
    }

    #[test]
    fn fallback_objects_are_resolved_next_to_ring_object() {
        let ring = Path::new("/module/config/ebpf/queuebuffer_probe.bpf.o");
        assert_eq!(
            stats_fallback_path(ring),
            PathBuf::from("/module/config/ebpf/queuebuffer_probe_stats.bpf.o")
        );
        assert_eq!(
            perf_fallback_path(ring),
            PathBuf::from("/module/config/ebpf/queuebuffer_probe_perf.bpf.o")
        );
    }

    #[test]
    fn fps_symbols_have_stable_readable_names() {
        assert_eq!(LIBGUI_FRAME_SYMBOLS.len(), LIBGUI_FRAME_SYMBOL_NAMES.len());
        assert_eq!(
            LIBGUI_FRAME_SYMBOLS.len(),
            LIBGUI_FRAME_SYMBOL_NAME_CSTRS.len()
        );
        for (index, raw) in LIBGUI_FRAME_SYMBOLS.iter().enumerate() {
            assert_eq!(readable_symbol_from_raw(raw), readable_symbol_name(index));
            assert_eq!(
                compact_symbol_name(index),
                readable_symbol_name(index)
                    .strip_prefix("Surface::")
                    .unwrap()
            );
        }
        assert_eq!(
            readable_symbol_from_raw("missing"),
            "Surface::queueBuffer(未知符号)"
        );
    }

    #[test]
    fn probe_summary_groups_no_frame_and_stalled_candidates() {
        let probe = PidSymbolProbe {
            candidate_index: 3,
            candidate_started_ns: 9,
            round_started_ns: 1,
            confirmed: false,
            confirmed_once: true,
            exhausted: true,
            attachable_mask: candidate_bit(0) | candidate_bit(2) | candidate_bit(3),
            no_frame_mask: candidate_bit(0) | candidate_bit(2),
            stalled_mask: candidate_bit(3),
            unavailable_mask: candidate_bit(1) | candidate_bit(4),
        };
        assert_eq!(
            probe_candidate_results(probe),
            "queueBuffer=0 | hook_queueBuffer=0 | queueBufferInternal=停帧"
        );
        assert_eq!(probe.attachable_mask.count_ones(), 3);
    }

    #[test]
    fn backend_report_keeps_attempt_order_and_compacts_errors() {
        assert_eq!(
            backend_selection_report(
                "跳过",
                Some("内核 4.19\n不支持 RingBuf"),
                "成功",
                None,
                "未尝试",
            ),
            "RingBuf=跳过（内核 4.19 不支持 RingBuf） | StatsMap=成功 | PerfEvent=未尝试 | SurfaceFlinger=待命"
        );
    }

    #[test]
    fn kernel_release_parser_handles_android_vendor_suffixes() {
        assert_eq!(
            parse_kernel_release_version("4.19.113-perf-g42cc20a57a7b"),
            Some((4, 19))
        );
        assert_eq!(
            parse_kernel_release_version("5.4.210-qgki-g123"),
            Some((5, 4))
        );
        assert_eq!(parse_kernel_release_version("5.8.0"), Some((5, 8)));
        assert_eq!(
            parse_kernel_release_version("6.6.66-android15-8"),
            Some((6, 6))
        );
        assert_eq!(parse_kernel_release_version("android-kernel"), None);
    }
}
