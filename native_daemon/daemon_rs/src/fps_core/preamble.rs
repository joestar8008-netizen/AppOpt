    // FPS 模块的公共导入和常量。
    //
    // 这个模块只在 Android/Linux 目标启用；Windows 主机 cargo check 会走 fps.rs 里的空实现。
    // 真正的 Android 交叉编译由 build_module.sh no 验证。
    //
    // FPS 主路径是多进程 eBPF queueBuffer；RingBuf、StatsMap、PerfEvent 和
    // SurfaceFlinger 组成按能力降级链。
    use std::collections::BTreeSet;
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::io::{self, Read};
    use std::mem;
    use std::path::PathBuf;
    use std::ptr;
    use std::process::{Command, Stdio};
    use std::slice;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use appopt_ebpf_bridge::{
        appopt_ebpf_backend, appopt_ebpf_backend_note, appopt_ebpf_get, appopt_ebpf_last_error,
        appopt_ebpf_last_start_error, appopt_ebpf_metrics, appopt_ebpf_pid, appopt_ebpf_poll,
        appopt_ebpf_probe_state, appopt_ebpf_set_target_pids,
        appopt_ebpf_set_detailed_logging,
        appopt_ebpf_start_for_package, appopt_ebpf_symbol_display,
        appopt_ebpf_startup_note, appopt_ebpf_stop, appopt_jank_create,
        appopt_jank_last_event, appopt_jank_recover, appopt_jank_stop, appopt_jank_update, AppOptEbpfCtx,
        AppOptFrameMetrics, AppOptJankCtx,
    };
    use crate::{app_top_state_check, process_index_find_package_pids};

    // FPS 监测流程：
    // 1. App 写 fps.cmd 请求开始监测某个包名。
    // 2. Rust daemon 优先加载 RingBuf 对象；旧内核自动切 StatsMap 对象，仍然通过
    //    libgui queueBuffer uprobe 在内核 map 中统计目标进程帧数。
    // 3. 用户态为同包进程的现有/新增线程增量挂载 uprobe，并同步 TGID map，不重载 BPF 对象。
    // 4. 只有 eBPF 无法加载或连续轮询报错才降级到 SurfaceFlinger Binder/CLI；
    //    应用空闲、首帧尚未出现或暂时停帧都保留 eBPF 主路径。
    // 5. 输出优先走 App 建立的 socket，socket 不可用时写 files/fps 兼容旧路径。
    const FPS_CMD_FILE: &str = "/data/adb/modules/AppOpt/config/fps.cmd";
    const FPS_OUT_DIR: &str = "/data/data/top.suto.appopt/files";
    const FPS_OUT_FILE: &str = "/data/data/top.suto.appopt/files/fps";
    const FPS_BPF_OBJ: &str = "/data/adb/modules/AppOpt/config/ebpf/queuebuffer_probe.bpf.o";
    const FOREGROUND_TASK_STATE_FILE: &str = "/data/adb/modules/AppOpt/config/foreground_task.state";
    const JANK_BOOST_FILE: &str = "/data/adb/modules/AppOpt/config/jank_boost.conf";
    const FOREGROUND_TASK_MAX_AGE_MS: u64 = 12_000;
    const FPS_WINDOW: Duration = Duration::from_millis(1000);
    const FPS_EBPF_STALE: Duration = Duration::from_millis(2500);
    const FPS_EBPF_TARGET_REFRESH: Duration = Duration::from_secs(5);
    const FPS_EBPF_PROBE_TARGET_REFRESH: Duration = Duration::from_secs(1);
    const FPS_EBPF_TARGET_FULL_SCAN: Duration = Duration::from_secs(60);
    const FPS_EBPF_RELOCK_CHECK: Duration = Duration::from_secs(1);
    const FPS_EBPF_FALLBACK_GRACE: Duration = Duration::from_secs(30);
    const FPS_EBPF_FALLBACK_FAILURES: u32 = 3;
    const FPS_JANK_SAMPLE_INTERVAL: Duration = Duration::from_millis(900);
    const FPS_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(30);
    const FPS_EBPF_RETRY_LOG_INTERVAL: Duration = Duration::from_secs(60);
    const FPS_EBPF_PROBE_PENDING: i32 = 1;
    const FPS_EBPF_PROBE_EXHAUSTED: i32 = 3;
    const FPS_RELOCK_MISS: u32 = 3;
    const FPS_PROBE_FAIL: u32 = 5;
    const FPS_FRESH_NS: u64 = 5_000_000_000;
    pub fn start_fps_thread() -> Option<thread::JoinHandle<()>> {
        let recovered = appopt_jank_recover();
        if recovered > 0 {
            println!("[boost] 已恢复上次异常退出遗留的 {recovered} 项临时参数");
        }
        match thread::Builder::new()
            .name("AppOptRsFps".to_string())
            .spawn(|| {
                if let Err(err) = fps_loop() {
                    eprintln!("[FPS] 帧率监测线程已停止: {err}");
                }
            }) {
            Ok(handle) => Some(handle),
            Err(err) => {
                eprintln!("[FPS] 帧率监测线程创建失败: {err}");
                None
            }
        }
    }

    struct FpsMonitor {
        pkg: String,
        // ctx 内部持有目标进程各线程的 libgui uprobe、TGID map 与 RingBuf/PerfEvent 后端。
        ctx: *mut AppOptEbpfCtx,
        // 连续失败计数，防止偶发 poll 错误立刻重载 eBPF。
        ebpf_failures: u32,
        // seen/stale 用于区分“从未收到帧”和“曾经有帧但后来停了”。
        ebpf_seen_frames: bool,
        ebpf_stale_zero_sent: bool,
        ebpf_last_frame: Instant,
        last_ebpf_fps: f64,
        // 低频刷新目标 TGID，避免每 80ms 扫 /proc。
        ebpf_last_target_refresh: Instant,
        ebpf_last_full_target_scan: Option<Instant>,
        ebpf_last_restart: Instant,
        ebpf_next_restart: Instant,
        ebpf_restart_failures: u32,
        ebpf_no_frame_retries: u32,
        ebpf_retry_pid: i32,
        ebpf_last_relock_check: Option<Instant>,
        ebpf_last_target_error_log: Option<Instant>,
        ebpf_last_retry_log: Option<Instant>,
        ebpf_suppressed_retry_logs: u32,
        ebpf_attempt_detailed: bool,
        ebpf_retry_reported: bool,
        ebpf_pending_recovery: bool,
        ebpf_first_fps: bool,
        target_pids: BTreeSet<i32>,
        fallback: Option<SfFallback>,
        fallback_state_reported: bool,
        // SurfaceFlinger 只允许在 eBPF 明确不可用时接管，不能因为应用空闲无帧就触发。
        fallback_allowed: bool,
        ebpf_no_pid_since: Option<Instant>,
        socket: FpsSocket,
        last_output: Option<Instant>,
        target_pid: i32,
        started_at: Instant,
        last_frame_pid: i32,
        backend_name: String,
        confirmed_backend: Option<String>,
        fallback_used: bool,
        adaptive_enabled: bool,
        jank: *mut AppOptJankCtx,
        jank_last_sample: Option<Instant>,
        output_enabled: bool,
    }
