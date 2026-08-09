    // FPS 命令循环。
    //
    // App 写入 fps.cmd，daemon 原子认领后读取并删除：
    // - start <pkg> [socket token]
    // - stop
    //
    // socket/token 是 App 侧实时 FPS 通道；如果没有提供或连接失败，就回落到 files/fps。
    // 这里不解析更多复杂参数，避免命令文件变成半套 IPC 协议。
    fn fps_loop() -> io::Result<()> {
        let mut monitor: Option<FpsMonitor> = None;
        let mut manual_pkg: Option<String> = None;
        let mut auto_pkg: Option<String> = None;
        let mut last_selected: Option<Vec<String>> = None;
        let mut selected = Vec::new();
        let mut last_auto_check = Instant::now() - Duration::from_secs(10);
        let mut last_command_error_log: Option<Instant> = None;
        while !crate::shutdown_requested() {
            let auto_check_interval = if selected.is_empty() {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(1)
            };
            if last_auto_check.elapsed() >= auto_check_interval {
                last_auto_check = Instant::now();
                selected = read_jank_packages();
                if last_selected.as_ref() != Some(&selected) {
                    if selected.is_empty() {
                        println!("[boost] 卡顿时临时提速未配置应用");
                    } else {
                        let preview = selected.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
                        let remaining = selected.len().saturating_sub(5);
                        println!(
                            "[boost] 已配置临时提速: {}{}；等待所选应用进入前台",
                            preview,
                            if remaining > 0 {
                                format!(" ... +{remaining}")
                            } else {
                                String::new()
                            }
                        );
                    }
                    last_selected = Some(selected.clone());
                }
                let target = selected_jank_foreground(&selected);
                if manual_pkg.is_none() && target != auto_pkg {
                    if let Some(mut old) = monitor.take() {
                        old.stop("动态调度目标切换");
                    }
                    monitor = target.clone().map(|pkg| {
                        let mut active = FpsMonitor::start(pkg, None, None);
                        active.set_output_enabled(false);
                        active.set_adaptive(true);
                        active
                    });
                    auto_pkg = target;
                } else if let (Some(manual), Some(active)) =
                    (manual_pkg.as_deref(), monitor.as_mut())
                {
                    active.set_adaptive(target.as_deref() == Some(manual));
                }
            }
            // fps.cmd 是简单命令文件，App 每次启动/停止 FPS 都会写入。
            // 瞬时文件错误不能结束整个 FPS 线程；限频记录后继续保留当前监测状态。
            let command = match read_command() {
                Ok(command) => command,
                Err(err) => {
                    let now = Instant::now();
                    if last_command_error_log
                        .map(|last| now.duration_since(last) >= Duration::from_secs(30))
                        .unwrap_or(true)
                    {
                        eprintln!("[FPS] 读取命令文件失败，稍后重试: {err}");
                        last_command_error_log = Some(now);
                    }
                    None
                }
            };
            if let Some(cmd) = command {
                if let Some(rest) = cmd.strip_prefix("start ").map(str::trim) {
                    if let Some(mut old) = monitor.take() {
                        old.stop("切换监测目标");
                    }
                    let parts = rest.split_whitespace().collect::<Vec<_>>();
                    if let Some(pkg) = parts.first().copied().filter(|pkg| !pkg.is_empty()) {
                        let socket_name = parts.get(1).map(|value| (*value).to_string());
                        let socket_token = parts.get(2).map(|value| (*value).to_string());
                        monitor = Some(FpsMonitor::start(
                            pkg.to_string(),
                            socket_name,
                            socket_token,
                        ));
                        manual_pkg = Some(pkg.to_string());
                        auto_pkg = None;
                        selected = read_jank_packages();
                        if selected_jank_foreground(&selected).as_deref() == Some(pkg) {
                            if let Some(active) = monitor.as_mut() {
                                active.set_adaptive(true);
                            }
                        }
                    }
                } else if cmd == "stop" || cmd.starts_with("stop ") {
                    manual_pkg = None;
                    selected = read_jank_packages();
                    let target = selected_jank_foreground(&selected);
                    if let Some(pkg) = target {
                        if monitor.as_ref().is_none_or(|active| active.pkg != pkg) {
                            if let Some(mut old) = monitor.take() {
                                old.stop("切换到动态调度目标");
                            }
                            monitor = Some(FpsMonitor::start(pkg.clone(), None, None));
                        }
                        if let Some(active) = monitor.as_mut() {
                            active.set_output_enabled(false);
                            active.set_adaptive(true);
                        }
                        auto_pkg = Some(pkg);
                    } else if let Some(mut old) = monitor.take() {
                        old.stop("用户停止");
                    }
                }
            }

            if let Some(active) = monitor.as_mut() {
                active.poll();
            } else {
                thread::sleep(Duration::from_millis(300));
            }
        }
        if let Some(mut active) = monitor.take() {
            active.stop("守护进程退出");
        }
        Ok(())
    }

    fn read_jank_packages() -> Vec<String> {
        fs::read_to_string(JANK_BOOST_FILE)
            .unwrap_or_default()
            .lines()
            .filter_map(normalize_jank_package)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn normalize_jank_package(line: &str) -> Option<String> {
        let value = line.split('#').next()?.trim();
        let base = value.split(':').next()?.trim();
        if base.is_empty()
            || !base.contains('.')
            || !base
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
        {
            return None;
        }
        Some(base.to_string())
    }

    enum JankForegroundState {
        Reliable(String),
        Unavailable,
    }

    fn selected_jank_foreground(selected: &[String]) -> Option<String> {
        if selected.is_empty() {
            return None;
        }
        match read_jank_foreground() {
            JankForegroundState::Reliable(pkg) => {
                selected.iter().any(|item| item == &pkg).then_some(pkg)
            }
            JankForegroundState::Unavailable => {
                // cgroup 内容与目标包无关，只扫描一次再和配置集合求交。逐包重复扫描
                // 会在前台助手不可用且配置较多时把同一批 /proc/cgroup IO 放大数十倍。
                let top_state = app_top_state_check("");
                selected.iter().find_map(|pkg| {
                    top_state
                        .packages
                        .iter()
                        .any(|top_pkg| top_pkg == pkg)
                        .then(|| pkg.clone())
                })
            }
        }
    }

    fn read_jank_foreground() -> JankForegroundState {
        let Ok(raw) = fs::read_to_string(FOREGROUND_TASK_STATE_FILE) else {
            return JankForegroundState::Unavailable;
        };
        let mut status = "";
        let mut focused = "";
        let mut updated = 0u64;
        for line in raw.lines() {
            let Some((key, value)) = line.split_once('=') else { continue; };
            match key.trim() {
                "status" => status = value.trim(),
                "focused_package" => focused = value.trim(),
                "updated_wall_ms" => updated = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        if status != "ok"
            || focused.is_empty()
            || updated == 0
            || now == 0
            || now < updated
            || now - updated > FOREGROUND_TASK_MAX_AGE_MS
        {
            return JankForegroundState::Unavailable;
        }
        normalize_jank_package(focused)
            .map(JankForegroundState::Reliable)
            .unwrap_or(JankForegroundState::Unavailable)
    }

    fn read_command() -> io::Result<Option<String>> {
        const CLAIMED_FILE: &str = "/data/adb/modules/AppOpt/config/fps.cmd.processing";

        // 固定认领文件允许守护异常退出后继续处理，同时保证 App 在 FPS_CMD_FILE
        // 写入的新命令不会被消费旧命令时的 remove_file() 一并删掉。
        match fs::metadata(CLAIMED_FILE) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                match fs::rename(FPS_CMD_FILE, CLAIMED_FILE) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(err) => return Err(err),
                }
            }
            Err(err) => return Err(err),
        }

        let before = match fs::metadata(CLAIMED_FILE) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let bytes = match fs::read(CLAIMED_FILE) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let after = match fs::metadata(CLAIMED_FILE) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let stable = before.len() == after.len()
            && before.modified().ok() == after.modified().ok();
        if !stable {
            return Ok(None);
        }
        let text = String::from_utf8(bytes).ok().map(|text| text.trim().to_string());
        let valid = text.as_deref().is_some_and(|text| {
            text.starts_with("start ") || text == "stop" || text.starts_with("stop ")
        });
        if !valid {
            let stale = after
                .modified()
                .ok()
                .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                .is_some_and(|age| age >= Duration::from_secs(2));
            if stale {
                match fs::remove_file(CLAIMED_FILE) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err),
                }
            }
            return Ok(None);
        }
        match fs::remove_file(CLAIMED_FILE) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        Ok(text)
    }

    #[derive(Clone, Debug)]
    struct PidChoice {
        pid: i32,
        is_main: bool,
        source: String,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ForegroundHelperState {
        Target,
        Other,
        Unavailable,
    }

    fn wait_pkg_pid(pkg: &str, attempts: u32, delay: Duration) -> Option<PidChoice> {
        // 启动目标应用后给系统一点时间创建进程，
        // 前几轮不允许子进程兜底，避免刚启动就锁到 push/MSF 等非渲染进程。
        for _ in 0..attempts {
            if let Some(choice) = find_preferred_pkg_pid(pkg, false) {
                if pid_ready_for_ebpf(choice.pid, pkg) {
                    return Some(choice);
                }
            }
            if !delay.is_zero() {
                thread::sleep(delay);
            }
        }
        find_preferred_pkg_pid(pkg, true)
            .filter(|choice| pid_ready_for_ebpf(choice.pid, pkg))
    }

    fn find_top_app_pid(pkg: &str) -> Option<PidChoice> {
        let state = crate::app_top_state_check(pkg);
        if state.target_top_app && state.target_pid > 0 {
            return Some(PidChoice {
                pid: state.target_pid,
                is_main: state.target_pid_is_main,
                source: if state.target_pid_is_main {
                    "cgroup 前台组主进程".to_string()
                } else {
                    "cgroup 前台组子进程".to_string()
                },
            });
        }
        None
    }

    fn find_preferred_pkg_pid(pkg: &str, allow_child: bool) -> Option<PidChoice> {
        // 只在启动、停帧重锁定和低频前台 PID 纠偏时调用，不在每轮 FPS poll 全量扫。
        // 优先级：ActivityTaskManager helper -> 前台 cgroup -> 包名主进程 -> 子进程兜底。
        // helper 状态新鲜时具有否决权：它明确说前台不是目标包，就不再用后台进程兜底。
        match foreground_helper_state(pkg) {
            ForegroundHelperState::Target => {
                if let Some(mut choice) = find_top_app_pid(pkg) {
                    if allow_child || choice.is_main {
                        choice.source = format!("前台助手+{}", choice.source);
                        return Some(choice);
                    }
                }
                if let Some(choice) = find_pkg_cmdline_pid(pkg, allow_child, "前台助手+") {
                    return Some(choice);
                }
                return None;
            }
            ForegroundHelperState::Other => return None,
            ForegroundHelperState::Unavailable => {}
        }

        if let Some(choice) = find_top_app_pid(pkg) {
            if allow_child || choice.is_main {
                return Some(choice);
            }
        }

        find_pkg_cmdline_pid(pkg, allow_child, "")
    }

    fn pid_ready_for_ebpf(pid: i32, pkg: &str) -> bool {
        if pid <= 0 {
            return false;
        }
        let Ok(cmdline) = read_cmdline(pid) else {
            return false;
        };
        if cmdline != pkg
            && !cmdline
                .strip_prefix(pkg)
                .is_some_and(|rest| rest.starts_with(':'))
        {
            return false;
        }
        match fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(maps) => maps.lines().any(|line| line.contains("libgui.so")),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                // Android 17 开始，即使 Magisk Root 也可能被 procfs/SELinux 禁止读取
                // 其他应用的 maps。bridge 仍能用系统绝对路径附加 libgui，因此这里
                // 只确认进程至少有可枚举线程，并且设备存在可用的系统 libgui。
                fs::read_dir(format!("/proc/{pid}/task"))
                    .ok()
                    .and_then(|mut entries| entries.next())
                    .is_some()
                    && process_libgui_exists(pid)
            }
            Err(_) => false,
        }
    }

    fn process_libgui_exists(pid: i32) -> bool {
        let is_64_bit = (|| {
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
        })();
        let paths = match is_64_bit {
            Some(false) => ["/system/lib/libgui.so", "/system_ext/lib/libgui.so"].as_slice(),
            _ => [
                "/system/lib64/libgui.so",
                "/system_ext/lib64/libgui.so",
            ]
            .as_slice(),
        };
        paths.iter().any(|path| fs::metadata(path).is_ok())
    }

    fn collect_pkg_ebpf_pids(
        pkg: &str,
        known: &BTreeSet<i32>,
        allow_full_scan: bool,
    ) -> BTreeSet<i32> {
        // 常规刷新优先复用 daemon 已维护的 pid_cache.tsv，只对目标包候选做身份
        // 与 libgui 就绪检查。完整 /proc 遍历仅在缓存为空或低频恢复校验时执行。
        let mut candidates = process_index_find_package_pids(pkg).unwrap_or_default();
        for pid in known.iter().copied() {
            if read_cmdline(pid).ok().is_some_and(|cmdline| {
                cmdline == pkg
                    || cmdline
                        .strip_prefix(pkg)
                        .is_some_and(|suffix| suffix.starts_with(':'))
            }) {
                candidates.insert(pid);
            }
        }
        if let Some(choice) = find_foreground_pkg_hint(pkg) {
            candidates.insert(choice.pid);
        }
        if allow_full_scan || candidates.is_empty() {
            candidates.extend(scan_pkg_ebpf_pids(pkg));
        }
        candidates
            .into_iter()
            .filter(|pid| known.contains(pid) || pid_ready_for_ebpf(*pid, pkg))
            .collect()
    }

    fn find_foreground_pkg_hint(pkg: &str) -> Option<PidChoice> {
        // 高频目标集合刷新只读取 helper/cgroup，不在这里退回全 /proc。包名兜底由
        // pid_cache 和低频 scan_pkg_ebpf_pids 负责。
        match foreground_helper_state(pkg) {
            ForegroundHelperState::Target => find_top_app_pid(pkg).map(|mut choice| {
                choice.source = format!("前台助手+{}", choice.source);
                choice
            }),
            ForegroundHelperState::Other => None,
            ForegroundHelperState::Unavailable => find_top_app_pid(pkg),
        }
    }

    fn scan_pkg_ebpf_pids(pkg: &str) -> BTreeSet<i32> {
        let mut pids = BTreeSet::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return pids;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|text| text.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(cmdline) = read_cmdline(pid) else {
                continue;
            };
            let belongs_to_pkg = cmdline == pkg
                || cmdline
                    .strip_prefix(pkg)
                    .is_some_and(|suffix| suffix.starts_with(':'));
            if belongs_to_pkg && pid_ready_for_ebpf(pid, pkg) {
                pids.insert(pid);
            }
        }
        pids
    }

    fn find_pkg_cmdline_pid(pkg: &str, allow_child: bool, source_prefix: &str) -> Option<PidChoice> {
        let mut child_fallback = None;
        let entries = fs::read_dir("/proc").ok()?;
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|text| text.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(cmdline) = read_cmdline(pid) else {
                continue;
            };
            if cmdline == pkg {
                return Some(PidChoice {
                    pid,
                    is_main: true,
                    source: format!("{source_prefix}包名主进程"),
                });
            }
            if child_fallback.is_none()
                && cmdline
                    .strip_prefix(pkg)
                    .is_some_and(|rest| rest.starts_with(':'))
            {
                child_fallback = Some(PidChoice {
                    pid,
                    is_main: false,
                    source: format!("{source_prefix}包名子进程回退"),
                });
            }
        }
        if allow_child { child_fallback } else { None }
    }

    fn foreground_helper_state(pkg: &str) -> ForegroundHelperState {
        let Ok(raw) = fs::read_to_string(FOREGROUND_TASK_STATE_FILE) else {
            return ForegroundHelperState::Unavailable;
        };
        let mut status = "";
        let mut focused = "";
        let mut visible = "";
        let mut updated_wall_ms = 0u64;

        for line in raw.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "status" => status = value.trim(),
                "focused_package" => focused = value.trim(),
                "visible_packages" => visible = value.trim(),
                "updated_wall_ms" => updated_wall_ms = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        if status != "ok" {
            return ForegroundHelperState::Unavailable;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        if updated_wall_ms == 0
            || now_ms == 0
            || updated_wall_ms > now_ms
            || now_ms - updated_wall_ms > FOREGROUND_TASK_MAX_AGE_MS
        {
            return ForegroundHelperState::Unavailable;
        }
        if focused == pkg || visible.split(',').any(|item| item.trim() == pkg) {
            ForegroundHelperState::Target
        } else {
            ForegroundHelperState::Other
        }
    }

    fn read_cmdline(pid: i32) -> io::Result<String> {
        let data = fs::read(format!("/proc/{pid}/cmdline"))?;
        let first = data.split(|byte| *byte == 0).next().unwrap_or_default();
        Ok(String::from_utf8_lossy(first).trim().to_string())
    }

    fn write_fps_file(fps: f64) {
        let _ = fs::create_dir_all(FPS_OUT_DIR);
        let path = PathBuf::from(FPS_OUT_FILE);
        let fresh = !path.exists();
        if fs::write(&path, format!("{fps:.1}")).is_ok() && fresh {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o666));
            }
        }
    }
