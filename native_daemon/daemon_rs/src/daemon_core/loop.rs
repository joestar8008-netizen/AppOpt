// 常驻守护主循环。
//
// 这里负责把“规则文件 -> 扫描计划 -> 进程/线程命中 -> sched_setaffinity”串起来。
// 日常轮次优先使用 DaemonState.known_pids，并以数字 PID 快照发现新进程；只有配置变化、
// 健康观察或前台生命周期发现时才完整读取 /proc/<pid>。
//
// 这个文件只关心调度节奏和日志摘要，具体规则解析/扫描/绑核分别在 config.rs、scan.rs、
// affinity.rs 中实现。
fn daemon_loop(args: &Args) -> io::Result<()> {
    fs::create_dir_all(STATE_DIR)?;
    install_shutdown_handlers()?;
    println!("[RS] 启动 AppOpt Rust 守护 v{VERSION}");
    println!("[RS] 作者: suto & 一只小柒夏");
    println!("[RS] 配置文件: {}", args.config.display());
    println!("[RS] 包名 UID 映射: {}", args.uid_map.display());
    println!("[RS] 检查间隔: {} 秒", args.interval_secs);
    println!("[RS] cpuset 运行组: /dev/cpuset/{}", args.cpuset_name);
    println!(
        "[RS] 目标范围: {}",
        args.target_pkg.as_deref().unwrap_or("全部配置应用")
    );
    print_startup_device_info();
    calibration::print_version_diagnostics(VERSION);
    calibration::sync_policy_topology_for_runtime();

    let mut file_monitor = RuntimeFileMonitor::new(&args.config, &args.uid_map).ok();
    println!(
        "[RS] 配置文件监控模式: {}",
        if file_monitor.is_some() {
            "inotify 事件通知 + 60 秒内容校验"
        } else {
            "元数据变化轮询 + 内容指纹校验"
        }
    );
    if start_daemon_socket_thread() {
        println!("[RS] 启用守护进程验证 socket");
    }
    if calibration::start_calibration_thread(args.config.clone()) {
        println!("[RS] 启用自动校准线程");
    }
    let fps_thread = fps::start_fps_thread();
    if fps_thread.is_some() {
        println!("[RS] 启用真实帧率监测线程 (多进程 eBPF / SF fallback)");
    }
    let mut state = DaemonState::default();
    match load_managed_tid_journal(&args.cpuset_name) {
        Ok(load) => {
            if let Some(warning) = load.warning.as_deref() {
                eprintln!("[RS] {warning}");
            }
            if !load.entries.is_empty() {
                println!(
                    "[RS] 已续接上次守护进程的线程恢复基线: {} 条",
                    load.entries.len()
                );
            }
            state.managed_tids = load.entries;
            state.managed_tid_quarantine_before_starttime = load
                .quarantine_existing
                .then(managed_tid_starttime_cutoff);
            // 首轮强制重写一次，用于清理同一 boot 内已经退出的旧 TID，并把头部
            // cpuset 名称同步为本次配置。
            state.managed_tid_journal_dirty = true;
            state.managed_tid_journal_loaded = true;
        }
        Err(err) => {
            eprintln!("[RS] 线程恢复基线读取失败，本次仅接管可安全记录的新线程: {err}");
        }
    }
    let mut runtime = RuntimeInputsCache::default();
    let mut file_changes = RuntimeFileChanges::all();

    while !shutdown_requested() {
        if let Err(err) = run_daemon_round(
            args,
            &mut state,
            &mut runtime,
            file_changes,
            file_monitor.is_some(),
        ) {
            eprintln!("[RS] 守护轮询失败: {err}");
        }
        if shutdown_requested() {
            break;
        }
        if let Err(err) = wait_for_daemon_wake(
            file_monitor.as_ref(),
            regular_scan_wait_timeout(args.interval_secs, &state),
        ) {
            eprintln!("[RS] 守护事件等待失败，本轮退回定时检查: {err}");
            thread::sleep(Duration::from_secs(args.interval_secs));
        }
        file_changes = match file_monitor.as_mut().map(RuntimeFileMonitor::drain) {
            Some(Ok(changes)) => changes,
            Some(Err(err)) => {
                eprintln!("[RS] inotify 读取失败，已转为元数据轮询: {err}");
                file_monitor = None;
                RuntimeFileChanges::all()
            }
            None => RuntimeFileChanges::default(),
        };
        if file_changes.monitor_invalidated {
            file_monitor = RuntimeFileMonitor::new(&args.config, &args.uid_map).ok();
            if file_monitor.is_none() {
                eprintln!("[RS] inotify 监听已失效，后续使用元数据轮询");
            }
        }
    }

    if let Some(thread) = fps_thread {
        if thread.join().is_err() {
            eprintln!("[FPS] 帧率监测线程退出时发生 panic");
        }
    }
    let (restored, pending) = restore_all_managed_tids(&mut state.managed_tids, &args.cpuset_name);
    state.managed_tid_journal_dirty = true;
    if let Err(err) = sync_managed_tid_journal(&mut state, &args.cpuset_name, true) {
        eprintln!("[RS] 守护退出时保存待恢复线程失败: {err}");
    }
    println!(
        "[RS] 守护进程已停止: 已恢复线程={} 待下次重试={}",
        restored, pending
    );
    Ok(())
}

fn wait_for_daemon_wake(
    file_monitor: Option<&RuntimeFileMonitor>,
    timeout: Duration,
) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let Some(monitor) = file_monitor else {
            thread::sleep(timeout);
            return Ok(());
        };
        let mut poll_fd = libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = file_monitor;
        thread::sleep(timeout);
        Ok(())
    }
}

// 启动时输出设备诊断，便于用户反馈日志时确认运行环境。
fn print_startup_device_info() {
    let properties = read_android_properties();
    let android_version = first_property(
        &properties,
        &[
            "ro.build.version.release",
            "ro.system.build.version.release",
        ],
    );
    let api_level = first_property(
        &properties,
        &["ro.build.version.sdk", "ro.system.build.version.sdk"],
    );
    if let Some(version) = android_version {
        if let Some(api) = api_level {
            println!("Android 版本: {version} (API {api})");
        } else {
            println!("Android 版本: {version}");
        }
    }

    let brand = first_property(
        &properties,
        &[
            "ro.product.brand",
            "ro.product.system.brand",
            "ro.product.vendor.brand",
            "ro.product.odm.brand",
            "ro.product.product.brand",
        ],
    );
    let market_model = first_property(
        &properties,
        &[
            "ro.product.marketname",
            "ro.product.vendor.marketname",
            "ro.product.odm.marketname",
            "ro.product.system.marketname",
            "ro.product.product.marketname",
            "ro.vendor.product.marketname",
            "ro.config.marketing_name",
            "ro.vendor.oplus.market.name",
            "ro.oplus.market.name",
        ],
    );
    let certified_model = first_property(
        &properties,
        &[
            "ro.product.model",
            "ro.product.vendor.model",
            "ro.product.odm.model",
            "ro.product.system.model",
            "ro.product.product.model",
        ],
    );
    if let Some(brand) = brand {
        if let Some(model) = market_model.or(certified_model) {
            println!("设备品牌: {brand} {model}");
        } else {
            println!("设备品牌: {brand}");
        }
    } else if let Some(model) = market_model.or(certified_model) {
        println!("设备型号: {model}");
    }

    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let release = release.trim();
        if !release.is_empty() {
            println!("内核版本: Linux {release}");
        }
    }
}

fn read_android_properties() -> HashMap<String, String> {
    let output = Command::new("/system/bin/getprop")
        .output()
        .or_else(|_| Command::new("getprop").output());
    let Ok(output) = output else {
        return HashMap::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut properties = HashMap::new();
    for line in text.lines() {
        let Some(separator) = line.find("]: [") else {
            continue;
        };
        if !line.starts_with('[') {
            continue;
        }
        let key = &line[1..separator];
        let value = line[separator + 4..].strip_suffix(']').unwrap_or(&line[separator + 4..]);
        if !key.is_empty() && !value.is_empty() {
            properties.insert(key.to_string(), value.to_string());
        }
    }
    properties
}

fn first_property<'a>(properties: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| properties.get(*key).map(String::as_str))
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Default)]
struct ProcessIndexRound {
    view: ProcessIndexView,
}

fn pid_snapshot_interval_ms(state: &DaemonState) -> u64 {
    if state.interactive {
        PID_SNAPSHOT_ACTIVE_MS
    } else {
        PID_SNAPSHOT_IDLE_MS
    }
}

fn update_interactive_mode(state: &mut DaemonState, observed: Option<bool>) {
    if let Some(interactive) = observed {
        state.interactive = interactive;
        state.interactive_known = true;
    } else if !state.interactive_known {
        state.interactive = true;
    }
}

fn regular_scan_interval_ms(interval_secs: u64, interactive: bool) -> u64 {
    if interactive {
        interval_secs.max(1).saturating_mul(1000)
    } else {
        SCREEN_OFF_SCAN_INTERVAL_MS
    }
}

fn regular_scan_due(interval_secs: u64, state: &DaemonState, now_elapsed: u64) -> bool {
    let interval = regular_scan_interval_ms(interval_secs, state.interactive);
    state.last_regular_scan_elapsed_ms.is_none_or(|last| {
        now_elapsed < last || now_elapsed.saturating_sub(last) >= interval
    })
}

fn periodic_full_scan_due(state: &DaemonState, now_elapsed: u64) -> bool {
    let interval = if state.interactive {
        ACTIVE_FULL_SCAN_INTERVAL_MS
    } else {
        SCREEN_OFF_FULL_SCAN_INTERVAL_MS
    };
    state.last_full_scan_elapsed_ms.is_none_or(|last| {
        now_elapsed < last || now_elapsed.saturating_sub(last) >= interval
    })
}

fn regular_scan_wait_timeout(interval_secs: u64, state: &DaemonState) -> Duration {
    let interval = regular_scan_interval_ms(interval_secs, state.interactive);
    let now_elapsed = elapsed_realtime_ms();
    // 首轮尚未建立扫描截止时间时仍保留配置间隔，避免配置读取失败后立即忙循环重试。
    let remaining = state.last_regular_scan_elapsed_ms.map_or(interval, |last| {
        if now_elapsed < last {
            0
        } else {
            interval.saturating_sub(now_elapsed.saturating_sub(last))
        }
    });
    Duration::from_millis(remaining)
}

fn pid_snapshot_log_due(state: &mut DaemonState, now_elapsed: u64) -> bool {
    let due = state.last_pid_snapshot_log_elapsed_ms.is_none_or(|last| {
        now_elapsed >= last
            && now_elapsed.saturating_sub(last) >= PID_SNAPSHOT_LOG_INTERVAL_MS
    });
    if due {
        state.last_pid_snapshot_log_elapsed_ms = Some(now_elapsed);
    }
    due
}

fn prepare_process_index_round(
    state: &mut DaemonState,
    now_elapsed: u64,
    force: bool,
    rebuild_all: bool,
) -> io::Result<ProcessIndexRound> {
    let interval = pid_snapshot_interval_ms(state);
    let due = force
        || !state.process_index_initialized
        || state.last_pid_snapshot_elapsed_ms.is_none_or(|last| {
            now_elapsed >= last && now_elapsed.saturating_sub(last) >= interval
    });
    let view = if due {
        refresh_process_index(
            &mut state.process_index,
            now_elapsed,
            rebuild_all || !state.process_index_initialized,
        )?
    } else if state.process_index_has_candidates {
        match load_process_index_view(&mut state.process_index, now_elapsed) {
            Ok(view) => view,
            Err(_) => refresh_process_index(&mut state.process_index, now_elapsed, true)?,
        }
    } else {
        ProcessIndexView::default()
    };
    let round = ProcessIndexRound { view };
    if round.view.refreshed {
        if !state.process_index_initialized {
            state.process_index_initialized = true;
        }
        state.last_pid_snapshot_elapsed_ms = Some(now_elapsed);
    }
    if round.view.loaded {
        state.process_index_has_candidates = !round.view.candidate_pids.is_empty();
        state
            .known_pids
            .retain(|pid| round.view.current_pids.contains(pid));
    }
    Ok(round)
}

fn merge_candidate_hits(
    scan_result: &mut ProcScanResult,
    candidate_result: CandidateScanResult,
    state: &mut DaemonState,
) {
    for pid in candidate_result.gone_pids {
        state.known_pids.remove(&pid);
        state.process_scan_stamps.remove(&pid);
    }
    for hit in candidate_result.hits {
        let pid = hit.pid;
        state.known_pids.insert(pid);
        if !hit.health_scan_complete {
            if let Some(pkg) = base_package(&hit.cmdline) {
                scan_result
                    .health_incomplete_packages
                    .insert(pkg.to_string());
            }
        }
        if let Some(existing) = scan_result.hits.iter_mut().find(|item| item.pid == pid) {
            *existing = hit;
        } else {
            scan_result.hits.push(hit);
        }
    }
}

fn merge_proc_scan_result(
    target: &mut ProcScanResult,
    incoming: ProcScanResult,
    state: &mut DaemonState,
) {
    target.complete &= incoming.complete;
    target
        .health_incomplete_packages
        .extend(incoming.health_incomplete_packages);
    for hit in incoming.hits {
        state.known_pids.insert(hit.pid);
        if let Some(existing) = target.hits.iter_mut().find(|item| item.pid == hit.pid) {
            *existing = hit;
        } else {
            target.hits.push(hit);
        }
    }
}

fn refresh_managed_tid_cache(
    state: &mut DaemonState,
    hits: &[ProcHit],
    reconcile_all: bool,
    cpuset_name: &str,
) -> bool {
    let seen_round = state.round_index.saturating_add(1);
    let mut journal_changed = false;
    let observed = hits
        .iter()
        .flat_map(|hit| {
            hit.actions
                .iter()
                .map(move |action| {
                    (
                        action.tid,
                        (hit.pid, hit.pid_starttime, action.tid_starttime),
                    )
                })
        })
        .collect::<HashMap<_, _>>();
    let complete_tgids = hits
        .iter()
        .filter(|hit| hit.health_scan_complete)
        .map(|hit| hit.pid)
        .collect::<HashSet<_>>();
    let removed = state
        .managed_tids
        .iter()
        .filter(|(tid, entry)| {
            let observation = observed.get(tid);
            let still_observed = observation.is_some_and(|observation| {
                managed_identity_matches_observation(entry, *observation)
            });
            let confirmed_reuse = observation.is_some_and(|observation| {
                managed_identity_conflicts_with_observation(entry, *observation)
            });
            !still_observed
                && (confirmed_reuse
                    || entry.restore_pending
                    || reconcile_all
                    || complete_tgids.contains(&entry.tgid)
                    || !state.known_pids.contains(&entry.tgid))
        })
        .map(|(tid, entry)| (*tid, entry.clone()))
        .collect::<Vec<_>>();
    let mut restore_retries = 0usize;
    let mut restore_giveups = 0usize;
    for (tid, entry) in removed {
        match restore_managed_tid(tid, &entry, cpuset_name) {
            Ok(()) => {
                journal_changed |= state.managed_tids.remove(&tid).is_some();
            }
            Err(err) if is_thread_gone_error(&err) => {
                journal_changed |= state.managed_tids.remove(&tid).is_some();
            }
            Err(err) => {
                if entry.restore_pending {
                    // ROM 已经连续两次拒绝恢复。继续把同一条记录放回队列只会每
                    // 轮重复 sched_setaffinity，并不能让已变窄的 cpuset 变宽。
                    // 到这里保留线程当前的系统状态，丢弃旧基线，等待下次重新
                    // 命中规则时重新捕获真实基线。
                    if restore_giveups < MAX_ERROR_DETAILS_PER_ROUND {
                        eprintln!(
                            "[RS] 规则移除后恢复未完成，已停止重试 进程={} 线程={} 错误={}",
                            entry.tgid,
                            tid,
                            error_text_zh(&err)
                        );
                    }
                    restore_giveups = restore_giveups.saturating_add(1);
                    journal_changed |= state.managed_tids.remove(&tid).is_some();
                } else {
                    if restore_retries < MAX_ERROR_DETAILS_PER_ROUND {
                        eprintln!(
                            "[RS] 规则移除后恢复线程状态失败，将延迟重试一次 进程={} 线程={} 错误={}",
                            entry.tgid,
                            tid,
                            error_text_zh(&err)
                        );
                    }
                    restore_retries = restore_retries.saturating_add(1);
                    if let Some(pending) = state.managed_tids.get_mut(&tid) {
                        pending.restore_pending = true;
                        pending.desired_mask_low64 = None;
                        pending.verified_mask_low64 = None;
                        pending.cpuset_synced = false;
                        pending.next_affinity_check_elapsed_ms = 0;
                    }
                }
            }
        }
    }
    if restore_retries > MAX_ERROR_DETAILS_PER_ROUND {
        eprintln!(
            "[RS] 规则移除后恢复线程状态失败: 本轮共 {} 条将延迟重试一次, 仅显示前 {} 条明细",
            restore_retries, MAX_ERROR_DETAILS_PER_ROUND
        );
    }
    if restore_giveups > MAX_ERROR_DETAILS_PER_ROUND {
        eprintln!(
            "[RS] 规则移除后恢复未完成: {} 条已停止重试，仅显示前 {} 条",
            restore_giveups, MAX_ERROR_DETAILS_PER_ROUND
        );
    }

    let quarantine_before_starttime = state.managed_tid_quarantine_before_starttime;
    let managed_tids = &mut state.managed_tids;
    let mut capacity_skips = 0usize;

    for hit in hits {
        for action in &hit.actions {
            let cached = managed_tids.get(&action.tid).cloned().filter(|current| {
                managed_identity_matches_observation(
                    current,
                    (hit.pid, hit.pid_starttime, action.tid_starttime),
                )
            });
            if managed_tid_identity_quarantined(
                cached.is_some(),
                action.tid_starttime,
                quarantine_before_starttime,
            ) {
                continue;
            }
            if cached.is_none() && managed_tids.contains_key(&action.tid) {
                // 同一个数值 TID 仍有无法确认身份的旧恢复记录时，先保留旧记录等待
                // 完整扫描或身份复核，不能用新观察覆盖唯一基线。
                continue;
            }
            if hit.pid_starttime.is_none() || action.tid_starttime.is_none() {
                // starttime 是防 PID/TID 复用的唯一稳定身份。瞬时读不到时只续期已有
                // 记录，绝不能把当前已受控状态重新当成“接管前基线”。
                if let Some(current) = managed_tids.get_mut(&action.tid).filter(|current| {
                    managed_identity_matches_observation(
                        current,
                        (hit.pid, hit.pid_starttime, action.tid_starttime),
                    )
                }) {
                    current.last_seen_round = seen_round;
                }
                continue;
            }
            if cached.is_none() && !managed_tid_capacity_available(managed_tids, action.tid) {
                // 达到保护上限后宁可暂缓新线程，也不能丢弃仍在使用的恢复基线。
                // 下一轮旧线程退出或规则移除后会自然释放容量。
                capacity_skips = capacity_skips.saturating_add(1);
                continue;
            }
            let next_mask_low64 = CpuMask::parse(&action.cpus).and_then(|mask| mask.to_low64());
            let cpuset_synced = cached.as_ref().is_some_and(|current| {
                current.tgid == hit.pid && current.starttime == action.tid_starttime &&
                    current.cpuset_synced && current.desired_mask_low64 == next_mask_low64
            });
            let restore_state = cached.as_ref().map(|current| {
                (
                    current.original_mask_low64,
                    current.original_cpuset.clone(),
                )
            }).or_else(|| capture_tid_restore_state(hit, action, cpuset_name));
            let Some((original_mask_low64, original_cpuset)) = restore_state else {
                // 无法可靠记录恢复基线时不把该线程纳入 managed_tids；apply 阶段也会
                // 因缺少受管记录而跳过，避免产生无法回滚的半接管状态。
                continue;
            };
            let next = ManagedTidEntry {
                tgid: hit.pid,
                tgid_starttime: hit.pid_starttime,
                starttime: action.tid_starttime,
                last_seen_round: seen_round,
                cpuset_synced,
                cpuset_failure_count: cached
                    .as_ref()
                    .map_or(0, |current| current.cpuset_failure_count),
                cpuset_retry_after_elapsed_ms: cached
                    .as_ref()
                    .map_or(0, |current| current.cpuset_retry_after_elapsed_ms),
                desired_mask_low64: cached
                    .as_ref()
                    .and_then(|current| current.desired_mask_low64),
                verified_mask_low64: cached
                    .as_ref()
                    .and_then(|current| current.verified_mask_low64),
                last_affinity_check_elapsed_ms: cached
                    .as_ref()
                    .map_or(0, |current| current.last_affinity_check_elapsed_ms),
                next_affinity_check_elapsed_ms: cached
                    .as_ref()
                    .map_or(0, |current| current.next_affinity_check_elapsed_ms),
                original_mask_low64,
                original_cpuset,
                restore_persisted: cached
                    .as_ref()
                    .is_some_and(|current| current.restore_persisted),
                restore_pending: false,
            };
            let should_update = managed_tids
                .get(&action.tid)
                .is_none_or(|current| {
                    current.tgid != next.tgid
                        || current.tgid_starttime != next.tgid_starttime
                        || current.starttime != next.starttime
                });
            if should_update {
                managed_tids.insert(action.tid, next);
                journal_changed = true;
            } else if let Some(current) = managed_tids.get_mut(&action.tid) {
                current.last_seen_round = seen_round;
                current.restore_pending = false;
            }
        }
    }

    if capacity_skips > 0 {
        eprintln!(
            "[RS] 受管线程已达到安全上限 {}，本轮暂缓接管 {} 个新线程",
            MAX_MANAGED_TIDS, capacity_skips
        );
    }
    journal_changed
}

fn managed_identity_matches_observation(
    entry: &ManagedTidEntry,
    observation: (i32, Option<u64>, Option<u64>),
) -> bool {
    let (tgid, tgid_starttime, tid_starttime) = observation;
    entry.tgid == tgid
        && tgid_starttime.is_none_or(|value| entry.tgid_starttime == Some(value))
        && tid_starttime.is_none_or(|value| entry.starttime == Some(value))
}

fn managed_identity_conflicts_with_observation(
    entry: &ManagedTidEntry,
    observation: (i32, Option<u64>, Option<u64>),
) -> bool {
    let (tgid, tgid_starttime, tid_starttime) = observation;
    entry.tgid != tgid
        || tgid_starttime.is_some_and(|value| entry.tgid_starttime.is_some_and(|old| old != value))
        || tid_starttime.is_some_and(|value| entry.starttime.is_some_and(|old| old != value))
}

fn managed_tid_capacity_available(
    managed_tids: &HashMap<i32, ManagedTidEntry>,
    tid: i32,
) -> bool {
    managed_tids.contains_key(&tid) || managed_tids.len() < MAX_MANAGED_TIDS
}

fn managed_tid_identity_quarantined(
    has_persisted_entry: bool,
    tid_starttime: Option<u64>,
    cutoff: Option<u64>,
) -> bool {
    !has_persisted_entry
        && tid_starttime.is_some_and(|starttime| cutoff.is_some_and(|cutoff| starttime <= cutoff))
}

fn ensure_managed_tid_journal_loaded(
    state: &mut DaemonState,
    cpuset_name: &str,
) -> io::Result<()> {
    if state.managed_tid_journal_loaded {
        return Ok(());
    }
    let load = load_managed_tid_journal(cpuset_name)?;
    if let Some(warning) = load.warning.as_deref() {
        eprintln!("[RS] {warning}");
    }
    state.managed_tids = load.entries;
    state.managed_tid_quarantine_before_starttime = load
        .quarantine_existing
        .then(managed_tid_starttime_cutoff);
    state.managed_tid_journal_dirty = true;
    state.managed_tid_journal_loaded = true;
    Ok(())
}

#[derive(Debug, Default)]
struct ManagedTidJournalLoad {
    entries: HashMap<i32, ManagedTidEntry>,
    quarantine_existing: bool,
    warning: Option<String>,
}

fn load_managed_tid_journal(cpuset_name: &str) -> io::Result<ManagedTidJournalLoad> {
    let content = match fs::read_to_string(MANAGED_TID_STATE_FILE) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(ManagedTidJournalLoad::default());
        }
        Err(err) => return Err(err),
    };
    let boot_id = read_managed_tid_boot_id()?;
    let load = decode_managed_tid_journal(&content, &boot_id, cpuset_name);
    if load.quarantine_existing {
        isolate_corrupt_managed_tid_journal();
    }
    Ok(load)
}

fn decode_managed_tid_journal(
    content: &str,
    current_boot_id: &str,
    cpuset_name: &str,
) -> ManagedTidJournalLoad {
    match parse_managed_tid_journal(content, current_boot_id, cpuset_name) {
        Ok(entries) => ManagedTidJournalLoad {
            entries,
            ..ManagedTidJournalLoad::default()
        },
        Err(err) => ManagedTidJournalLoad {
            entries: HashMap::new(),
            quarantine_existing: true,
            warning: Some(format!(
                "线程恢复基线已损坏并隔离；当前存活线程等待身份更新后再接管: {err}"
            )),
        },
    }
}

fn isolate_corrupt_managed_tid_journal() {
    let quarantine = format!(
        "{MANAGED_TID_STATE_FILE}.corrupt.{}",
        std::process::id()
    );
    let _ = fs::rename(MANAGED_TID_STATE_FILE, quarantine);
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn managed_tid_starttime_cutoff() -> u64 {
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return u64::MAX;
    }
    let ticks_per_second = ticks_per_second as u64;
    let uptime_ticks = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|seconds| (seconds * ticks_per_second as f64) as u64)
        .unwrap_or_else(|| {
            elapsed_realtime_ms()
                .saturating_mul(ticks_per_second)
                .saturating_div(1000)
        });
    uptime_ticks
        // 给 journal 隔离与首轮扫描之间的竞态留一秒余量。
        .saturating_add(ticks_per_second)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn managed_tid_starttime_cutoff() -> u64 {
    u64::MAX
}

fn parse_managed_tid_journal(
    content: &str,
    current_boot_id: &str,
    cpuset_name: &str,
) -> io::Result<HashMap<i32, ManagedTidEntry>> {
    let mut lines = content.lines();
    let header = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "线程恢复基线缺少头部")
    })?;
    let mut header_fields = header.split('\t');
    if header_fields.next() != Some(MANAGED_TID_STATE_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "线程恢复基线版本不兼容",
        ));
    }
    let stored_boot_id = header_fields.next().unwrap_or_default();
    if stored_boot_id.is_empty() || current_boot_id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "线程恢复基线缺少 boot_id",
        ));
    }
    if stored_boot_id != current_boot_id {
        // TID/starttime 只在同一启动周期内有意义；跨重启状态绝不能用于恢复新线程。
        return Ok(HashMap::new());
    }
    let stored_cpuset_name = header_fields.next().unwrap_or_default();
    if stored_cpuset_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "线程恢复基线缺少 cpuset 名称",
        ));
    }

    let mut managed_tids = HashMap::new();
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("线程恢复基线第 {} 行字段数量错误", line_index + 2),
            ));
        }
        let parse_number = |value: &str, field: &str| -> io::Result<u64> {
            value.parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("线程恢复基线第 {} 行 {field} 无效", line_index + 2),
                )
            })
        };
        let tid_raw = parse_number(fields[0], "TID")?;
        let tgid_raw = parse_number(fields[1], "TGID")?;
        if tid_raw == 0 || tgid_raw == 0 || tid_raw > i32::MAX as u64 || tgid_raw > i32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("线程恢复基线第 {} 行进程身份无效", line_index + 2),
            ));
        }
        let tid = tid_raw as i32;
        let tgid = tgid_raw as i32;
        let tgid_starttime = parse_number(fields[2], "TGID starttime")?;
        let tid_starttime = parse_number(fields[3], "TID starttime")?;
        let original_mask_low64 = if fields[4] == "-" {
            None
        } else {
            Some(u64::from_str_radix(fields[4], 16).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("线程恢复基线第 {} 行 affinity 无效", line_index + 2),
                )
            })?)
            .filter(|mask| *mask != 0)
        };
        let original_cpuset = decode_managed_tid_cpuset(fields[5]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("线程恢复基线第 {} 行 cpuset 无效", line_index + 2),
            )
        })?;
        if original_mask_low64.is_none() && original_cpuset.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("线程恢复基线第 {} 行没有可恢复状态", line_index + 2),
            ));
        }
        let entry = ManagedTidEntry {
            tgid,
            tgid_starttime: Some(tgid_starttime),
            starttime: Some(tid_starttime),
            last_seen_round: 0,
            cpuset_synced: false,
            cpuset_failure_count: 0,
            cpuset_retry_after_elapsed_ms: 0,
            desired_mask_low64: None,
            verified_mask_low64: None,
            last_affinity_check_elapsed_ms: 0,
            next_affinity_check_elapsed_ms: 0,
            original_mask_low64,
            original_cpuset,
            restore_persisted: true,
            restore_pending: false,
        };
        if !managed_tids.contains_key(&tid) && managed_tids.len() >= MAX_MANAGED_TIDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "线程恢复基线超过安全上限",
            ));
        }
        managed_tids.insert(tid, entry);
    }

    // cpuset 名称变化不影响已保存的原 cpuset/affinity；新一轮接管会使用当前名称。
    let _ = (stored_cpuset_name, cpuset_name);
    Ok(managed_tids)
}

fn sync_managed_tid_journal(
    state: &mut DaemonState,
    cpuset_name: &str,
    force: bool,
) -> io::Result<()> {
    if !state.managed_tid_journal_loaded {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "线程恢复基线尚未成功读取",
        ));
    }
    if !force && !state.managed_tid_journal_dirty {
        return Ok(());
    }

    if state.managed_tids.is_empty() {
        match fs::remove_file(MANAGED_TID_STATE_FILE) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        state.managed_tid_journal_dirty = false;
        return Ok(());
    }

    let boot_id = read_managed_tid_boot_id()?;
    let content = serialize_managed_tid_journal(&state.managed_tids, &boot_id, cpuset_name);
    fs::create_dir_all(STATE_DIR)?;
    write_managed_tid_journal_file(Path::new(MANAGED_TID_STATE_FILE), &content)?;
    for entry in state.managed_tids.values_mut() {
        entry.restore_persisted = true;
    }
    state.managed_tid_journal_dirty = false;
    Ok(())
}

fn write_managed_tid_journal_file(path: &Path, content: &str) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let commit_result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if let Err(err) = commit_result {
        let _ = fs::remove_file(&temporary);
        return Err(err);
    }
    Ok(())
}

fn serialize_managed_tid_journal(
    managed_tids: &HashMap<i32, ManagedTidEntry>,
    boot_id: &str,
    cpuset_name: &str,
) -> String {
    let mut rows = managed_tids.iter().collect::<Vec<_>>();
    rows.sort_unstable_by_key(|(tid, _)| **tid);
    let mut output = format!("{MANAGED_TID_STATE_MAGIC}\t{boot_id}\t{cpuset_name}\n");
    for (tid, entry) in rows {
        let (Some(tgid_starttime), Some(tid_starttime)) =
            (entry.tgid_starttime, entry.starttime)
        else {
            continue;
        };
        if entry.original_mask_low64.is_none() && entry.original_cpuset.is_none() {
            continue;
        }
        let mask = entry
            .original_mask_low64
            .filter(|mask| *mask != 0)
            .map_or_else(|| "-".to_string(), |mask| format!("{mask:016x}"));
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            tid,
            entry.tgid,
            tgid_starttime,
            tid_starttime,
            mask,
            encode_managed_tid_cpuset(entry.original_cpuset.as_deref())
        ));
    }
    output
}

fn read_managed_tid_boot_id() -> io::Result<String> {
    fs::read_to_string(BOOT_ID_FILE)
        .map(|value| value.trim().to_string())
        .and_then(|value| {
            if value.is_empty() {
                Err(io::Error::new(io::ErrorKind::InvalidData, "无法读取 boot_id"))
            } else {
                Ok(value)
            }
        })
}

fn encode_managed_tid_cpuset(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "-".to_string();
    };
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_managed_tid_cpuset(value: &str) -> Option<Option<String>> {
    if value == "-" {
        return Some(None);
    }
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    let cpuset = String::from_utf8(bytes).ok()?;
    valid_cpuset_relative_path(&cpuset).then_some(Some(cpuset))
}

fn restore_all_managed_tids(
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    cpuset_name: &str,
) -> (usize, usize) {
    let entries = managed_tids
        .iter()
        .map(|(tid, entry)| (*tid, entry.clone()))
        .collect::<Vec<_>>();
    let mut restored = 0usize;
    let mut failures = 0usize;
    for (tid, entry) in entries {
        match restore_managed_tid(tid, &entry, cpuset_name) {
            Ok(()) => {
                managed_tids.remove(&tid);
                restored = restored.saturating_add(1);
            }
            Err(err) if is_thread_gone_error(&err) => {
                managed_tids.remove(&tid);
            }
            Err(err) => {
                failures = failures.saturating_add(1);
                if failures <= MAX_ERROR_DETAILS_PER_ROUND {
                    eprintln!(
                        "[RS] 守护退出恢复线程失败 进程={} 线程={} 错误={}",
                        entry.tgid,
                        tid,
                        error_text_zh(&err)
                    );
                }
            }
        }
    }
    if failures > MAX_ERROR_DETAILS_PER_ROUND {
        eprintln!(
            "[RS] 守护退出恢复线程失败: 共 {} 条，仅显示前 {} 条",
            failures, MAX_ERROR_DETAILS_PER_ROUND
        );
    }
    (restored, managed_tids.len())
}

fn run_daemon_round(
    args: &Args,
    state: &mut DaemonState,
    runtime: &mut RuntimeInputsCache,
    file_changes: RuntimeFileChanges,
    monitor_active: bool,
) -> io::Result<()> {
    let round_start = Instant::now();
    ensure_managed_tid_journal_loaded(state, &args.cpuset_name)?;
    if let Err(err) = ensure_rule_health_loaded(state) {
        eprintln!("[RS] 规则健康状态读取失败，本轮不禁用任何规则: {err}");
    }
    let reset_rule_health_packages = match consume_rule_health_reset_request(state) {
        Ok(packages) => packages,
        Err(err) => {
            eprintln!("[RS] 规则健康重新检测请求处理失败，将保留请求重试: {err}");
            BTreeSet::new()
        }
    };
    let rule_health_reset = !reset_rule_health_packages.is_empty();
    let scan_clock = elapsed_realtime_ms();
    let foreground_state = read_rule_health_foreground_state(scan_clock);
    // helper 首次启动或状态文件尚未写完时保守按亮屏处理；一旦拿到过可信值，
    // helper 短暂过期期间沿用最后状态，避免息屏被误判为亮屏而恢复 2 秒扫描。
    update_interactive_mode(state, foreground_state.interactive);
    let focused_package = (state.interactive
        && foreground_state.reliable
        && foreground_state.observable
        && !foreground_state.focused_package.is_empty())
        .then(|| foreground_state.focused_package.clone());
    let regular_scan_due = regular_scan_due(args.interval_secs, state, scan_clock);
    let refresh = runtime.refresh(
        args,
        state,
        file_changes,
        monitor_active,
        scan_clock,
    )?;
    if refresh.index_rebuilt {
        // 规则健康停用/恢复不会改变配置文件指纹，但动作集合已经变化。清掉线程
        // 指纹快路径，确保本轮真实重建 actions，并能恢复刚失去规则的线程。
        state.process_scan_stamps.clear();
    }
    let rules = &runtime.rules;
    let uid_map = &runtime.uid_map;
    let index = &runtime.index;
    let plan = &index.plan;
    let config_key = runtime.config_key.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "配置文件没有可用内容指纹")
    })?;
    let uid_key = runtime.uid_map_key;
    let rule_config_changed = state.last_config_key != Some(config_key);
    let config_changed = rule_config_changed || state.last_uid_map_key != uid_key;
    if config_changed {
        log_config_summary(rules, uid_map, plan);
    }
    if rule_config_changed {
        for rule_line in disabled_rule_health_lines(rules, state) {
            println!("[RS] 规则健康已停用: {rule_line}");
        }
    }
    let cache_uninitialized = !state.proc_scan_initialized;
    if !regular_scan_due && !config_changed && !cache_uninitialized && !rule_health_reset {
        return Ok(());
    }

    // 配置变化或固定周期到期都算一次常规轮次；inotify 提前唤醒不会改变扫描节奏。
    state.last_regular_scan_elapsed_ms = Some(scan_clock);

    let proc_total = system_process_count();
    let proc_count_grew = matches!(
        (state.last_proc_total, proc_total),
        (Some(last), Some(current)) if current > last
    );
    let growth_hint_allowed = state.last_proc_growth_scan_elapsed_ms.is_none_or(|last| {
        scan_clock >= last && scan_clock.saturating_sub(last) >= PID_GROWTH_HINT_MIN_MS
    });
    if proc_count_grew && growth_hint_allowed {
        state.proc_growth_scan_pending = true;
    }
    let full_scan_retry_pending = state.last_full_scan_attempt_elapsed_ms.is_some();
    let full_scan_retry_allowed = state
        .last_full_scan_attempt_elapsed_ms
        .is_none_or(|last| {
            scan_clock >= last
                && scan_clock.saturating_sub(last) >= RULE_HEALTH_FULL_SCAN_RETRY_MS
        });
    let health_scan_packages = rule_health_scan_due_packages(state);
    let foreground_discovery_pkg = foreground_discovery_scan_due(
        args.target_pkg.as_deref(),
        &plan.all_pkgs,
        state,
        &foreground_state,
        scan_clock,
    );
    let mut targeted_scan_packages = health_scan_packages.clone();
    targeted_scan_packages.extend(reset_rule_health_packages.iter().cloned());
    if let Some(pkg) = &foreground_discovery_pkg {
        targeted_scan_packages.insert(pkg.clone());
    }
    let periodic_full_scan_due = periodic_full_scan_due(state, scan_clock);

    // Rust 版的核心优化点：
    // - 配置刚变化时必须全量扫，因为规则目标可能完全变了。
    // - 第一次启动时必须全量扫；全扫结果为空后也视为缓存已经初始化。
    // - 系统进程数增长只要求立即刷新轻量 PID 快照，不再因此全量读取 cmdline。
    // - 规则健康和前台生命周期只扫描对应包；PID 快照和短期候选复查覆盖日常进程变化。
    // - 已知进程按 10/30 秒节奏校验
    //   TID 指纹，集合未变化时不读取全部线程名和 affinity。
    // - 已确认空结果不会每轮重扫；新进程由 PID 快照差集和短期复查发现。
    let full_scan = config_changed
        || cache_uninitialized
        || ((full_scan_retry_pending || periodic_full_scan_due) && full_scan_retry_allowed);
    let mut scan_reason = if config_changed {
        "配置变更"
    } else if cache_uninitialized {
        "初始扫描"
    } else if rule_health_reset {
        "规则健康重新检测"
    } else if full_scan_retry_pending && full_scan {
        "不完整全扫重试"
    } else if periodic_full_scan_due && full_scan {
        if state.interactive {
            "亮屏周期恢复扫描"
        } else {
            "息屏周期恢复扫描"
        }
    } else if !health_scan_packages.is_empty() {
        "健康观察包级复核"
    } else if foreground_discovery_pkg.is_some() {
        "前台生命周期包级发现"
    } else {
        "PID缓存"
    };
    let scan_started = Instant::now();
    let previous_known_pids = state.known_pids.clone();
    let growth_refresh_requested = state.proc_growth_scan_pending;
    let mut process_index_round = match prepare_process_index_round(
        state,
        scan_clock,
        full_scan || growth_refresh_requested,
        full_scan,
    ) {
        Ok(update) => {
            if update.view.refreshed {
                state.proc_growth_scan_pending = false;
                if growth_refresh_requested {
                    state.last_proc_growth_scan_elapsed_ms = Some(scan_clock);
                }
            }
            update
        }
        Err(err) => {
            // 后续仍可从旧索引保留正向命中，但本轮不能把它当成完整全扫证据。
            state.process_index.snapshot_complete = false;
            if pid_snapshot_log_due(state, scan_clock) {
                eprintln!("[RS] PID快照刷新失败，保留现有缓存并等待下轮重试: {err}");
            }
            ProcessIndexRound::default()
        }
    };
    if (process_index_round.view.added > 0 || process_index_round.view.exited > 0)
        && pid_snapshot_log_due(state, scan_clock)
    {
        println!(
            "[RS] 进程索引变化: 新增={} 退出={} 待确认={}",
            process_index_round.view.added,
            process_index_round.view.exited,
            process_index_round.view.candidate_pids.len()
        );
    }
    if !full_scan && process_index_round.view.added > 0 {
        scan_reason = "进程索引发现";
    }
    let mut priority_pids = focused_package
        .as_deref()
        .map(|pkg| process_index_verified_package_pids(&state.process_index, pkg))
        .unwrap_or_default();
    let deep_scan_interval_ms = if state.interactive {
        ACTIVE_PROCESS_DEEP_SCAN_MS
    } else {
        SCREEN_OFF_PROCESS_DEEP_SCAN_MS
    };
    let mut scan_result = if full_scan {
        match scan_proc(rules, index, &state.known_pids, &state.process_index) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("[RS] 全量扫描失败，本轮仅保留正向结果并等待冷却重试: {err}");
                ProcScanResult::default()
            }
        }
    } else {
        scan_known_pids(
            rules,
            index,
            &mut state.known_pids,
            &mut state.process_scan_stamps,
            KnownPidScanPolicy {
                now_elapsed: scan_clock,
                deep_scan_interval_ms,
                priority_pids: &priority_pids,
                background_budget: Duration::from_millis(BACKGROUND_SCAN_BUDGET_MS),
            },
        )
    };

    let mut scoped_scan_evidence = None;
    if !full_scan && !targeted_scan_packages.is_empty() {
        match scan_proc_packages(
            rules,
            index,
            &state.known_pids,
            &state.process_index,
            &targeted_scan_packages,
        ) {
            Ok(scoped_result) => {
                scoped_scan_evidence = Some((
                    scoped_result.complete,
                    scoped_result.health_incomplete_packages.clone(),
                ));
                merge_proc_scan_result(&mut scan_result, scoped_result, state);
            }
            Err(err) => {
                eprintln!("[RS] 包级扫描失败，本轮不产生规则健康负向证据: {err}");
                scoped_scan_evidence = Some((false, BTreeSet::new()));
                scan_result.complete = false;
            }
        }
    }

    if !full_scan {
        let dropped_pids = previous_known_pids
            .difference(&state.known_pids)
            .filter(|pid| process_index_round.view.current_pids.contains(pid))
            .copied()
            .collect::<Vec<_>>();
        if !dropped_pids.is_empty() {
            if let Err(err) = process_index_mark_candidates(
                &mut state.process_index,
                dropped_pids.iter().copied(),
                scan_clock,
            ) {
                if pid_snapshot_log_due(state, scan_clock) {
                    eprintln!("[RS] 进程索引复查标记失败: {err}");
                }
            }
            process_index_round.view.candidate_pids.extend(dropped_pids);
            state.process_index_has_candidates = true;
        }
    }

    // refresh 与本轮重新标记的候选共用一次原子写盘；失败时保留 dirty，下一轮重试。
    if process_index_round.view.loaded {
        if let Err(err) = flush_process_index(&mut state.process_index, scan_clock) {
            if pid_snapshot_log_due(state, scan_clock) {
                eprintln!("[RS] 进程索引批量写入失败，保留内存索引等待重试: {err}");
            }
        }
    }

    let already_scanned = scan_result
        .hits
        .iter()
        .map(|hit| hit.pid)
        .collect::<BTreeSet<_>>();
    process_index_round.view.candidate_pids.retain(|pid| {
        !state.known_pids.contains(pid) && !already_scanned.contains(pid)
    });

    let candidate_result = scan_candidate_pids(
        rules,
        index,
        &process_index_round.view.candidate_pids,
    );
    merge_candidate_hits(&mut scan_result, candidate_result, state);
    if let Some((_, scoped_incomplete_packages)) = scoped_scan_evidence.as_mut() {
        for hit in &scan_result.hits {
            let Some(pkg) = base_package(&hit.cmdline) else {
                continue;
            };
            if targeted_scan_packages.contains(pkg) && !hit.health_scan_complete {
                scoped_incomplete_packages.insert(pkg.to_string());
            }
        }
    }
    if let Some(pkg) = focused_package.as_deref() {
        priority_pids.extend(
            scan_result
                .hits
                .iter()
                .filter(|hit| process_belongs_to_uid_package(&hit.cmdline, pkg))
                .map(|hit| hit.pid),
        );
    }
    let scan_finished_at = elapsed_realtime_ms();
    let ProcScanResult {
        hits,
        complete: scan_complete,
        health_incomplete_packages,
    } = scan_result;
    let observed_owners = hits
        .iter()
        .map(|hit| hit.cmdline.clone())
        .filter(|owner| owner.contains(':'))
        .collect::<BTreeSet<_>>();
    let full_scan_evidence = if full_scan {
        Some(FullScanEvidence {
            completed_at: scan_finished_at,
            global_complete: scan_complete,
            incomplete_packages: health_incomplete_packages.clone(),
            scanned_packages: None,
            observed_owners: observed_owners.clone(),
        })
    } else {
        scoped_scan_evidence.map(|(complete, incomplete_packages)| FullScanEvidence {
            completed_at: scan_finished_at,
            global_complete: complete,
            incomplete_packages,
            scanned_packages: Some(targeted_scan_packages.clone()),
            observed_owners: observed_owners.clone(),
        })
    };
    if full_scan || !health_scan_packages.is_empty() {
        state.last_health_full_scan_attempt_elapsed_ms = Some(scan_finished_at);
    }
    let scan_elapsed = scan_started.elapsed();
    state.last_proc_total = proc_total;

    if full_scan {
        if scan_complete {
            state.known_pids.clear();
        } else {
            state.known_pids = previous_known_pids.clone();
        }
        state.known_pids.extend(hits.iter().map(|hit| hit.pid));
        state.proc_scan_initialized = true;
        state.last_full_scan_attempt_elapsed_ms = (!scan_complete).then_some(scan_finished_at);
        if scan_complete {
            state.last_full_scan_elapsed_ms = Some(scan_finished_at);
            state.proc_growth_scan_pending = false;
        }
        state.last_config_key = Some(config_key);
        state.last_uid_map_key = uid_key;
    }
    for hit in &hits {
        update_process_scan_stamp(
            &mut state.process_scan_stamps,
            hit,
            scan_finished_at,
            deep_scan_interval_ms,
        );
    }
    state
        .process_scan_stamps
        .retain(|pid, _| state.known_pids.contains(pid));
    let managed_journal_changed = refresh_managed_tid_cache(
        state,
        &hits,
        refresh.index_rebuilt && scan_complete && health_incomplete_packages.is_empty(),
        &args.cpuset_name,
    );
    state.managed_tid_journal_dirty |= managed_journal_changed;
    let managed_journal_synced = match sync_managed_tid_journal(state, &args.cpuset_name, false) {
        Ok(()) => true,
        Err(err) => {
            // 已持久化的旧线程仍可继续验证/恢复；本轮新记录保持 restore_persisted=false，
            // apply 阶段只跳过这些新线程，下一轮写盘成功后自动开始接管。
            eprintln!("[RS] 线程恢复基线写入失败，新线程等待下轮重试: {err}");
            false
        }
    };

    let known_pids = state.known_pids.len();
    let processes = state.known_pids.len();
    let has_new_hit_pid = hits
        .iter()
        .any(|hit| !previous_known_pids.contains(&hit.pid));
    let first_summary = !state.logged_round_once;
    let forced_summary = config_changed || first_summary;
    let runtime_state_changed = has_new_hit_pid
        || known_pids != state.last_logged_known_pids
        || processes != state.last_logged_processes;
    let scan_incomplete = (full_scan || !targeted_scan_packages.is_empty()) && !scan_complete;
    let last_summary = state.last_runtime_summary_log_elapsed_ms;
    let state_change_summary_due = (runtime_state_changed || scan_incomplete)
        && last_summary.is_none_or(|last| {
            scan_clock < last
                || scan_clock.saturating_sub(last) >= RUNTIME_CHANGE_LOG_INTERVAL_MS
        });
    let periodic_summary_due = last_summary.is_some_and(|last| {
        scan_clock < last
            || scan_clock.saturating_sub(last) >= RUNTIME_SUMMARY_LOG_INTERVAL_MS
    });
    let detail_log = forced_summary || state_change_summary_due || periodic_summary_due;
    let hit_preview_log = config_changed || first_summary;

    if let Err(err) = update_rule_health(
        rules,
        &hits,
        full_scan_evidence.as_ref(),
        args.target_pkg.as_deref(),
        rule_config_changed,
        &foreground_state,
        scan_clock,
        state,
    ) {
        eprintln!("[RS] 规则健康状态更新失败: {err}");
    }

    let apply_started = Instant::now();
    let base_cpuset = Path::new("/dev/cpuset").join(&args.cpuset_name);
    let interactive = state.interactive;
    let managed_count_before_apply = state.managed_tids.len();
    let mut stats = apply_hits(
        &hits,
        &mut state.managed_tids,
        ApplyPolicy {
            detail_log,
            cpuset_name: &args.cpuset_name,
            now_elapsed: scan_finished_at,
            foreground_pids: &priority_pids,
            interactive,
            require_restore_baseline: true,
        },
    );
    let (verify_stats, next_verify_cursor) = verify_managed_affinity(
        &mut state.managed_tids,
        AffinityVerifyPolicy {
            foreground_pids: &priority_pids,
            interactive,
            now_elapsed: scan_finished_at,
            detail_log,
            base_cpuset: &base_cpuset,
            cpuset_name: &args.cpuset_name,
            start_cursor: state.affinity_verify_cursor,
        },
    );
    state.affinity_verify_cursor = next_verify_cursor;
    stats.merge(verify_stats);
    if state.managed_tids.len() != managed_count_before_apply {
        state.managed_tid_journal_dirty = true;
    }
    if managed_journal_synced {
        if let Err(err) = sync_managed_tid_journal(state, &args.cpuset_name, false) {
            // 这里只会清理已经退出的旧 TID；旧文件保留其超集仍可安全恢复。
            eprintln!("[RS] 线程恢复基线收尾写入失败，将在下轮重试: {err}");
        }
    }
    let apply_elapsed = apply_started.elapsed();
    state.round_index = state.round_index.saturating_add(1);
    let scanned_threads = hits.iter().map(|hit| hit.scanned_threads).sum::<usize>();
    let actions = hits.iter().map(|hit| hit.actions.len()).sum::<usize>();
    let process_actions = hits
        .iter()
        .flat_map(|hit| hit.actions.iter())
        .filter(|action| action.source == RuleSource::Process)
        .count();
    let thread_actions = actions.saturating_sub(process_actions);
    let process_rules = hits
        .iter()
        .map(|hit| hit.process_rules.len())
        .sum::<usize>();
    let should_log = detail_log;
    if should_log {
        println!(
            "[RS] 运行摘要: 轮次={} 模式={} 扫描完整={} 原因={} 配置变更={} 目标包={} 已知PID={} 命中进程={} 扫描线程={} 进程规则={} 线程规则命中={} 进程规则应用={} 已应用={} 已跳过={} 系统限制={} 失败={} 无效规则={} 抢写={} 扫描耗时={}ms 应用耗时={}ms 总耗时={}ms",
            state.round_index,
            if full_scan {
                "全量扫描"
            } else if !targeted_scan_packages.is_empty() {
                "包级扫描"
            } else {
                "PID缓存"
            },
            if scan_complete { "是" } else { "否" },
            scan_reason,
            if config_changed { "是" } else { "否" },
            plan.package_count(),
            known_pids,
            processes,
            scanned_threads,
            process_rules,
            thread_actions,
            process_actions,
            stats.applied,
            stats.skipped,
            stats.restricted,
            stats.failed,
            stats.invalid_rules,
            stats.mismatched,
            scan_elapsed.as_millis(),
            apply_elapsed.as_millis(),
            round_start.elapsed().as_millis()
        );
        if stats.cpuset_failed > 0 {
            println!("[RS] cpuset辅助写入失败: {}", stats.cpuset_failed);
        }
        if hit_preview_log && !hits.is_empty() {
            log_hit_preview(&hits, 5, &previous_known_pids);
        } else if hit_preview_log && !plan.is_empty() {
            println!(
                "[RS] 未命中任何进程: appId映射包={} 缺少映射包={}",
                plan.by_app_id.values().map(BTreeSet::len).sum::<usize>(),
                plan.fallback_pkgs.len()
            );
        }
        state.logged_round_once = true;
        state.last_runtime_summary_log_elapsed_ms = Some(scan_clock);
        state.last_logged_known_pids = known_pids;
        state.last_logged_processes = processes;
    }
    Ok(())
}

fn log_config_summary(rules: &[Rule], uid_map: &HashMap<String, u32>, plan: &ScanPlan) {
    let active_rules = rules.iter().filter(|rule| !rule.auto).count();
    let auto_rules = rules.iter().filter(|rule| rule.auto).count();
    let mut owners = BTreeSet::new();
    let mut base_pkgs = BTreeSet::new();
    for rule in rules {
        owners.insert(rule.owner.as_str());
        if let Some(base) = base_package(&rule.owner) {
            base_pkgs.insert(base);
        }
    }
    let app_id_bound_pkgs = plan.by_app_id.values().map(BTreeSet::len).sum::<usize>();
    println!(
        "[RS] 规则加载完成: 规则={} auto={} 应用/进程={} 基础包={}",
        active_rules,
        auto_rules,
        owners.len(),
        base_pkgs.len()
    );
    println!(
        "[RS] 包名 UID 映射: 已加载 {} 个, appId快路径 {} 个, 缺少映射 {} 个",
        uid_map.len(),
        app_id_bound_pkgs,
        plan.fallback_pkgs.len()
    );
    println!(
        "[RS] 扫描计划: appId快路径=[{}] 缺少映射=[{}]",
        plan_app_id_preview(plan, 8),
        preview_set(&plan.fallback_pkgs, 8)
    );
}

fn plan_app_id_preview(plan: &ScanPlan, limit: usize) -> String {
    let mut rows = Vec::new();
    for (app_id, pkgs) in &plan.by_app_id {
        for pkg in pkgs {
            rows.push(format!("{pkg}:{app_id}"));
        }
    }
    rows.sort();
    preview_list(&rows, limit)
}

fn preview_set(values: &BTreeSet<String>, limit: usize) -> String {
    let rows = values.iter().cloned().collect::<Vec<_>>();
    preview_list(&rows, limit)
}

fn preview_list(values: &[String], limit: usize) -> String {
    if values.is_empty() {
        return "-".to_string();
    }
    let mut out = values
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if values.len() > limit {
        out.push_str(&format!(" ... +{}", values.len() - limit));
    }
    out
}

fn log_hit_preview(hits: &[ProcHit], limit: usize, previous_known_pids: &BTreeSet<i32>) {
    let shown = hits.len().min(limit);
    if hits.len() > limit {
        println!("[RS] 命中详情: 显示 {shown}/{} 个进程", hits.len());
    } else {
        println!("[RS] 命中详情: {} 个进程", hits.len());
    }
    let mut rows = hits.iter().collect::<Vec<_>>();
    rows.sort_by_key(|hit| (previous_known_pids.contains(&hit.pid), hit.pid));
    for hit in rows.into_iter().take(limit) {
        let process_actions = hit
            .actions
            .iter()
            .filter(|action| action.source == RuleSource::Process)
            .count();
        let thread_actions = hit.actions.len().saturating_sub(process_actions);
        println!(
            "[RS]   {}pid={} uid={} 进程={} 扫描线程={} 进程规则={} 线程规则={} 兜底线程={}",
            if previous_known_pids.contains(&hit.pid) {
                ""
            } else {
                "新进程 "
            },
            hit.pid,
            hit.uid,
            hit.cmdline,
            hit.scanned_threads,
            hit.process_rules.len(),
            thread_actions,
            process_actions
        );
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn system_process_count() -> Option<u64> {
    let mut info: libc::sysinfo = unsafe { mem::zeroed() };
    let rc = unsafe { libc::sysinfo(&mut info) };
    if rc == 0 {
        Some(info.procs as u64)
    } else {
        None
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn system_process_count() -> Option<u64> {
    None
}

#[cfg(test)]
mod managed_tid_cache_tests {
    use super::*;

    fn entry(last_seen_round: u64, restore_pending: bool) -> ManagedTidEntry {
        ManagedTidEntry {
            tgid: 1,
            tgid_starttime: Some(1),
            starttime: Some(1),
            last_seen_round,
            cpuset_synced: false,
            cpuset_failure_count: 0,
            cpuset_retry_after_elapsed_ms: 0,
            desired_mask_low64: None,
            verified_mask_low64: None,
            last_affinity_check_elapsed_ms: 0,
            next_affinity_check_elapsed_ms: 0,
            original_mask_low64: Some(0xff),
            original_cpuset: Some("/top-app".to_string()),
            restore_persisted: true,
            restore_pending,
        }
    }

    #[test]
    fn capacity_limit_keeps_existing_entries_and_rejects_only_new_tids() {
        let mut managed = HashMap::new();
        for tid in 1..=MAX_MANAGED_TIDS as i32 {
            managed.insert(tid, entry(tid as u64, false));
        }

        assert!(managed_tid_capacity_available(&managed, 1));
        assert!(!managed_tid_capacity_available(
            &managed,
            MAX_MANAGED_TIDS as i32 + 1
        ));
        assert_eq!(managed.len(), MAX_MANAGED_TIDS);
    }

    #[test]
    fn missing_observed_starttime_preserves_existing_identity() {
        let current = entry(1, false);
        assert!(managed_identity_matches_observation(
            &current,
            (1, None, None)
        ));
        assert!(!managed_identity_conflicts_with_observation(
            &current,
            (1, None, None)
        ));
        assert!(managed_identity_conflicts_with_observation(
            &current,
            (1, Some(1), Some(2))
        ));
    }

    #[test]
    fn managed_tid_journal_round_trip_preserves_restore_baseline() {
        let managed = HashMap::from([(42, entry(7, true))]);
        let encoded = serialize_managed_tid_journal(&managed, "boot-test", "AppOptRs");
        let decoded = parse_managed_tid_journal(&encoded, "boot-test", "AppOptRs").unwrap();

        let decoded = decoded.get(&42).unwrap();
        let original = managed.get(&42).unwrap();
        assert_eq!(decoded.tgid, original.tgid);
        assert_eq!(decoded.tgid_starttime, original.tgid_starttime);
        assert_eq!(decoded.starttime, original.starttime);
        assert_eq!(decoded.original_mask_low64, original.original_mask_low64);
        assert_eq!(decoded.original_cpuset, original.original_cpuset);
        assert!(decoded.restore_persisted);
        assert!(!decoded.restore_pending);
        assert!(parse_managed_tid_journal(&encoded, "other-boot", "AppOptRs")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn corrupt_journal_header_and_row_enter_identity_quarantine() {
        let bad_header = decode_managed_tid_journal("broken\n", "boot-test", "AppOptRs");
        assert!(bad_header.entries.is_empty());
        assert!(bad_header.quarantine_existing);
        assert!(bad_header.warning.is_some());

        let bad_row = decode_managed_tid_journal(
            "APPOPT_MANAGED_TIDS_V1\tboot-test\tAppOptRs\n42\tbad\n",
            "boot-test",
            "AppOptRs",
        );
        assert!(bad_row.entries.is_empty());
        assert!(bad_row.quarantine_existing);
        assert!(bad_row.warning.is_some());

        let other_boot = decode_managed_tid_journal(
            "APPOPT_MANAGED_TIDS_V1\told-boot\tAppOptRs\n",
            "boot-test",
            "AppOptRs",
        );
        assert!(!other_boot.quarantine_existing);
        assert!(other_boot.warning.is_none());
    }

    #[test]
    fn corrupt_journal_quarantine_expires_only_for_new_thread_identity() {
        assert!(managed_tid_identity_quarantined(
            false,
            Some(100),
            Some(100)
        ));
        assert!(!managed_tid_identity_quarantined(
            false,
            Some(101),
            Some(100)
        ));
        assert!(!managed_tid_identity_quarantined(
            true,
            Some(100),
            Some(100)
        ));
    }

    #[test]
    fn journal_commit_failure_removes_temporary_file_and_can_retry() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = env::temp_dir().join(format!(
            "appopt-managed-journal-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&target).unwrap();
        let temporary = target.with_extension(format!("tmp.{}", std::process::id()));

        assert!(write_managed_tid_journal_file(&target, "test").is_err());
        assert!(!temporary.exists());

        fs::remove_dir(&target).unwrap();
    }

    #[test]
    fn stale_helper_keeps_last_known_screen_off_state() {
        let mut state = DaemonState::default();
        update_interactive_mode(&mut state, None);
        assert!(state.interactive);
        assert!(!state.interactive_known);

        update_interactive_mode(&mut state, Some(false));
        update_interactive_mode(&mut state, None);
        assert!(!state.interactive);
        assert!(state.interactive_known);

        update_interactive_mode(&mut state, Some(true));
        assert!(state.interactive);
    }
}
