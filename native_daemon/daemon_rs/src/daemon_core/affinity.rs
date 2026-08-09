// CPU affinity 写入与读回验证。
//
// daemon 最终只做一件事：把命中的 TID 写到目标 CPU mask。
// 写入前优先通过 sched_getaffinity 读取当前 mask，系统不支持时才回退 /proc status；
// 写入后再读回一次，区分 cpuset 合法收窄与厂商服务抢写。
//
// mismatched 对移植系统很关键：有些 ROM/厂商服务会反复把线程绑回 4-7、6-7 之类的范围，
// 这时不是 AppOpt 规则没命中，而是外部调度服务在抢写。
struct ApplyPolicy<'a> {
    detail_log: bool,
    cpuset_name: &'a str,
    now_elapsed: u64,
    foreground_pids: &'a BTreeSet<i32>,
    interactive: bool,
    require_restore_baseline: bool,
}

fn apply_hits(
    hits: &[ProcHit],
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    policy: ApplyPolicy<'_>,
) -> ApplyStats {
    let ApplyPolicy {
        detail_log,
        cpuset_name,
        now_elapsed,
        foreground_pids,
        interactive,
        require_restore_baseline,
    } = policy;
    let mut stats = ApplyStats::default();
    let mut invalid_details = 0usize;
    let mut restricted_details = 0usize;
    let mut read_failed_details = 0usize;
    let mut cpuset_failed_details = 0usize;
    let mut affinity_failed_details = 0usize;
    let mut mismatch_details = 0usize;
    let mut identity_details = 0usize;

    let present_mask = read_present_cpus().and_then(|cpus| CpuMask::parse(&cpus));
    let base_cpuset = Path::new("/dev/cpuset").join(cpuset_name);
    let mut cpuset_cache = CpusetRoundCache::default();

    for hit in hits {
        for action in &hit.actions {
            // cpus 解析失败不终止整个 daemon，只统计并打印错误，避免一条坏规则影响其他应用。
            let Some(requested_mask) = CpuMask::parse(&action.cpus) else {
                stats.invalid_rules += 1;
                if should_log_detail(detail_log, &mut invalid_details) {
                    eprintln!(
                        "[RS] 无效CPU规则 进程={} 线程={} 线程名={} 规则={}",
                        hit.pid, action.tid, action.name, action.rule
                    );
                }
                continue;
            };
            if require_restore_baseline
                && !managed_tids.get(&action.tid).is_some_and(|entry| {
                    entry.tgid == hit.pid
                        && entry.tgid_starttime == hit.pid_starttime
                        && entry.starttime == action.tid_starttime
                        && managed_restore_baseline_ready(entry)
                })
            {
                stats.skipped += 1;
                if should_log_detail(detail_log, &mut read_failed_details) {
                    eprintln!(
                        "[RS] 跳过未建立恢复基线的线程 进程={} 线程={} 线程名={}",
                        hit.pid, action.tid, action.name
                    );
                }
                continue;
            }
            let mask = if let Some(present) = &present_mask {
                let clipped = requested_mask.intersection(present);
                if clipped.is_empty() {
                    stats.restricted += 1;
                    if should_log_detail(detail_log, &mut restricted_details) {
                        eprintln!(
                            "[RS] CPU规则不包含当前设备核心 进程={} 线程={} 线程名={} 规则={} 请求={} present={}",
                            hit.pid,
                            action.tid,
                            action.name,
                            action.rule,
                            action.cpus,
                            present.to_list()
                        );
                    }
                    continue;
                }
                if clipped != requested_mask {
                    stats.restricted += 1;
                    if should_log_detail(detail_log, &mut restricted_details) {
                        eprintln!(
                            "[RS] CPU规则已裁剪到当前设备核心 进程={} 线程={} 线程名={} 规则={} 请求={} 实际={} present={}",
                            hit.pid,
                            action.tid,
                            action.name,
                            action.rule,
                            action.cpus,
                            clipped.to_list(),
                            present.to_list()
                        );
                    }
                }
                clipped
            } else {
                requested_mask
            };
            let effective_cpus = mask.to_list();
            let desired_mask_low64 = mask.to_low64();
            let verify_interval_ms = if foreground_pids.contains(&hit.pid) {
                FOREGROUND_AFFINITY_VERIFY_MS
            } else if interactive {
                ACTIVE_BACKGROUND_AFFINITY_VERIFY_MS
            } else {
                SCREEN_OFF_BACKGROUND_AFFINITY_VERIFY_MS
            };

            let cached = managed_tids.get(&action.tid).cloned().filter(|entry| {
                entry.tgid == hit.pid
                    && entry.tgid_starttime == hit.pid_starttime
                    && entry.starttime == action.tid_starttime
            });
            let desired_changed = cached
                .as_ref()
                .and_then(|entry| entry.desired_mask_low64)
                != desired_mask_low64;
            let needs_cpuset_sync = cached.as_ref().is_none_or(|entry| {
                desired_changed
                    || (!entry.cpuset_synced && cpuset_retry_due(entry, now_elapsed))
            });
            if needs_cpuset_sync {
                if !action_identity_is_current(
                    hit,
                    action,
                    "cpuset",
                    detail_log,
                    &mut identity_details,
                ) {
                    stats.skipped += 1;
                    continue;
                }
                let previous_cpuset_failure_count =
                    cached.as_ref().map_or(0, |entry| entry.cpuset_failure_count);
                let cpuset_move = move_tid_to_cpuset(
                    action.tid,
                    &mask,
                    &base_cpuset,
                    cpuset_name,
                    &mut cpuset_cache,
                );
                let (cpuset_synced, cpuset_failure_count, cpuset_retry_after_elapsed_ms) =
                    match cpuset_move {
                    Ok(()) => (true, 0, 0),
                    Err(err) if is_thread_gone_error(&err) => {
                        stats.skipped += 1;
                        continue;
                    }
                    Err(err) => {
                        let expected_reject = is_cpuset_expected_reject(&err);
                        if !expected_reject {
                            stats.cpuset_failed += 1;
                        }
                        if !expected_reject
                            && should_log_detail(detail_log, &mut cpuset_failed_details)
                        {
                            eprintln!(
                                "[RS] cpuset辅助写入失败 进程={} 线程={} 线程名={} 规则={} 核心={} 错误={}",
                                hit.pid,
                                action.tid,
                                action.name,
                                action.rule,
                                effective_cpus,
                                error_text_zh(&err)
                            );
                        }
                        let (failure_count, retry_after) =
                            next_cpuset_retry(previous_cpuset_failure_count, now_elapsed);
                        (false, failure_count, retry_after)
                    }
                };
                let last_seen_round = managed_tids
                    .get(&action.tid)
                    .map_or(0, |entry| entry.last_seen_round);
                managed_tids.insert(
                    action.tid,
                    ManagedTidEntry {
                        tgid: hit.pid,
                        tgid_starttime: hit.pid_starttime,
                        starttime: action.tid_starttime,
                        last_seen_round,
                        cpuset_synced,
                        cpuset_failure_count,
                        cpuset_retry_after_elapsed_ms,
                        desired_mask_low64: cached
                            .as_ref()
                            .and_then(|entry| entry.desired_mask_low64),
                        verified_mask_low64: cached
                            .as_ref()
                            .and_then(|entry| entry.verified_mask_low64),
                        last_affinity_check_elapsed_ms: cached
                            .as_ref()
                            .map_or(0, |entry| entry.last_affinity_check_elapsed_ms),
                        next_affinity_check_elapsed_ms: cached
                            .as_ref()
                            .map_or(0, |entry| entry.next_affinity_check_elapsed_ms),
                        original_mask_low64: cached
                            .as_ref()
                            .and_then(|entry| entry.original_mask_low64),
                        original_cpuset: cached
                            .as_ref()
                            .and_then(|entry| entry.original_cpuset.clone()),
                        restore_persisted: cached
                            .as_ref()
                            .is_some_and(|entry| entry.restore_persisted),
                        restore_pending: false,
                    },
                );
            }

            // 深扫会重新生成全部 action。身份、规则和 cpuset 都未变化的线程统一交给
            // 验证队列，避免 60 秒全扫在同一轮集中读回所有已管理线程。
            if managed_action_can_defer(cached.as_ref(), desired_changed) {
                stats.skipped += 1;
                continue;
            }

            let affinity_cache_fresh = desired_mask_low64.is_some_and(|desired| {
                managed_tids.get(&action.tid).is_some_and(|entry| {
                    entry.tgid == hit.pid
                        && entry.tgid_starttime == hit.pid_starttime
                        && entry.starttime == action.tid_starttime
                        && entry.desired_mask_low64 == Some(desired)
                        && now_elapsed >= entry.last_affinity_check_elapsed_ms
                        && now_elapsed.saturating_sub(entry.last_affinity_check_elapsed_ms)
                            < verify_interval_ms
                })
            });
            if affinity_cache_fresh {
                stats.skipped += 1;
                continue;
            }

            // 已经在目标核心上就不重复写 affinity，减少长期守护进程对系统的打扰。
            let mut observed_mask_low64 = None;
            match read_allowed_mask(hit.pid, action.tid) {
                Ok(Some(current))
                    if accepted_managed_mask(cached.as_ref(), &current, &mask)
                        && !desired_changed =>
                {
                    mark_managed_affinity_checked(
                        managed_tids,
                        action.tid,
                        desired_mask_low64,
                        current.to_low64(),
                        now_elapsed,
                        verify_interval_ms,
                    );
                    stats.skipped += 1;
                    continue;
                }
                Ok(Some(current)) => observed_mask_low64 = current.to_low64(),
                Ok(None) => {}
                Err(err) if is_thread_gone_error(&err) => {
                    stats.skipped += 1;
                    continue;
                }
                Err(err) => {
                    if should_log_detail(detail_log, &mut read_failed_details) {
                        eprintln!(
                            "[RS] 读取绑核状态失败 进程={} 线程={} 线程名={} 错误={}",
                            hit.pid,
                            action.tid,
                            action.name,
                            error_text_zh(&err)
                        );
                    }
                }
            }

            if !action_identity_is_current(
                hit,
                action,
                "affinity",
                detail_log,
                &mut identity_details,
            ) {
                stats.skipped += 1;
                continue;
            }

            match set_affinity(action.tid, &mask) {
                Ok(()) => {
                    stats.applied += 1;
                    // 写入后读回一次，用于发现移植系统或厂商服务把线程核心抢写回去的情况。
                    match read_allowed_mask(hit.pid, action.tid) {
                        Ok(Some(current)) if current == mask => {
                            mark_managed_affinity_checked(
                                managed_tids,
                                action.tid,
                                desired_mask_low64,
                                current.to_low64(),
                                now_elapsed,
                                verify_interval_ms,
                            );
                        }
                        Ok(Some(current)) if current.is_subset_of(&mask) => {
                            // 写入成功但 cpuset/内核只允许目标子集，单独计为系统限制，
                            // 不能把旧范围是新范围子集误判成扩容已经完成。
                            stats.restricted += 1;
                            mark_managed_affinity_checked(
                                managed_tids,
                                action.tid,
                                desired_mask_low64,
                                current.to_low64(),
                                now_elapsed,
                                verify_interval_ms,
                            );
                            if desired_changed {
                                mark_managed_cpuset_failure(
                                    managed_tids,
                                    action.tid,
                                    now_elapsed,
                                );
                            }
                            if should_log_detail(detail_log, &mut restricted_details) {
                                eprintln!(
                                    "[RS] CPU规则受系统限制 进程={} 线程={} 线程名={} 期望={} 实际={}",
                                    hit.pid,
                                    action.tid,
                                    action.name,
                                    effective_cpus,
                                    current.to_list()
                                );
                            }
                        }
                        Ok(Some(current)) => {
                            stats.mismatched += 1;
                            if should_log_detail(detail_log, &mut mismatch_details) {
                                eprintln!(
                                    "[RS] 绑核被系统改写 进程={} 线程={} 线程名={} 规则={} 期望={} 实际={}",
                                    hit.pid,
                                    action.tid,
                                    action.name,
                                    action.rule,
                                    effective_cpus,
                                    current.to_list()
                                );
                            }
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    if is_thread_gone_error(&err) {
                        stats.skipped += 1;
                    } else if is_affinity_restricted_error(&err) {
                        stats.restricted += 1;
                        mark_managed_affinity_checked(
                            managed_tids,
                            action.tid,
                            desired_mask_low64,
                            observed_mask_low64,
                            now_elapsed,
                            verify_interval_ms,
                        );
                    } else {
                        stats.failed += 1;
                        mark_managed_affinity_checked(
                            managed_tids,
                            action.tid,
                            desired_mask_low64,
                            observed_mask_low64,
                            now_elapsed,
                            verify_interval_ms,
                        );
                        if should_log_detail(detail_log, &mut affinity_failed_details) {
                            eprintln!(
                                "[RS] 绑核失败 进程={} 线程={} 线程名={} 规则={} 错误={}",
                                hit.pid,
                                action.tid,
                                action.name,
                                action.rule,
                                error_text_zh(&err)
                            );
                        }
                    }
                }
            }
        }
    }

    if detail_log {
        log_limited_detail_count("无效CPU规则", invalid_details);
        log_limited_detail_count("CPU规则受设备核心范围限制", restricted_details);
        log_limited_detail_count("读取绑核状态失败", read_failed_details);
        log_limited_detail_count("cpuset辅助写入失败", cpuset_failed_details);
        log_limited_detail_count("绑核失败", affinity_failed_details);
        log_limited_detail_count("绑核被系统改写", mismatch_details);
        log_limited_detail_count("进程/线程身份已变化", identity_details);
    }

    stats
}

struct AffinityVerifyPolicy<'a> {
    foreground_pids: &'a BTreeSet<i32>,
    interactive: bool,
    now_elapsed: u64,
    detail_log: bool,
    base_cpuset: &'a Path,
    cpuset_name: &'a str,
    start_cursor: usize,
}

fn verify_managed_affinity(
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    policy: AffinityVerifyPolicy<'_>,
) -> (ApplyStats, usize) {
    let AffinityVerifyPolicy {
        foreground_pids,
        interactive,
        now_elapsed,
        detail_log,
        base_cpuset,
        cpuset_name,
        start_cursor,
    } = policy;
    let mut stats = ApplyStats::default();
    let mut mismatch_details = 0usize;
    let mut failed_details = 0usize;
    let background_started = Instant::now();
    // 这里只复制轻量 TID。ManagedTidEntry 含有原 cpuset 字符串，先克隆整张表会让
    // 每个常规轮次都产生与受控线程数成正比的字符串分配。
    // HashMap 的键顺序不需要排序；轮转游标已经保证每轮从不同位置开始，
    // 这里避免数千 TID 的 O(N log N) 排序和额外比较。
    let mut snapshot = managed_tids.keys().copied().collect::<Vec<_>>();
    let snapshot_len = snapshot.len();
    if snapshot_len > 0 {
        let offset = start_cursor % snapshot_len;
        snapshot.rotate_left(offset);
    }
    let mut stale_tids = Vec::new();
    let mut foreground_checked = 0usize;
    let mut background_checked = 0usize;
    let mut cpuset_cache = CpusetRoundCache::default();

    for tid in snapshot {
        let Some(entry) = managed_tids.get(&tid) else {
            continue;
        };
        let Some(expected_low64) = entry.desired_mask_low64 else {
            continue;
        };
        let foreground = foreground_pids.contains(&entry.tgid);
        let interval_ms = if foreground {
            FOREGROUND_AFFINITY_VERIFY_MS
        } else if interactive {
            ACTIVE_BACKGROUND_AFFINITY_VERIFY_MS
        } else {
            SCREEN_OFF_BACKGROUND_AFFINITY_VERIFY_MS
        };
        let due = entry.next_affinity_check_elapsed_ms == 0
            || now_elapsed < entry.last_affinity_check_elapsed_ms
            || now_elapsed >= entry.next_affinity_check_elapsed_ms;
        if !due {
            continue;
        }
        if foreground {
            if foreground_checked >= MAX_FOREGROUND_AFFINITY_CHECKS_PER_ROUND {
                continue;
            }
            foreground_checked += 1;
        } else {
            if background_checked >= MAX_BACKGROUND_AFFINITY_CHECKS_PER_ROUND
                || background_started.elapsed()
                    >= Duration::from_millis(BACKGROUND_AFFINITY_BUDGET_MS)
            {
                continue;
            }
            background_checked += 1;
        }
        // 只克隆本轮真正到期且未被预算挡住的记录。
        let entry = entry.clone();

        let expected = CpuMask::from_low64(expected_low64);
        match read_allowed_mask(entry.tgid, tid) {
            Ok(Some(current)) if accepted_managed_mask(Some(&entry), &current, &expected) => {
                mark_managed_affinity_checked(
                    managed_tids,
                    tid,
                    Some(expected_low64),
                    current.to_low64(),
                    now_elapsed,
                    interval_ms,
                );
            }
            Ok(Some(current)) => {
                match managed_tid_identity_status(tid, &entry) {
                    ManagedTidIdentityStatus::Current => {}
                    ManagedTidIdentityStatus::GoneOrReused => {
                        stale_tids.push(tid);
                        continue;
                    }
                    ManagedTidIdentityStatus::Unreadable => {
                        // /proc 的瞬时读取失败不是线程退出证据。保留恢复基线并延后复核，
                        // 绝不能因为一次 EACCES/EIO 就把仍受控线程从缓存中丢掉。
                        mark_managed_affinity_checked(
                            managed_tids,
                            tid,
                            Some(expected_low64),
                            current.to_low64(),
                            now_elapsed,
                            interval_ms,
                        );
                        continue;
                    }
                }
                // mask 漂移通常意味着 Android task profile/cpuset 已重新接管线程。
                // 不依赖前台助手是否识别成功：和原版 affinity_sync 一样，先把
                // TID 迁回目标 cpuset，再写 sched_setaffinity。
                let should_retry_cpuset = entry.cpuset_synced || cpuset_retry_due(&entry, now_elapsed);
                set_managed_cpuset_synced(managed_tids, tid, false);
                if should_retry_cpuset {
                    match move_tid_to_cpuset(
                        tid,
                        &expected,
                        base_cpuset,
                        cpuset_name,
                        &mut cpuset_cache,
                    ) {
                        Ok(()) => mark_managed_cpuset_success(managed_tids, tid),
                        Err(err) if is_thread_gone_error(&err) => {
                            stale_tids.push(tid);
                            continue;
                        }
                        Err(err) => {
                            mark_managed_cpuset_failure(managed_tids, tid, now_elapsed);
                            if !is_cpuset_expected_reject(&err)
                                && should_log_detail(detail_log, &mut failed_details)
                            {
                                eprintln!(
                                    "[RS] cpuset 重新同步失败 进程={} 线程={} 期望={} 错误={}",
                                    entry.tgid,
                                    tid,
                                    expected.to_list(),
                                    error_text_zh(&err)
                                );
                            }
                        }
                    }
                }
                match set_affinity(tid, &expected) {
                    Ok(()) => {
                        stats.applied += 1;
                        match read_allowed_mask(entry.tgid, tid) {
                            Ok(Some(restored))
                                if restored == expected || restored.is_subset_of(&expected) =>
                            {
                                mark_managed_affinity_checked(
                                    managed_tids,
                                    tid,
                                    Some(expected_low64),
                                    restored.to_low64(),
                                    now_elapsed,
                                    interval_ms,
                                );
                                let recovered = current != restored
                                    || !current.is_subset_of(&expected);
                                if recovered {
                                    stats.mismatched += 1;
                                }
                                if recovered
                                    && should_log_detail(detail_log, &mut mismatch_details)
                                {
                                    println!(
                                        "[RS] 绑核抢写已恢复 进程={} 线程={} 期望={} 原值={}",
                                        entry.tgid,
                                        tid,
                                        expected.to_list(),
                                        current.to_list()
                                    );
                                }
                            }
                            Ok(Some(restored)) => {
                                stats.mismatched += 1;
                                mark_managed_affinity_checked(
                                    managed_tids,
                                    tid,
                                    Some(expected_low64),
                                    restored.to_low64(),
                                    now_elapsed,
                                    interval_ms,
                                );
                                if should_log_detail(detail_log, &mut mismatch_details) {
                                    eprintln!(
                                        "[RS] 绑核抢写恢复后仍不一致 进程={} 线程={} 期望={} 实际={}",
                                        entry.tgid,
                                        tid,
                                        expected.to_list(),
                                        restored.to_list()
                                    );
                                }
                            }
                            Ok(None) | Err(_) => {
                                mark_managed_affinity_checked(
                                    managed_tids,
                                    tid,
                                    Some(expected_low64),
                                    entry.verified_mask_low64,
                                    now_elapsed,
                                    interval_ms,
                                );
                            }
                        }
                    }
                    Err(err) if is_thread_gone_error(&err) => stale_tids.push(tid),
                    Err(err) if is_affinity_restricted_error(&err) => {
                        stats.restricted += 1;
                        set_managed_cpuset_synced(managed_tids, tid, false);
                        mark_managed_affinity_checked(
                            managed_tids,
                            tid,
                            Some(expected_low64),
                            current.to_low64(),
                            now_elapsed,
                            interval_ms,
                        );
                    }
                    Err(err) => {
                        stats.failed += 1;
                        mark_managed_affinity_checked(
                            managed_tids,
                            tid,
                            Some(expected_low64),
                            current.to_low64(),
                            now_elapsed,
                            interval_ms,
                        );
                        if should_log_detail(detail_log, &mut failed_details) {
                            eprintln!(
                                "[RS] 绑核抢写恢复失败 进程={} 线程={} 期望={} 错误={}",
                                entry.tgid,
                                tid,
                                expected.to_list(),
                                error_text_zh(&err)
                            );
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(err) if is_thread_gone_error(&err) => stale_tids.push(tid),
            Err(_) => {
                mark_managed_affinity_checked(
                    managed_tids,
                    tid,
                    Some(expected_low64),
                    entry.verified_mask_low64,
                    now_elapsed,
                    interval_ms,
                );
            }
        }
    }

    for tid in stale_tids {
        managed_tids.remove(&tid);
    }
    let next_cursor = if snapshot_len > 0 {
        start_cursor
            .saturating_add(foreground_checked.saturating_add(background_checked))
            % snapshot_len
    } else {
        0
    };
    if detail_log {
        log_limited_detail_count("绑核抢写恢复", mismatch_details);
        log_limited_detail_count("绑核抢写恢复失败", failed_details);
    }
    (stats, next_cursor)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedTidIdentityStatus {
    Current,
    GoneOrReused,
    Unreadable,
}

fn managed_tid_identity_status(tid: i32, entry: &ManagedTidEntry) -> ManagedTidIdentityStatus {
    let (Some(expected_tgid_start), Some(expected_tid_start)) =
        (entry.tgid_starttime, entry.starttime)
    else {
        return ManagedTidIdentityStatus::Unreadable;
    };
    let process_path = PathBuf::from(format!("/proc/{}", entry.tgid));
    match read_proc_starttime(&process_path) {
        Ok(value) if value == expected_tgid_start => {}
        Ok(_) => return ManagedTidIdentityStatus::GoneOrReused,
        Err(err) if is_thread_gone_error(&err) => {
            return ManagedTidIdentityStatus::GoneOrReused;
        }
        Err(_) => return ManagedTidIdentityStatus::Unreadable,
    }
    let task_path = process_path.join("task").join(tid.to_string());
    match read_proc_starttime(&task_path) {
        Ok(value) if value == expected_tid_start => ManagedTidIdentityStatus::Current,
        Ok(_) => ManagedTidIdentityStatus::GoneOrReused,
        Err(err) if is_thread_gone_error(&err) => ManagedTidIdentityStatus::GoneOrReused,
        Err(_) => ManagedTidIdentityStatus::Unreadable,
    }
}

fn mark_managed_affinity_checked(
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    tid: i32,
    desired_mask_low64: Option<u64>,
    verified_mask_low64: Option<u64>,
    now_elapsed: u64,
    interval_ms: u64,
) {
    let Some(entry) = managed_tids.get_mut(&tid) else {
        return;
    };
    entry.desired_mask_low64 = desired_mask_low64;
    entry.verified_mask_low64 = verified_mask_low64;
    entry.last_affinity_check_elapsed_ms = now_elapsed;
    entry.next_affinity_check_elapsed_ms = next_affinity_check_slot(
        tid,
        entry.starttime.unwrap_or(0),
        now_elapsed,
        interval_ms,
    );
}

fn set_managed_cpuset_synced(
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    tid: i32,
    synced: bool,
) {
    if let Some(entry) = managed_tids.get_mut(&tid) {
        entry.cpuset_synced = synced;
    }
}

fn cpuset_retry_due(entry: &ManagedTidEntry, now_elapsed: u64) -> bool {
    entry.cpuset_retry_after_elapsed_ms == 0
        || now_elapsed >= entry.cpuset_retry_after_elapsed_ms
}

fn next_cpuset_retry(failure_count: u8, now_elapsed: u64) -> (u8, u64) {
    let next_count = failure_count.saturating_add(1);
    let exponent = next_count.saturating_sub(1).min(5) as u32;
    let delay = CPUSET_RETRY_INITIAL_MS
        .saturating_mul(1u64 << exponent)
        .min(CPUSET_RETRY_MAX_MS);
    (next_count, now_elapsed.saturating_add(delay))
}

fn mark_managed_cpuset_success(
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    tid: i32,
) {
    if let Some(entry) = managed_tids.get_mut(&tid) {
        entry.cpuset_synced = true;
        entry.cpuset_failure_count = 0;
        entry.cpuset_retry_after_elapsed_ms = 0;
    }
}

fn mark_managed_cpuset_failure(
    managed_tids: &mut HashMap<i32, ManagedTidEntry>,
    tid: i32,
    now_elapsed: u64,
) {
    if let Some(entry) = managed_tids.get_mut(&tid) {
        entry.cpuset_synced = false;
        (entry.cpuset_failure_count, entry.cpuset_retry_after_elapsed_ms) =
            next_cpuset_retry(entry.cpuset_failure_count, now_elapsed);
    }
}

fn next_affinity_check_slot(
    tid: i32,
    starttime: u64,
    now_elapsed: u64,
    interval_ms: u64,
) -> u64 {
    let interval = interval_ms.max(1);
    let round = now_elapsed / interval;
    // 主循环约 2 秒一轮，单纯在同一个 2 秒窗内设置毫秒相位仍会在下一轮一起到期。
    // 按线程和当前轮次分成相邻两轮，既把读取错开，最迟也只延后到两个验证周期。
    let wait_rounds = 1 + ((affinity_slot_hash(tid, starttime) ^ round) & 1);
    now_elapsed.saturating_add(interval.saturating_mul(wait_rounds))
}

fn accepted_managed_mask(
    entry: Option<&ManagedTidEntry>,
    current: &CpuMask,
    expected: &CpuMask,
) -> bool {
    if current == expected {
        return true;
    }
    if !current.is_subset_of(expected) {
        return false;
    }
    let Some(entry) = entry else {
        return false;
    };
    let current_low64 = current.to_low64();
    current_low64.is_some()
        && current_low64 == entry.verified_mask_low64
        && entry.verified_mask_low64 != entry.desired_mask_low64
}

fn managed_action_can_defer(
    cached: Option<&ManagedTidEntry>,
    desired_changed: bool,
) -> bool {
    cached.is_some_and(|entry| !desired_changed && entry.cpuset_synced)
}

fn managed_restore_baseline_ready(entry: &ManagedTidEntry) -> bool {
    entry.restore_persisted
        && (entry.original_mask_low64.is_some() || entry.original_cpuset.is_some())
}

fn affinity_slot_hash(tid: i32, starttime: u64) -> u64 {
    let mut value = (tid as u64) ^ starttime.rotate_left(13);
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value
}

impl ApplyStats {
    fn merge(&mut self, other: ApplyStats) {
        self.applied = self.applied.saturating_add(other.applied);
        self.skipped = self.skipped.saturating_add(other.skipped);
        self.failed = self.failed.saturating_add(other.failed);
        self.restricted = self.restricted.saturating_add(other.restricted);
        self.invalid_rules = self.invalid_rules.saturating_add(other.invalid_rules);
        self.mismatched = self.mismatched.saturating_add(other.mismatched);
        self.cpuset_failed = self.cpuset_failed.saturating_add(other.cpuset_failed);
    }
}

fn action_identity_is_current(
    hit: &ProcHit,
    action: &ThreadAction,
    phase: &str,
    detail_log: bool,
    identity_details: &mut usize,
) -> bool {
    match proc_thread_identity_matches(hit, action) {
        Ok(true) => true,
        Ok(false) => {
            if should_log_detail(detail_log, identity_details) {
                eprintln!(
                    "[RS] 跳过已变化的进程/线程身份 阶段={} 进程={} 线程={} 线程名={} 规则={}",
                    phase, hit.pid, action.tid, action.name, action.rule
                );
            }
            false
        }
        Err(err) => {
            if should_log_detail(detail_log, identity_details) {
                eprintln!(
                    "[RS] 复核进程/线程身份失败 阶段={} 进程={} 线程={} 线程名={} 规则={} 错误={}",
                    phase,
                    hit.pid,
                    action.tid,
                    action.name,
                    action.rule,
                    error_text_zh(&err)
                );
            }
            false
        }
    }
}

fn should_log_detail(detail_log: bool, detail_count: &mut usize) -> bool {
    if !detail_log {
        return false;
    }
    let should_log = *detail_count < MAX_ERROR_DETAILS_PER_ROUND;
    *detail_count += 1;
    should_log
}

fn log_limited_detail_count(kind: &str, detail_count: usize) {
    if detail_count > MAX_ERROR_DETAILS_PER_ROUND {
        eprintln!(
            "[RS] {kind}: 本轮共 {} 条, 仅显示前 {} 条明细",
            detail_count, MAX_ERROR_DETAILS_PER_ROUND
        );
    }
}

fn is_cpuset_expected_reject(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(1 | 13 | 19 | 22 | 30 | 95))
        || matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
        )
}

fn is_affinity_restricted_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(1 | 13 | 22))
        || matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
        )
}

fn is_thread_gone_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(2 | 3)) || err.kind() == io::ErrorKind::NotFound
}

fn error_text_zh(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(1) => "权限不足(EPERM/1), 内核或安全策略拒绝操作".to_string(),
        Some(2) => "路径不存在(ENOENT/2), 目标进程或线程可能已经退出".to_string(),
        Some(3) => "线程不存在(ESRCH/3), 目标线程可能已经结束".to_string(),
        Some(13) => "权限不足(EACCES/13), 无法访问目标文件或线程".to_string(),
        Some(16) => "资源忙(EBUSY/16), 系统暂时无法完成操作".to_string(),
        Some(19) => "设备不存在(ENODEV/19), 目标 cpuset 或系统节点不可用".to_string(),
        Some(22) => "无效参数(EINVAL/22), CPU 核心范围对当前线程不可用或 CPU mask 非法".to_string(),
        Some(code) => format!("系统错误(OS {code})"),
        None => match err.kind() {
            io::ErrorKind::NotFound => "路径不存在, 目标进程或线程可能已经退出".to_string(),
            io::ErrorKind::PermissionDenied => "权限不足, 内核或安全策略拒绝操作".to_string(),
            io::ErrorKind::InvalidInput => {
                "无效参数, CPU 核心范围对当前线程不可用或 CPU mask 非法".to_string()
            }
            _ => "I/O 操作失败".to_string(),
        },
    }
}

impl CpuMask {
    fn empty() -> Self {
        Self {
            words: [0; CPU_MASK_WORDS],
        }
    }

    fn parse(input: &str) -> Option<Self> {
        let mut mask = Self::empty();
        let mut any = false;

        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (start, end) = if let Some((left, right)) = part.split_once('-') {
                let start = left.trim().parse::<usize>().ok()?;
                let end = right.trim().parse::<usize>().ok()?;
                if start > end {
                    return None;
                }
                (start, end)
            } else {
                let cpu = part.parse::<usize>().ok()?;
                (cpu, cpu)
            };

            for cpu in start..=end {
                mask.set(cpu)?;
                any = true;
            }
        }

        if any {
            Some(mask)
        } else {
            None
        }
    }

    fn set(&mut self, cpu: usize) -> Option<()> {
        let word = cpu / 64;
        if word >= CPU_MASK_WORDS {
            return None;
        }
        let bit = cpu % 64;
        self.words[word] |= 1u64 << bit;
        Some(())
    }

    fn or_assign(&mut self, other: &Self) {
        for (left, right) in self.words.iter_mut().zip(other.words.iter()) {
            *left |= *right;
        }
    }

    fn intersection(&self, other: &Self) -> Self {
        let mut mask = Self::empty();
        for ((out, left), right) in mask
            .words
            .iter_mut()
            .zip(self.words.iter())
            .zip(other.words.iter())
        {
            *out = left & right;
        }
        mask
    }

    fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    fn to_list(&self) -> String {
        let mut ranges = Vec::new();
        let mut cpu = 0usize;
        let max = CPU_MASK_WORDS * 64;

        while cpu < max {
            if !self.contains(cpu) {
                cpu += 1;
                continue;
            }

            let start = cpu;
            while cpu + 1 < max && self.contains(cpu + 1) {
                cpu += 1;
            }
            let end = cpu;
            if start == end {
                ranges.push(start.to_string());
            } else {
                ranges.push(format!("{start}-{end}"));
            }
            cpu += 1;
        }

        ranges.join(",")
    }

    fn contains(&self, cpu: usize) -> bool {
        let word = cpu / 64;
        if word >= CPU_MASK_WORDS {
            return false;
        }
        (self.words[word] & (1u64 << (cpu % 64))) != 0
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        self.words
            .iter()
            .zip(other.words.iter())
            .all(|(left, right)| (left & !right) == 0)
    }

    fn to_low64(&self) -> Option<u64> {
        self.words[1..].iter().all(|word| *word == 0).then_some(self.words[0])
    }

    fn from_low64(value: u64) -> Self {
        let mut mask = Self::empty();
        mask.words[0] = value;
        mask
    }
}

fn read_allowed_mask(pid: i32, tid: i32) -> io::Result<Option<CpuMask>> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        match read_allowed_mask_syscall(tid) {
            Ok(mask) => return Ok(Some(mask)),
            Err(err) if matches!(err.raw_os_error(), Some(22 | 38)) => {}
            Err(err) => return Err(err),
        }
    }
    read_allowed_mask_proc(pid, tid)
}

fn read_allowed_mask_proc(pid: i32, tid: i32) -> io::Result<Option<CpuMask>> {
    let status = fs::read_to_string(format!("/proc/{pid}/task/{tid}/status"))?;
    for line in status.lines() {
        let Some(value) = line.strip_prefix("Cpus_allowed_list:") else {
            continue;
        };
        return Ok(CpuMask::parse(value.trim()));
    }
    Ok(None)
}

fn capture_tid_restore_state(
    hit: &ProcHit,
    action: &ThreadAction,
    cpuset_name: &str,
) -> Option<(Option<u64>, Option<String>)> {
    let pid = hit.pid;
    let tid = action.tid;
    let mut original_mask_low64 = read_allowed_mask(pid, tid)
        .ok()
        .flatten()
        .and_then(|mask| mask.to_low64());
    let mut original_cpuset = fs::read_to_string(format!("/proc/{pid}/task/{tid}/cpuset"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| valid_cpuset_relative_path(value));
    if let Some(current) = original_cpuset.as_deref() {
        let normalized = normalized_restore_cpuset(current, cpuset_name);
        if normalized != current {
            // daemon 异常重启后，当前值可能就是上一次遗留的 AppOpt mask 子组。
            // 此时不能把旧规则 mask 当成“接管前状态”，改用父组/根组允许范围。
            let cpus_path = Path::new("/dev/cpuset")
                .join(normalized.trim_start_matches('/'))
                .join("cpus");
            original_mask_low64 = fs::read_to_string(cpus_path)
                .ok()
                .and_then(|cpus| CpuMask::parse(cpus.trim()))
                .and_then(|mask| mask.to_low64())
                .or_else(|| {
                    read_present_cpus()
                        .and_then(|cpus| CpuMask::parse(&cpus))
                        .and_then(|mask| mask.to_low64())
                });
            original_cpuset = Some(normalized);
        }
    }
    // 基线读取完成后重新对照扫描阶段记录的 starttime；期间如果发生 TID 复用，
    // 丢弃本次基线，避免把新线程状态写进旧线程记录。至少有一个可恢复维度时
    // 才允许进入 managed_tids。
    if proc_thread_identity_matches(hit, action).ok() != Some(true)
        || (original_mask_low64.is_none() && original_cpuset.is_none())
    {
        return None;
    }
    Some((original_mask_low64, original_cpuset))
}

fn restore_managed_tid(
    tid: i32,
    entry: &ManagedTidEntry,
    cpuset_name: &str,
) -> io::Result<()> {
    match managed_tid_identity_status(tid, entry) {
        ManagedTidIdentityStatus::Current => {}
        ManagedTidIdentityStatus::GoneOrReused => {
            return Err(io::Error::from_raw_os_error(3));
        }
        ManagedTidIdentityStatus::Unreadable => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "线程身份暂时无法读取",
            ));
        }
    }

    let mut cpuset_error = None;
    let mut restore_cpuset = None;
    if let Some(cpuset) = entry.original_cpuset.as_deref() {
        let cpuset = normalized_restore_cpuset(cpuset, cpuset_name);
        if let Err(err) = move_tid_to_existing_cpuset(tid, &cpuset) {
            cpuset_error = Some(err);
        } else {
            restore_cpuset = Some(cpuset);
        }
    }
    let mut affinity_error = None;
    if let Some(mask) = entry.original_mask_low64.filter(|mask| *mask != 0) {
        let original = CpuMask::from_low64(mask);
        // cpuset/任务画像可能在 daemon 重启后收窄线程可用核心。必须读取迁回后
        // cpuset 的有效范围，而不能使用线程当前 affinity；后者仍可能是 AppOpt
        // 的旧绑定范围，会导致本应恢复到 0-7 的线程只保留在 4-7。
        let cpuset_allowed = restore_cpuset
            .as_deref()
            .and_then(read_existing_cpuset_mask)
            .or_else(|| read_present_cpus().and_then(|cpus| CpuMask::parse(&cpus)));
        let online = read_online_cpu_mask();
        let allowed = match (cpuset_allowed, online) {
            (Some(cpuset), Some(online)) => {
                let effective = cpuset.intersection(&online);
                (!effective.is_empty()).then_some(effective)
            }
            (Some(cpuset), None) => Some(cpuset),
            (None, Some(online)) => Some(online),
            (None, None) => None,
        };
        let target = allowed
            .map(|allowed| restore_affinity_target(&original, &allowed))
            .unwrap_or_else(|| Some(original.clone()));
        let Some(target) = target else {
            return Err(io::Error::from_raw_os_error(22));
        };
        if let Err(err) = set_affinity(tid, &target) {
            affinity_error = Some(err);
        }
    }
    // 只有 cpuset 与 affinity 都恢复成功才算完成；如果 ROM 拒绝了其中一层，
    // 上层只会延迟重试一次，随后清理旧基线，避免无限刷 EINVAL。
    affinity_error.or(cpuset_error).map_or(Ok(()), Err)
}

fn restore_affinity_target(original: &CpuMask, current: &CpuMask) -> Option<CpuMask> {
    let clipped = original.intersection(current);
    (!clipped.is_empty()).then_some(clipped)
}

fn read_existing_cpuset_mask(cpuset: &str) -> Option<CpuMask> {
    if !valid_cpuset_relative_path(cpuset) {
        return None;
    }
    let root = Path::new("/dev/cpuset");
    let mut path = root.join(cpuset.trim_start_matches('/'));
    loop {
        for name in ["cpus.effective", "cpus"] {
            if let Some(mask) = fs::read_to_string(path.join(name))
                .ok()
                .and_then(|value| CpuMask::parse(value.trim()))
            {
                return Some(mask);
            }
        }
        if path == root || !path.pop() || !path.starts_with(root) {
            return None;
        }
    }
}

fn read_online_cpu_mask() -> Option<CpuMask> {
    fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|value| CpuMask::parse(value.trim()))
}

fn normalized_restore_cpuset(original: &str, cpuset_name: &str) -> String {
    let mut parts = original
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() >= 2
        && parts[parts.len() - 2] == cpuset_name
        && CpuMask::parse(parts[parts.len() - 1]).is_some()
    {
        // daemon 异常重启后可能只能看到上一次留下的 AppOpt 子组。至少退回父组，
        // 避免继续被旧 CPU 范围限制；自定义 cpuset 的父组仍保留 ROM 原有语义。
        if cpuset_name == DEFAULT_CPUSET_NAME {
            parts.clear();
        } else {
            parts.pop();
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn valid_cpuset_relative_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && path
            .split('/')
            .all(|part| part.is_empty() || (part != "." && part != ".." && !part.contains('\0')))
}

fn move_tid_to_existing_cpuset(tid: i32, cpuset: &str) -> io::Result<()> {
    if !valid_cpuset_relative_path(cpuset) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "无效的原 cpuset 路径",
        ));
    }
    let path = Path::new("/dev/cpuset").join(cpuset.trim_start_matches('/'));
    let mut tasks = fs::OpenOptions::new()
        .append(true)
        .open(path.join("tasks"))?;
    writeln!(tasks, "{tid}")
}

fn move_tid_to_cpuset(
    tid: i32,
    mask: &CpuMask,
    base_cpuset: &Path,
    cpuset_name: &str,
    cache: &mut CpusetRoundCache,
) -> io::Result<()> {
    let cpuset_root = Path::new("/dev/cpuset");
    if !cpuset_root.exists() {
        return Ok(());
    }

    let cpus = mask.to_list();
    if cpus.is_empty() {
        return Ok(());
    }

    // 自定义名称可能指向 ROM 已有的 cpuset。已有自定义目录只作为父组使用，
    // 不改写其 cpus/mems/权限；AppOpt 自己的默认目录仍按旧逻辑维护。
    if !cache.base_ready {
        if !base_cpuset.exists() || cpuset_name == DEFAULT_CPUSET_NAME {
            let present = read_present_cpus().unwrap_or_else(|| cpus.clone());
            ensure_cpuset_dir(base_cpuset, &present, "0")?;
        }
        cache.base_ready = true;
    }

    let target = base_cpuset.join(&cpus);
    if !cache.ready_masks.contains(&cpus) {
        ensure_cpuset_dir(&target, &cpus, "0")?;
        cache.ready_masks.insert(cpus.clone());
    }

    let tasks_path = target.join("tasks");
    let mut tasks = fs::OpenOptions::new().append(true).open(&tasks_path);
    if tasks
        .as_ref()
        .is_err_and(|err| err.kind() == io::ErrorKind::NotFound)
    {
        // ROM 可能在本轮中途清理自建 cpuset；清掉本轮缓存并重建一次。
        cache.ready_masks.remove(&cpus);
        if !base_cpuset.exists() {
            cache.base_ready = false;
            let present = read_present_cpus().unwrap_or_else(|| cpus.clone());
            ensure_cpuset_dir(base_cpuset, &present, "0")?;
            cache.base_ready = true;
        }
        ensure_cpuset_dir(&target, &cpus, "0")?;
        cache.ready_masks.insert(cpus);
        tasks = fs::OpenOptions::new().append(true).open(tasks_path);
    }
    let mut tasks = tasks?;
    writeln!(tasks, "{tid}")?;
    Ok(())
}

#[derive(Default)]
struct CpusetRoundCache {
    base_ready: bool,
    ready_masks: HashSet<String>,
}

fn read_present_cpus() -> Option<String> {
    fs::read_to_string("/sys/devices/system/cpu/present")
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn ensure_cpuset_dir(path: &Path, cpus: &str, mems: &str) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_cpuset_dir_owner_mode(path);
    fs::write(path.join("cpus"), cpus)?;
    fs::write(path.join("mems"), mems)?;
    Ok(())
}

#[cfg(unix)]
fn set_cpuset_dir_owner_mode(path: &Path) {
    let Some(path) = path.to_str() else {
        return;
    };
    let Ok(c_path) = CString::new(path) else {
        return;
    };
    unsafe {
        libc::chmod(c_path.as_ptr(), 0o755);
        libc::chown(c_path.as_ptr(), 0, 0);
    }
}

#[cfg(not(unix))]
fn set_cpuset_dir_owner_mode(_path: &Path) {}

#[cfg(any(target_os = "android", target_os = "linux"))]
unsafe extern "C" {
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> i32;
    fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> i32;
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_allowed_mask_syscall(tid: i32) -> io::Result<CpuMask> {
    let mut mask = CpuMask::empty();
    let rc = unsafe {
        sched_getaffinity(
            tid,
            std::mem::size_of_val(&mask.words),
            mask.words.as_mut_ptr().cast::<u8>(),
        )
    };
    if rc == 0 {
        Ok(mask)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn set_affinity(tid: i32, mask: &CpuMask) -> io::Result<()> {
    let rc = unsafe {
        sched_setaffinity(
            tid,
            std::mem::size_of_val(&mask.words),
            mask.words.as_ptr().cast::<u8>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn set_affinity(_tid: i32, _mask: &CpuMask) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod affinity_state_tests {
    use super::*;

    fn managed_entry(cpuset_synced: bool) -> ManagedTidEntry {
        ManagedTidEntry {
            tgid: 1,
            tgid_starttime: Some(1),
            starttime: Some(1),
            last_seen_round: 1,
            cpuset_synced,
            cpuset_failure_count: 0,
            cpuset_retry_after_elapsed_ms: 0,
            desired_mask_low64: Some(0xff),
            verified_mask_low64: Some(0xff),
            last_affinity_check_elapsed_ms: 1,
            next_affinity_check_elapsed_ms: 1,
            original_mask_low64: Some(0xff),
            original_cpuset: Some("/top-app".to_string()),
            restore_persisted: true,
            restore_pending: false,
        }
    }

    #[test]
    fn restore_path_leaves_the_previous_appopt_mask_child() {
        assert_eq!(normalized_restore_cpuset("/AppOptRs/4-5", "AppOptRs"), "/");
        assert_eq!(
            normalized_restore_cpuset("/top-app/4-5", "top-app"),
            "/top-app"
        );
        assert_eq!(
            normalized_restore_cpuset("/top-app", "AppOptRs"),
            "/top-app"
        );
    }

    #[test]
    fn restore_affinity_is_clipped_to_the_current_allowed_mask() {
        let original = CpuMask::parse("0-7").unwrap();
        let current = CpuMask::parse("4-7").unwrap();
        let target = restore_affinity_target(&original, &current).unwrap();
        assert_eq!(target.to_list(), "4-7");

        let disjoint = CpuMask::parse("0-3").unwrap();
        assert!(restore_affinity_target(&disjoint, &current).is_none());
    }

    #[test]
    fn wider_mask_is_not_equal_to_its_old_subset() {
        let old = CpuMask::parse("4-5").unwrap();
        let wider = CpuMask::parse("4-7").unwrap();
        assert!(old.is_subset_of(&wider));
        assert_ne!(old, wider);
    }

    #[test]
    fn only_unchanged_synced_actions_defer_to_the_verify_queue() {
        let synced = managed_entry(true);
        let unsynced = managed_entry(false);

        assert!(managed_action_can_defer(Some(&synced), false));
        assert!(!managed_action_can_defer(Some(&synced), true));
        assert!(!managed_action_can_defer(Some(&unsynced), false));
        assert!(!managed_action_can_defer(None, false));
    }

    #[test]
    fn transient_journal_write_failure_only_blocks_unpersisted_entries() {
        let persisted = managed_entry(true);
        assert!(managed_restore_baseline_ready(&persisted));

        let mut pending_write = persisted.clone();
        pending_write.restore_persisted = false;
        assert!(!managed_restore_baseline_ready(&pending_write));
    }
}
