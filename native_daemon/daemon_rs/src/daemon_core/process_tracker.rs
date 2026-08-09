// 轻量进程索引。
//
// daemon 启动后把 pid_cache.tsv 加载到内存，日常只枚举 /proc 下的数字 PID：
// - 新 PID 和出生后 6 秒内的候选会读取 stat/comm/cmdline；
// - 稳定的非目标 PID 不再每 2 秒读取 stat；
// - 真正生成规则动作或 CLI 返回结果前仍重新校验 starttime 和 cmdline。
//
// 索引变更只标记 dirty，由主循环在本轮候选更新结束后统一原子写盘一次。
const PROCESS_INDEX_NAME_MAX_BYTES: usize = 127;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIndexEntry {
    pid: i32,
    starttime: u64,
    first_seen_elapsed_ms: u64,
    comm: String,
    cmdline: String,
}

#[derive(Debug, Default)]
struct ProcessIndex {
    entries: BTreeMap<i32, ProcessIndexEntry>,
    loaded: bool,
    dirty: bool,
    snapshot_complete: bool,
    last_flush_elapsed_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct ProcessIndexView {
    current_pids: BTreeSet<i32>,
    candidate_pids: BTreeSet<i32>,
    added: usize,
    exited: usize,
    refreshed: bool,
    loaded: bool,
}

#[derive(Debug, Default)]
struct ProcessIndexUpdate {
    candidate_pids: BTreeSet<i32>,
    added: usize,
    exited: usize,
    changed: bool,
    complete: bool,
}

fn ensure_process_index_loaded(index: &mut ProcessIndex) -> io::Result<()> {
    if index.loaded {
        return Ok(());
    }
    match load_process_index() {
        Ok(entries) => index.entries = entries,
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ) =>
        {
            // 缓存缺失、损坏或来自其他启动周期时，从本轮 /proc 快照重建。
            index.entries.clear();
            index.dirty = true;
        }
        Err(err) => return Err(err),
    }
    index.loaded = true;
    Ok(())
}

fn refresh_process_index(
    index: &mut ProcessIndex,
    now_elapsed: u64,
    rebuild_all: bool,
) -> io::Result<ProcessIndexView> {
    ensure_process_index_loaded(index)?;
    let current_pids = enumerate_proc_pids()?;
    let update = reconcile_process_index(
        &mut index.entries,
        &current_pids,
        now_elapsed,
        rebuild_all,
        |pid, old| read_process_index_entry(pid, now_elapsed, old),
    );
    index.dirty |= update.changed;
    if rebuild_all && !Path::new(PROCESS_CACHE_FILE).is_file() {
        index.dirty = true;
    }
    index.snapshot_complete = next_snapshot_completeness(
        index.snapshot_complete,
        rebuild_all,
        update.complete,
    );
    Ok(ProcessIndexView {
        current_pids,
        candidate_pids: update.candidate_pids,
        added: update.added,
        exited: update.exited,
        refreshed: true,
        loaded: true,
    })
}

fn next_snapshot_completeness(
    previous_complete: bool,
    rebuild_all: bool,
    refresh_complete: bool,
) -> bool {
    if rebuild_all {
        refresh_complete
    } else {
        previous_complete && refresh_complete
    }
}

fn load_process_index_view(
    index: &mut ProcessIndex,
    now_elapsed: u64,
) -> io::Result<ProcessIndexView> {
    ensure_process_index_loaded(index)?;
    Ok(ProcessIndexView {
        current_pids: index.entries.keys().copied().collect(),
        candidate_pids: process_index_candidate_pids(&index.entries, now_elapsed),
        loaded: true,
        ..ProcessIndexView::default()
    })
}

fn reconcile_process_index<F>(
    entries: &mut BTreeMap<i32, ProcessIndexEntry>,
    current_pids: &BTreeSet<i32>,
    now_elapsed: u64,
    rebuild_all: bool,
    mut read_entry: F,
) -> ProcessIndexUpdate
where
    F: FnMut(i32, Option<&ProcessIndexEntry>) -> io::Result<ProcessIndexEntry>,
{
    let added = current_pids
        .iter()
        .filter(|pid| !entries.contains_key(pid))
        .count();
    let exited = entries
        .keys()
        .filter(|pid| !current_pids.contains(pid))
        .count();
    entries.retain(|pid, _| current_pids.contains(pid));
    let mut changed = exited > 0;
    let mut complete = true;

    for pid in current_pids.iter().copied() {
        let should_refresh = rebuild_all
            || entries.get(&pid).is_none_or(|entry| {
                now_elapsed.saturating_sub(entry.first_seen_elapsed_ms)
                    <= PID_DISCOVERY_RETRY_MS
            });
        if !should_refresh {
            continue;
        }

        let previous_starttime = entries.get(&pid).map(|entry| entry.starttime);
        let mut entry = match read_entry(pid, entries.get(&pid)) {
            Ok(entry) => entry,
            Err(err) => {
                // 进程在快照后退出是正常竞态；其他错误意味着本轮索引存在真实读取缺口，
                // 后续扫描仍保留正向命中，但不能据此产生规则健康负向结论。
                if err.kind() != io::ErrorKind::NotFound {
                    complete = false;
                }
                continue;
            }
        };
        if let Some(old) = entries.get(&pid) {
            if previous_starttime == Some(entry.starttime) {
                entry.first_seen_elapsed_ms = old.first_seen_elapsed_ms;
            } else {
                entry.first_seen_elapsed_ms = now_elapsed;
            }
        }
        if entries.get(&pid).is_none_or(|old| old != &entry) {
            changed = true;
        }
        entries.insert(pid, entry);
    }

    ProcessIndexUpdate {
        candidate_pids: process_index_candidate_pids(entries, now_elapsed),
        added,
        exited,
        changed,
        complete,
    }
}

fn process_index_candidate_pids(
    entries: &BTreeMap<i32, ProcessIndexEntry>,
    now_elapsed: u64,
) -> BTreeSet<i32> {
    entries
        .values()
        .filter(|entry| {
            now_elapsed.saturating_sub(entry.first_seen_elapsed_ms) <= PID_DISCOVERY_RETRY_MS
        })
        .map(|entry| entry.pid)
        .collect()
}

fn process_index_mark_candidates(
    index: &mut ProcessIndex,
    pids: impl IntoIterator<Item = i32>,
    now_elapsed: u64,
) -> io::Result<()> {
    ensure_process_index_loaded(index)?;
    for pid in pids {
        if let Some(entry) = index.entries.get_mut(&pid) {
            if process_index_candidate_timestamp_should_refresh(
                entry.first_seen_elapsed_ms,
                now_elapsed,
            ) {
                entry.first_seen_elapsed_ms = now_elapsed;
                index.dirty = true;
            }
            continue;
        }
        if let Ok(entry) = read_process_index_entry(pid, now_elapsed, None) {
            index.entries.insert(pid, entry);
            index.dirty = true;
        }
    }
    Ok(())
}

fn process_index_candidate_timestamp_should_refresh(first_seen: u64, now_elapsed: u64) -> bool {
    now_elapsed < first_seen
        || now_elapsed.saturating_sub(first_seen) > PID_DISCOVERY_RETRY_MS
}

fn flush_process_index(index: &mut ProcessIndex, now_elapsed: u64) -> io::Result<()> {
    if !index.dirty {
        return Ok(());
    }
    if !process_index_flush_due(index.last_flush_elapsed_ms, now_elapsed) {
        // 进程 churn 时先保留内存索引，最多延后十秒写盘；下一轮仍会重试，
        // 不影响当前规则命中，也避免频繁整份重写约 50 KB 的缓存文件。
        return Ok(());
    }
    write_process_index(&index.entries, now_elapsed)?;
    index.dirty = false;
    index.last_flush_elapsed_ms = Some(now_elapsed);
    Ok(())
}

fn process_index_flush_due(last_flush_elapsed_ms: Option<u64>, now_elapsed: u64) -> bool {
    last_flush_elapsed_ms.is_none_or(|last| {
        now_elapsed < last || now_elapsed.saturating_sub(last) >= PID_CACHE_WRITE_MIN_MS
    })
}

fn read_process_index_entry(
    pid: i32,
    now_elapsed: u64,
    old: Option<&ProcessIndexEntry>,
) -> io::Result<ProcessIndexEntry> {
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let starttime = read_proc_starttime(&proc_path)?;
    let comm = truncate_process_index_name(&read_comm(&proc_path)?);
    let cmdline = truncate_process_index_name(&read_cmdline(pid)?);
    Ok(ProcessIndexEntry {
        pid,
        starttime,
        first_seen_elapsed_ms: old
            .filter(|entry| entry.starttime == starttime)
            .map_or(now_elapsed, |entry| entry.first_seen_elapsed_ms),
        comm,
        cmdline,
    })
}

fn load_process_index() -> io::Result<BTreeMap<i32, ProcessIndexEntry>> {
    let content = fs::read_to_string(PROCESS_CACHE_FILE)?;
    let current_boot_id = fs::read_to_string(BOOT_ID_FILE).unwrap_or_default();
    parse_process_index_content(&content, current_boot_id.trim())
}

fn parse_process_index_content(
    content: &str,
    current_boot_id: &str,
) -> io::Result<BTreeMap<i32, ProcessIndexEntry>> {
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "进程索引缺少头部"))?;
    let mut header_fields = header.split('\t');
    if header_fields.next() != Some(PROCESS_INDEX_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "进程索引版本不兼容",
        ));
    }
    let stored_boot_id = header_fields.next().unwrap_or_default();
    if stored_boot_id.is_empty()
        || current_boot_id.is_empty()
        || stored_boot_id != current_boot_id
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "进程索引属于其他启动周期",
        ));
    }

    let mut entries = BTreeMap::new();
    for line in lines {
        let mut fields = line.split('\t');
        let Some(pid) = fields.next().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let Some(starttime) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let Some(first_seen_elapsed_ms) = fields.next().and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        let Some(comm) = fields.next().and_then(decode_process_index_hex) else {
            continue;
        };
        let Some(cmdline) = fields.next().and_then(decode_process_index_hex) else {
            continue;
        };
        if pid > 0 {
            entries.insert(
                pid,
                ProcessIndexEntry {
                    pid,
                    starttime,
                    first_seen_elapsed_ms,
                    comm,
                    cmdline,
                },
            );
        }
    }
    Ok(entries)
}

fn write_process_index(
    entries: &BTreeMap<i32, ProcessIndexEntry>,
    now_elapsed: u64,
) -> io::Result<()> {
    let boot_id = fs::read_to_string(BOOT_ID_FILE).unwrap_or_default();
    let boot_id = boot_id.trim();
    if boot_id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "无法读取 boot_id",
        ));
    }
    fs::create_dir_all(STATE_DIR)?;
    let output = serialize_process_index(entries, boot_id, now_elapsed);
    let temporary = format!("{PROCESS_CACHE_FILE}.{}.tmp", std::process::id());
    fs::write(&temporary, output)?;
    fs::rename(&temporary, PROCESS_CACHE_FILE).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })
}

fn serialize_process_index(
    entries: &BTreeMap<i32, ProcessIndexEntry>,
    boot_id: &str,
    now_elapsed: u64,
) -> String {
    let mut output = format!("{PROCESS_INDEX_MAGIC}\t{boot_id}\t{now_elapsed}\n");
    for entry in entries.values() {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            entry.pid,
            entry.starttime,
            entry.first_seen_elapsed_ms,
            encode_process_index_hex(&truncate_process_index_name(&entry.comm)),
            encode_process_index_hex(&truncate_process_index_name(&entry.cmdline))
        ));
    }
    output
}

fn load_process_index_for_cli() -> io::Result<ProcessIndex> {
    let mut index = ProcessIndex::default();
    ensure_process_index_loaded(&mut index)?;
    if index.dirty {
        let now_elapsed = elapsed_realtime_ms();
        let _ = refresh_process_index(&mut index, now_elapsed, true)?;
        flush_process_index(&mut index, now_elapsed)?;
    }
    Ok(index)
}

fn process_index_find_pids(name: &str) -> io::Result<Vec<i32>> {
    let mut index = load_process_index_for_cli()?;
    // --find-pid 必须返回同名进程的完整集合。缓存命中一个旧 helper 不能提前结束，
    // 否则同名的第二个/分身进程会被静默漏掉；CLI 是按需调用，全量刷新不影响常驻循环。
    let now_elapsed = elapsed_realtime_ms();
    let _ = refresh_process_index(&mut index, now_elapsed, true)?;
    flush_process_index(&mut index, now_elapsed)?;
    let mut pids = index
        .entries
        .values()
        .filter(|entry| {
            process_index_name_matches(entry, name)
                && process_index_current_name_matches(entry, name)
        })
        .map(|entry| entry.pid)
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn process_index_verified_package_pids(index: &ProcessIndex, pkg: &str) -> BTreeSet<i32> {
    let mut pids = BTreeSet::new();
    for entry in index.entries.values() {
        if !process_belongs_to_uid_package(&entry.cmdline, pkg) {
            continue;
        }
        let proc_path = PathBuf::from(format!("/proc/{}", entry.pid));
        if !read_proc_starttime(&proc_path).is_ok_and(|starttime| starttime == entry.starttime) {
            continue;
        }
        let Ok(current_cmdline) = read_cmdline(entry.pid) else {
            continue;
        };
        if process_belongs_to_uid_package(&current_cmdline, pkg) {
            pids.insert(entry.pid);
        }
    }
    pids
}

// FPS 线程运行在独立线程，不能借用 daemon 主循环中的 ProcessIndex。这里读取同一份
// 原子快照并只验证目标包候选；未命中时 FPS 自己仍会执行低频 /proc 恢复扫描。
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn process_index_find_package_pids(pkg: &str) -> io::Result<BTreeSet<i32>> {
    let index = load_process_index_for_cli()?;
    Ok(process_index_verified_package_pids(&index, pkg))
}

fn process_index_cached_package_pids(
    index: &ProcessIndex,
    packages: &BTreeSet<String>,
) -> BTreeSet<i32> {
    index
        .entries
        .values()
        .filter(|entry| process_index_entry_matches_packages(entry, packages))
        .map(|entry| entry.pid)
        .collect()
}

fn process_index_entry_matches_packages(
    entry: &ProcessIndexEntry,
    packages: &BTreeSet<String>,
) -> bool {
    let base = entry
        .cmdline
        .split_once(':')
        .map_or(entry.cmdline.as_str(), |(pkg, _)| pkg);
    packages.contains(base)
}

fn process_index_find_names(names: &[String]) -> io::Result<Vec<String>> {
    let mut index = load_process_index_for_cli()?;
    let mut matched = vec![false; names.len()];
    for (position, name) in names.iter().enumerate() {
        matched[position] = index.entries.values().any(|entry| {
            process_index_name_matches(entry, name)
                && process_index_current_name_matches(entry, name)
        });
    }

    if matched.iter().any(|value| !value) {
        let now_elapsed = elapsed_realtime_ms();
        for pid in enumerate_proc_pids()? {
            let Ok(entry) = read_process_index_entry(pid, now_elapsed, None) else {
                continue;
            };
            for (position, name) in names.iter().enumerate() {
                if !matched[position]
                    && process_index_name_matches(&entry, name)
                    && process_index_current_name_matches(&entry, name)
                {
                    matched[position] = true;
                }
            }
            if index.entries.get(&pid) != Some(&entry) {
                index.entries.insert(pid, entry);
                index.dirty = true;
            }
            if matched.iter().all(|value| *value) {
                break;
            }
        }
        flush_process_index(&mut index, now_elapsed)?;
    }

    Ok(names
        .iter()
        .zip(matched)
        .filter(|(_, matched)| *matched)
        .map(|(name, _)| name.clone())
        .collect())
}

fn process_index_print_pids(name: &str) -> io::Result<()> {
    let pids = process_index_find_pids(name)?;
    for pid in &pids {
        println!("{pid}");
    }
    if pids.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "进程索引未命中",
        ))
    } else {
        Ok(())
    }
}

fn process_index_print_names(names: &[String]) -> io::Result<()> {
    let found = process_index_find_names(names)?;
    for name in &found {
        println!("{name}");
    }
    Ok(())
}

fn process_index_name_matches(entry: &ProcessIndexEntry, name: &str) -> bool {
    entry.comm == name
        || entry.cmdline == name
        || Path::new(&entry.cmdline)
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|base| base == name)
}

fn process_index_current_name_matches(entry: &ProcessIndexEntry, name: &str) -> bool {
    let proc_path = PathBuf::from(format!("/proc/{}", entry.pid));
    if !read_proc_starttime(&proc_path).is_ok_and(|starttime| starttime == entry.starttime) {
        return false;
    }
    let current = ProcessIndexEntry {
        pid: entry.pid,
        starttime: entry.starttime,
        first_seen_elapsed_ms: entry.first_seen_elapsed_ms,
        comm: read_comm(&proc_path).unwrap_or_default(),
        cmdline: read_cmdline(entry.pid).unwrap_or_default(),
    };
    process_index_name_matches(&current, name)
}

fn encode_process_index_hex(value: &str) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn truncate_process_index_name(value: &str) -> String {
    if value.len() <= PROCESS_INDEX_NAME_MAX_BYTES {
        return value.to_string();
    }
    let mut end = PROCESS_INDEX_NAME_MAX_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn decode_process_index_hex(value: &str) -> Option<String> {
    if value == "-" {
        return Some(String::new());
    }
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(text, 16).ok()?);
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod process_index_tests {
    use super::*;

    fn entry(pid: i32, starttime: u64, first_seen: u64, cmdline: &str) -> ProcessIndexEntry {
        ProcessIndexEntry {
            pid,
            starttime,
            first_seen_elapsed_ms: first_seen,
            comm: cmdline.to_string(),
            cmdline: cmdline.to_string(),
        }
    }

    #[test]
    fn stable_entries_are_not_revalidated_on_regular_snapshot() {
        let mut entries = BTreeMap::from([(10, entry(10, 100, 1_000, "system_server"))]);
        let current = BTreeSet::from([10]);
        let mut reads = 0usize;
        let update = reconcile_process_index(
            &mut entries,
            &current,
            20_000,
            false,
            |_, _| {
                reads += 1;
                Err(io::Error::other("稳定 PID 不应读取身份"))
            },
        );

        assert_eq!(reads, 0);
        assert!(!update.changed);
        assert!(update.candidate_pids.is_empty());
        assert_eq!(entries.get(&10).unwrap().starttime, 100);
    }

    #[test]
    fn new_and_recent_candidates_are_refreshed_together() {
        let mut entries = BTreeMap::from([(10, entry(10, 100, 8_000, "zygote64"))]);
        let current = BTreeSet::from([10, 11]);
        let mut reads = Vec::new();
        let update = reconcile_process_index(
            &mut entries,
            &current,
            10_000,
            false,
            |pid, old| {
                reads.push(pid);
                Ok(entry(
                    pid,
                    old.map_or(200, |value| value.starttime),
                    10_000,
                    if pid == 10 { "com.example" } else { "com.new" },
                ))
            },
        );

        assert_eq!(reads, vec![10, 11]);
        assert_eq!(update.added, 1);
        assert!(update.changed);
        assert_eq!(update.candidate_pids, BTreeSet::from([10, 11]));
        assert_eq!(entries.get(&10).unwrap().first_seen_elapsed_ms, 8_000);
    }

    #[test]
    fn pid_reuse_resets_candidate_window() {
        let mut entries = BTreeMap::from([(42, entry(42, 100, 1_000, "old.process"))]);
        let current = BTreeSet::from([42]);
        let update = reconcile_process_index(
            &mut entries,
            &current,
            90_000,
            true,
            |pid, _| Ok(entry(pid, 200, 90_000, "com.example")),
        );

        assert!(update.changed);
        assert_eq!(update.candidate_pids, BTreeSet::from([42]));
        let current = entries.get(&42).unwrap();
        assert_eq!(current.starttime, 200);
        assert_eq!(current.first_seen_elapsed_ms, 90_000);
    }

    #[test]
    fn non_transient_candidate_read_error_blocks_negative_evidence() {
        let mut entries = BTreeMap::from([(10, entry(10, 100, 8_000, "com.example"))]);
        let current = BTreeSet::from([10]);
        let update = reconcile_process_index(
            &mut entries,
            &current,
            10_000,
            false,
            |_, _| Err(io::Error::other("procfs denied")),
        );

        assert!(!update.complete);
        assert_eq!(update.candidate_pids, BTreeSet::from([10]));
        assert_eq!(entries.get(&10).unwrap().starttime, 100);
    }

    #[test]
    fn regular_refresh_cannot_upgrade_incomplete_snapshot() {
        assert!(!next_snapshot_completeness(false, false, true));
        assert!(!next_snapshot_completeness(true, false, false));
        assert!(next_snapshot_completeness(true, false, true));
        assert!(next_snapshot_completeness(false, true, true));
        assert!(!next_snapshot_completeness(true, true, false));
    }

    #[test]
    fn cache_write_is_batched_during_process_churn() {
        assert!(process_index_flush_due(None, 100));
        assert!(!process_index_flush_due(Some(100), 9_999));
        assert!(process_index_flush_due(Some(100), 10_100));
        assert!(process_index_flush_due(Some(10_000), 9_000));
    }

    #[test]
    fn repeated_candidate_marks_do_not_rewrite_the_cache_inside_retry_window() {
        assert!(!process_index_candidate_timestamp_should_refresh(10_000, 12_000));
        assert!(!process_index_candidate_timestamp_should_refresh(10_000, 16_000));
        assert!(process_index_candidate_timestamp_should_refresh(10_000, 16_001));
        assert!(process_index_candidate_timestamp_should_refresh(10_000, 9_000));
    }

    #[test]
    fn multiple_candidate_marks_only_dirty_the_resident_index() {
        let mut index = ProcessIndex {
            entries: BTreeMap::from([
                (10, entry(10, 100, 1_000, "com.first")),
                (11, entry(11, 200, 2_000, "com.second")),
            ]),
            loaded: true,
            dirty: false,
            ..ProcessIndex::default()
        };

        process_index_mark_candidates(&mut index, [10, 11], 30_000).unwrap();

        assert!(index.dirty);
        assert_eq!(index.entries.get(&10).unwrap().first_seen_elapsed_ms, 30_000);
        assert_eq!(index.entries.get(&11).unwrap().first_seen_elapsed_ms, 30_000);
    }

    #[test]
    fn cache_format_round_trip_remains_compatible() {
        let entries = BTreeMap::from([
            (10, entry(10, 100, 1_000, "com.example")),
            (11, entry(11, 200, 2_000, "com.example:worker")),
        ]);
        let encoded = serialize_process_index(&entries, "boot-test", 3_000);
        let decoded = parse_process_index_content(&encoded, "boot-test").unwrap();

        assert_eq!(decoded, entries);
        assert!(parse_process_index_content(&encoded, "other-boot").is_err());
    }

    #[test]
    fn indexed_target_filter_uses_exact_base_package() {
        let packages = BTreeSet::from(["com.example".to_string()]);
        assert!(process_index_entry_matches_packages(
            &entry(1, 1, 1, "com.example:worker"),
            &packages
        ));
        assert!(!process_index_entry_matches_packages(
            &entry(2, 2, 2, "com.example.extra"),
            &packages
        ));
    }
}
