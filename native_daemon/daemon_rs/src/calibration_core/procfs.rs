// 校准模块专用 procfs 工具。
//
// 校准和常驻绑核扫描的目标不同：
// - 常驻扫描只关心规则命中后该把线程绑到哪里。
// - 校准扫描要收集主进程/子进程 CPU 使用率，所以会读取 stat 的 utime/stime。
//
// /proc 读取失败很常见：进程可能刚退出，线程可能刚结束。这里统一选择跳过，不把它当异常。
fn collect_pkg_processes(pkg: &str) -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(parse_pid_text) else {
            continue;
        };
        let Ok(cmdline) = read_cmdline(pid) else {
            continue;
        };
        if cmdline == pkg
            || cmdline
                .strip_prefix(pkg)
                .is_some_and(|rest| rest.starts_with(':'))
        {
            out.push(ProcInfo {
                pid,
                owner: cmdline,
            });
        }
    }
    out
}

fn read_command() -> io::Result<Option<String>> {
    let claimed = format!("{CALIB_CMD_FILE}.processing");
    match fs::metadata(&claimed) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            match fs::rename(CALIB_CMD_FILE, &claimed) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(err),
            }
        }
        Err(err) => return Err(err),
    }

    let before = fs::metadata(&claimed)?;
    if before.len() > 512 {
        eprintln!(
            "[CALIB] 忽略过大的校准命令文件: bytes={}",
            before.len()
        );
        match fs::remove_file(&claimed) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        return Ok(None);
    }
    let bytes = match fs::read(&claimed) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let after = match fs::metadata(&claimed) {
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
            match fs::remove_file(&claimed) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        return Ok(None);
    }

    match fs::remove_file(&claimed) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    Ok(text)
}

fn write_state(state: &str) -> io::Result<()> {
    fs::create_dir_all(CONFIG_DIR)?;
    fs::write(CALIB_STATE_FILE, state)
}

fn read_cmdline(pid: i32) -> io::Result<String> {
    let data = fs::read(format!("/proc/{pid}/cmdline"))?;
    let first = data.split(|byte| *byte == 0).next().unwrap_or_default();
    let basename = first
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or_default();
    Ok(String::from_utf8_lossy(basename).trim().to_string())
}

fn read_thread_stat(path: &str) -> Option<(String, u64, u64)> {
    let text = fs::read_to_string(path).ok()?;
    parse_thread_stat(&text)
}

fn parse_thread_stat(text: &str) -> Option<(String, u64, u64)> {
    let start = text.find('(')?;
    let end = text.rfind(')')?;
    if start >= end {
        return None;
    }
    // stat 的第二字段与 /proc/<pid>/task/<tid>/comm 来源相同。直接从这里取名，
    // 可以让每个线程每轮只读取一个 procfs 文件；rfind 能兼容名称自身包含 ')'。
    let name = text.get(start + 1..end)?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let rest = text.get(end + 1..)?.trim_start();
    let mut utime = None;
    let mut stime = None;
    let mut starttime = None;
    for (index, field) in rest.split_whitespace().enumerate() {
        match index {
            // rest 从 stat 的第 3 字段 state 开始，因此 14/15/22 对应 11/12/19。
            11 => utime = field.parse::<u64>().ok(),
            12 => stime = field.parse::<u64>().ok(),
            19 => {
                starttime = field.parse::<u64>().ok();
                break;
            }
            _ => {}
        }
    }
    Some((name, utime? + stime?, starttime?))
}

fn parse_pid_text(text: &str) -> Option<i32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let pid = text.parse::<i32>().ok()?;
    if pid > 0 && pid <= 4_194_304 {
        Some(pid)
    } else {
        None
    }
}

fn safe_file_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn safe_history_name(name: &str) -> String {
    // e1 明确标记可逆格式；旧历史没有此前缀，App 可继续按原样读取。
    // 仅保留安全可见 ASCII，其余 UTF-8 字节统一百分号编码，避免 | , ; 和控制字符
    // 破坏主行/子线程详情的分隔结构，也不会把真实线程名永久改成下划线。
    let mut encoded = String::with_capacity(name.len().saturating_add(3));
    encoded.push_str("e1:");
    for byte in name.as_bytes() {
        if (0x20..=0x7e).contains(byte) && !matches!(*byte, b'%' | b'|' | b',' | b';') {
            encoded.push(*byte as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

#[cfg(test)]
mod history_name_tests {
    use super::{parse_thread_stat, safe_history_name};

    fn stat_line(name: &str) -> String {
        format!(
            "123 ({name}) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20"
        )
    }

    #[test]
    fn thread_stat_reuses_comm_and_cpu_fields() {
        let (name, ticks, starttime) = parse_thread_stat(&stat_line("RenderThread")).unwrap();
        assert_eq!(name, "RenderThread");
        assert_eq!(ticks, 23);
        assert_eq!(starttime, 19);
    }

    #[test]
    fn thread_stat_accepts_spaces_and_closing_parentheses_in_name() {
        let (name, ticks, starttime) =
            parse_thread_stat(&stat_line("Render ) Thread 2")).unwrap();
        assert_eq!(name, "Render ) Thread 2");
        assert_eq!(ticks, 23);
        assert_eq!(starttime, 19);
    }

    #[test]
    fn thread_stat_rejects_empty_or_incomplete_input() {
        assert!(parse_thread_stat("123 () S 1 2 3").is_none());
        assert!(parse_thread_stat("123 RenderThread S 1 2 3").is_none());
        assert!(parse_thread_stat("123 (RenderThread) S 1 2 3").is_none());
    }

    #[test]
    fn history_name_uses_versioned_reversible_encoding() {
        assert_eq!(safe_history_name("RenderThread"), "e1:RenderThread");
        assert_eq!(safe_history_name("a|b,c;d%"), "e1:a%7Cb%2Cc%3Bd%25");
        assert_eq!(safe_history_name("线程"), "e1:%E7%BA%BF%E7%A8%8B");
    }
}
