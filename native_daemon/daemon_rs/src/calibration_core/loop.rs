// 校准后台线程入口。
//
// App 通过写 config/calibrate.cmd 控制校准，不和 daemon 建立长连接：
// - start <pkg>：开始采样某个应用。
// - stop / stop <pkg>：停止当前采样并生成规则。
//
// 这么设计是为了兼容 App 被系统回收、Activity 重建、悬浮窗关闭等场景。daemon 只认命令文件
// 和状态文件，不依赖 App 进程一直活着。
pub fn start_calibration_thread(config_file: PathBuf) -> bool {
    match thread::Builder::new()
        .name("AppOptRsCalibration".to_string())
        .spawn(move || {
        if let Err(err) = calibration_loop(config_file) {
            eprintln!("[CALIB] 校准线程已停止: {err}");
        }
        }) {
        Ok(_) => true,
        Err(err) => {
            eprintln!("[CALIB] 校准线程创建失败: {err}");
            false
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CalibrationCommand {
    Start(String),
    Stop(Option<String>),
}

fn parse_calibration_command(command: &str) -> Option<CalibrationCommand> {
    let command = command.trim();
    let (kind, value) = command
        .split_once(' ')
        .map_or((command, ""), |(kind, value)| (kind, value.trim()));
    let valid_pkg = |pkg: &str| {
        !pkg.is_empty()
            && pkg.len() <= 255
            && pkg.contains('.')
            && pkg
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':'))
    };
    match kind {
        "start" if valid_pkg(value) => Some(CalibrationCommand::Start(value.to_string())),
        "stop" if value.is_empty() => Some(CalibrationCommand::Stop(None)),
        "stop" if valid_pkg(value) => Some(CalibrationCommand::Stop(Some(value.to_string()))),
        _ => None,
    }
}

fn calibration_loop(config_file: PathBuf) -> io::Result<()> {
    if let Err(err) = fs::create_dir_all(CONFIG_DIR) {
        eprintln!("[CALIB] 初始化配置目录失败，将在后续命令中重试: {err}");
    }
    if let Err(err) = fs::create_dir_all(HISTORY_DIR) {
        eprintln!("[CALIB] 初始化历史目录失败，写入时将重试: {err}");
    }
    if let Err(err) = write_state("idle") {
        eprintln!("[CALIB] 初始状态写入失败，校准线程继续运行: {err}");
    }

    let mut session: Option<CalibSession> = None;
    let mut last_command_error_log: Option<Instant> = None;
    let mut last_progress_log_round: Option<usize> = None;
    loop {
        // App 通过写 calibrate.cmd 控制开始/停止。
        // daemon 侧不直接和 Activity 通信，避免 App 被杀时校准线程状态丢失。
        let command = match read_command() {
            Ok(command) => {
                last_command_error_log = None;
                command
            }
            Err(err) => {
                let now = Instant::now();
                if last_command_error_log
                    .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10))
                {
                    eprintln!("[CALIB] 校准命令读取失败，将继续重试: {err}");
                    last_command_error_log = Some(now);
                }
                None
            }
        };
        if let Some(cmd) = command.and_then(|command| parse_calibration_command(&command)) {
            match cmd {
                CalibrationCommand::Start(pkg) => {
                    if let Some(active) = session.as_ref() {
                        if active.pkg == pkg {
                            println!("[CALIB] 已在采样，忽略重复开始命令: {pkg}");
                            if let Err(err) = write_state(&format!("sampling {pkg}")) {
                                eprintln!("[CALIB] 重复开始命令确认状态写入失败: {err}");
                            }
                        } else {
                            println!(
                                "[CALIB] 忽略开始命令: requested={} active={} reason=busy",
                                pkg, active.pkg
                            );
                            if let Err(err) = write_state(&format!(
                                "sampling {};reason=busy;requested={pkg}", active.pkg
                            )) {
                                eprintln!("[CALIB] 忙碌状态写入失败: {err}");
                            }
                        }
                    } else {
                        let processes = collect_pkg_processes(&pkg);
                        if processes.is_empty() {
                            println!("[CALIB] 忽略开始命令: {pkg} 没有运行中的进程");
                            if let Err(err) =
                                write_state(&format!("rejected {pkg};reason=no_process"))
                            {
                                eprintln!("[CALIB] 拒绝状态写入失败: {err}");
                            }
                        } else {
                            println!(
                                "[CALIB] 开始采样: pkg={} 进程数={} 进程=[{}]",
                                pkg,
                                processes.len(),
                                process_preview(&processes, 8)
                            );
                            match write_state(&format!("sampling {pkg}")) {
                                Ok(()) => {
                                    session = Some(CalibSession::new(pkg.clone(), processes));
                                    last_progress_log_round = None;
                                }
                                Err(err) => {
                                    eprintln!(
                                        "[CALIB] 采样状态写入失败，忽略本次开始命令: {err}"
                                    );
                                }
                            }
                        }
                    }
                }
                CalibrationCommand::Stop(requested) => {
                    let matches_active = session.as_ref().is_some_and(|active| {
                        requested.as_deref().is_none_or(|pkg| pkg == active.pkg)
                    });
                    if matches_active {
                        if let Some(done) = session.take() {
                            if let Err(err) = finish_session(done, &config_file) {
                                eprintln!("[CALIB] 校准收尾失败，后台线程将继续运行: {err}");
                            }
                        }
                    } else if let Some(active) = session.as_ref() {
                        let requested = requested.as_deref().unwrap_or_default();
                        println!(
                            "[CALIB] 忽略不属于当前会话的停止命令: requested={} active={}",
                            requested, active.pkg
                        );
                        if let Err(err) = write_state(&format!(
                            "sampling {};reason=stop_mismatch;requested={requested}", active.pkg
                        )) {
                            eprintln!("[CALIB] 停止命令不匹配状态写入失败: {err}");
                        }
                    } else if let Some(pkg) = requested {
                        // App 可能在 daemon 已自动收尾后补发 stop。给出明确确认，避免无意义等待。
                        if let Err(err) = write_state(&format!("done {pkg};reason=no_session")) {
                            eprintln!("[CALIB] 空会话停止确认写入失败: {err}");
                        }
                    } else if let Err(err) = write_state("idle") {
                        eprintln!("[CALIB] 空会话停止状态写入失败: {err}");
                    }
                }
            }
        }

        let mut should_finish = false;
        let mut session_timed_out = false;
        if let Some(active) = session.as_mut() {
            if active.started_at.elapsed() >= CALIB_MAX_SESSION_DURATION {
                should_finish = true;
                session_timed_out = true;
            } else if !active.sample_once() {
                should_finish = true;
            } else if active.rounds > 0
                && active.rounds % CALIB_PROGRESS_LOG_ROUNDS == 0
                && last_progress_log_round != Some(active.rounds)
            {
                last_progress_log_round = Some(active.rounds);
                println!(
                    "[CALIB] 采样中: pkg={} 轮次={} 活跃进程={} 负载项={} 跟踪TID={} 子进程线程摘要={} Top=[{}]",
                    active.pkg,
                    active.rounds,
                    active.processes.len(),
                    active.records.len(),
                    active.prev_ticks.len(),
                    active.child_threads.len(),
                    top_record_summary(active.records.values(), 5)
                );
            }
        }
        if should_finish {
            last_progress_log_round = None;
            if let Some(done) = session.take() {
                if session_timed_out {
                    println!("[CALIB] 校准会话已达到 6 小时上限: {}", done.pkg);
                } else {
                    println!("[CALIB] 主进程已退出: {}", done.pkg);
                }
                if let Err(err) = finish_session(done, &config_file) {
                    eprintln!("[CALIB] 校准收尾失败，后台线程将继续运行: {err}");
                }
            }
        }

        thread::sleep(SAMPLE_INTERVAL);
    }
}

#[cfg(test)]
mod calibration_command_tests {
    use super::*;

    #[test]
    fn commands_keep_package_ownership() {
        assert_eq!(
            parse_calibration_command("start com.example.game"),
            Some(CalibrationCommand::Start("com.example.game".to_string()))
        );
        assert_eq!(
            parse_calibration_command("stop com.example.game"),
            Some(CalibrationCommand::Stop(Some("com.example.game".to_string())))
        );
        assert_eq!(parse_calibration_command("stop"), Some(CalibrationCommand::Stop(None)));
        assert_eq!(parse_calibration_command("start bad;state"), None);
        assert_eq!(parse_calibration_command("stop other package"), None);
    }
}
