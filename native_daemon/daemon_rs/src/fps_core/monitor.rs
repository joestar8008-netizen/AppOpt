    // FPS 监测状态机。
    //
    // 一个 FpsMonitor 只监测一个包名：
    // - start 时找到一个就绪 PID，为目标进程线程启动 eBPF uprobe。
    // - poll 时读取 eBPF 帧事件并输出 FPS。
    // - 同包 PID/TID 变化只增量更新 uprobe 与 target_tgids map，不重载 BPF 对象。
    //
    // 这里不要直接读 App UI 状态。FPS 模块只对 fps.cmd 负责，上层悬浮窗关闭时会写 stop。
    impl FpsMonitor {
        fn start(pkg: String, socket_name: Option<String>, socket_token: Option<String>) -> Self {
            let output = if socket_name.is_some() { "socket" } else { "文件" };
            println!("[FPS] 监测启动: pkg={pkg} 通道={output}");
            // 游戏刚被拉起时 /proc/cmdline 可能短暂不可见，先等一小段时间。
            let initial_choice = wait_pkg_pid(&pkg, 30, Duration::from_millis(100));
            let initial_pid = initial_choice.as_ref().map_or(-1, |choice| choice.pid);
            let initial_source = initial_choice
                .as_ref()
                .map_or("未找到", |choice| choice.source.as_str());
            let initial_targets = initial_choice
                .iter()
                .map(|choice| choice.pid)
                .collect::<BTreeSet<_>>();
            let initial_target_count = if initial_pid > 0 {
                collect_pkg_ebpf_pids(&pkg, &initial_targets, true)
                    .len()
                    .max(1)
            } else {
                0
            };
            println!(
                "[FPS] 目标锁定: {}={} 来源={} 前台状态={} 同包进程={}",
                if initial_choice.as_ref().is_some_and(|choice| choice.is_main) {
                    "主PID"
                } else {
                    "子进程PID"
                },
                initial_pid,
                initial_source,
                foreground_state_from_source(initial_source),
                initial_target_count,
            );
            if initial_pid < 0 {
                println!(
                    "[FPS] 目标锁定失败: 等待约3秒仍未找到 {} 的可用进程；保持 eBPF 主路径并继续等待 PID",
                    pkg
                );
            }
            let ctx = if initial_pid > 0 {
                start_ebpf_for_pkg(&pkg, initial_pid, initial_source, true)
            } else {
                ptr::null_mut()
            };
            let now = Instant::now();
            let initial_load_failed = initial_pid > 0 && ctx.is_null();
            let initial_retry_failures = if initial_load_failed { 1 } else { 0 };
            let backend_name = if ctx.is_null() {
                "未启用".to_string()
            } else {
                cstr_lossy(appopt_ebpf_backend(ctx))
            };

            let mut monitor = Self {
                pkg,
                ctx,
                ebpf_failures: 0,
                ebpf_seen_frames: false,
                ebpf_stale_zero_sent: false,
                ebpf_last_frame: now,
                last_ebpf_fps: 0.0,
                ebpf_last_restart: now,
                ebpf_next_restart: now + super::ebpf_restart_delay(initial_retry_failures),
                ebpf_restart_failures: initial_retry_failures,
                ebpf_no_frame_retries: 0,
                ebpf_retry_pid: initial_pid,
                ebpf_last_relock_check: None,
                ebpf_last_target_error_log: None,
                ebpf_last_retry_log: None,
                ebpf_suppressed_retry_logs: 0,
                ebpf_attempt_detailed: true,
                ebpf_retry_reported: false,
                ebpf_pending_recovery: false,
                ebpf_first_fps: true,
                ebpf_last_target_refresh: now,
                ebpf_last_full_target_scan: None,
                target_pids: initial_targets,
                fallback: None,
                fallback_state_reported: false,
                fallback_allowed: false,
                ebpf_no_pid_since: (initial_pid < 0).then_some(now),
                socket: FpsSocket::new(socket_name, socket_token),
                last_output: None,
                target_pid: initial_pid,
                started_at: now,
                last_frame_pid: -1,
                backend_name,
                confirmed_backend: None,
                fallback_used: false,
                adaptive_enabled: false,
                jank: ptr::null_mut(),
                jank_last_sample: None,
                output_enabled: true,
            };
            if !monitor.ctx.is_null() {
                monitor.refresh_target_pids();
            }
            monitor
        }

        fn poll(&mut self) {
            if self.ctx.is_null() {
                let now = Instant::now();
                let relock_due = self
                    .ebpf_last_relock_check
                    .is_none_or(|last| now.duration_since(last) >= FPS_EBPF_RELOCK_CHECK);
                let hinted = if relock_due {
                    self.ebpf_last_relock_check = Some(now);
                    find_foreground_pkg_hint(&self.pkg)
                        .filter(|choice| pid_ready_for_ebpf(choice.pid, &self.pkg))
                } else {
                    None
                };
                let target_changed = hinted
                    .as_ref()
                    .is_some_and(|choice| choice.pid != self.ebpf_retry_pid);
                if target_changed || now >= self.ebpf_next_restart {
                    let choice = hinted.or_else(|| {
                        find_preferred_pkg_pid(&self.pkg, true)
                            .filter(|choice| pid_ready_for_ebpf(choice.pid, &self.pkg))
                    });
                    if let Some(choice) = choice {
                        self.ebpf_no_pid_since = None;
                        if choice.pid != self.ebpf_retry_pid {
                            self.ebpf_restart_failures = 0;
                            self.ebpf_no_frame_retries = 0;
                            self.ebpf_retry_pid = choice.pid;
                        }
                        // 即使本轮 eBPF 仍无法加载，也要记录热重启后的真实 PID，
                        // 不能继续沿用已经退出的旧进程；是否降级由明确失败策略决定。
                        self.target_pid = choice.pid;
                        self.ebpf_last_restart = now;
                        let recovered_from_fallback = self.fallback.is_some();
                        let detailed_attempt = !recovered_from_fallback || target_changed;
                        let retry_log = if detailed_attempt {
                            None
                        } else {
                            self.take_retry_log_slot(now)
                        };
                        self.ctx = start_ebpf_for_pkg(
                            &self.pkg,
                            choice.pid,
                            &choice.source,
                            detailed_attempt,
                        );
                        if !self.ctx.is_null() {
                            self.ebpf_no_pid_since = None;
                            self.fallback_allowed = false;
                            if recovered_from_fallback {
                                self.ebpf_pending_recovery = true;
                            }
                            self.backend_name = cstr_lossy(appopt_ebpf_backend(self.ctx));
                            self.ebpf_attempt_detailed = detailed_attempt;
                            self.ebpf_retry_reported = retry_log.is_some();
                            self.reset_ebpf_restart(choice.pid, now);
                            self.ebpf_failures = 0;
                            self.ebpf_seen_frames = false;
                            self.ebpf_stale_zero_sent = false;
                            self.ebpf_last_frame = now;
                            self.ebpf_first_fps = true;
                            self.target_pid = choice.pid;
                            if let Some(suppressed) = retry_log {
                                println!(
                                    "[FPS] eBPF 重试挂载: 后端={} PID={} 状态=等待帧源确认{}",
                                    self.backend_name,
                                    choice.pid,
                                    suppressed_retry_note(suppressed)
                                );
                            }
                            self.refresh_target_pids();
                            thread::sleep(Duration::from_millis(80));
                            return;
                        } else {
                            self.record_ebpf_start_failure(
                                choice.pid,
                                now,
                                detailed_attempt,
                                retry_log,
                            );
                        }
                    } else {
                        let missing_since = self.ebpf_no_pid_since.get_or_insert(now);
                        if now.duration_since(*missing_since) >= FPS_EBPF_FALLBACK_GRACE {
                            self.fallback_allowed = true;
                        }
                        self.ebpf_next_restart = now + super::ebpf_restart_delay(1);
                    }
                }
                if self.fallback_allowed {
                    self.start_fallback();
                    self.poll_fallback();
                } else {
                    // 目标进程可能比前台状态晚出现；在 eBPF 重新锁定前不启动
                    // SurfaceFlinger，避免一次启动竞态把主路径伪装成降级路径。
                    thread::sleep(Duration::from_millis(120));
                }
                return;
            }
            let now = Instant::now();
            let target_refresh_interval = if appopt_ebpf_probe_state(self.ctx)
                == FPS_EBPF_PROBE_PENDING
            {
                FPS_EBPF_PROBE_TARGET_REFRESH
            } else {
                FPS_EBPF_TARGET_REFRESH
            };
            if now.duration_since(self.ebpf_last_target_refresh) >= target_refresh_interval {
                self.ebpf_last_target_refresh = now;
                self.refresh_target_pids();
            }
            // appopt_ebpf_poll 会从选中的 RingBuf/StatsMap/PerfEvent 后端更新当前 FPS。
            let rc = appopt_ebpf_poll(self.ctx);
            if rc < 0 {
                self.ebpf_failures += 1;
                eprintln!(
                    "[FPS] eBPF 轮询失败 #{}: pkg={} pid={} err={}",
                    self.ebpf_failures,
                    self.pkg,
                    appopt_ebpf_pid(self.ctx),
                    cstr_lossy(appopt_ebpf_last_error(self.ctx))
                );
                if self.ebpf_failures >= 3 {
                    eprintln!(
                        "[FPS] eBPF 连续轮询失败，切换 SurfaceFlinger 降级并等待重试 eBPF: pkg={} failures={}",
                        self.pkg, self.ebpf_failures
                    );
                    let fallback_was_ready = self.fallback.is_some();
                    appopt_ebpf_stop(self.ctx);
                    self.ctx = ptr::null_mut();
                    self.fallback_allowed = true;
                    self.schedule_ebpf_restart(self.target_pid, Instant::now());
                    self.start_fallback();
                    if !fallback_was_ready {
                        self.write_fps(0.0);
                    }
                }
                thread::sleep(Duration::from_millis(120));
                return;
            }
            self.ebpf_failures = 0;

            let now = Instant::now();
            let fps = appopt_ebpf_get(self.ctx);
            let probe_state = appopt_ebpf_probe_state(self.ctx);
            let probe_pending = probe_state == FPS_EBPF_PROBE_PENDING;
            let active_pid = appopt_ebpf_pid(self.ctx);
            if rc > 0 && fps > 0.0 {
                // 原始事件经过稳定帧流筛选并得到有效 FPS 后，才刷新停帧计时。
                self.ebpf_seen_frames = true;
                self.ebpf_stale_zero_sent = false;
                self.ebpf_last_frame = now;
                self.last_ebpf_fps = fps;
                self.last_frame_pid = active_pid;
                self.confirmed_backend = Some(self.backend_name.clone());
                self.ebpf_no_frame_retries = 0;
                if self.ebpf_pending_recovery {
                    println!(
                        "[FPS] 后端恢复: SurfaceFlinger → eBPF 后端={} PID={} FPS={fps:.1}",
                        self.backend_name, active_pid
                    );
                    self.ebpf_pending_recovery = false;
                    self.fallback = None;
                    self.fallback_state_reported = false;
                    self.ebpf_attempt_detailed = true;
                    self.ebpf_retry_reported = false;
                    self.ebpf_last_retry_log = None;
                    self.ebpf_suppressed_retry_logs = 0;
                }
                // appopt_ebpf_poll 会在本轮内完成候选确认。若此前因明确错误启用过
                // SurfaceFlinger，首个有效 eBPF 帧到达后立即释放降级源。
                self.fallback = None;
                self.fallback_state_reported = false;
            }
            if self.ebpf_first_fps && fps > 0.0 {
                println!(
                    "[FPS] 计帧就绪: 来源={} 当前帧源PID={} FPS={fps:.1}",
                    ebpf_frame_source_label(&self.backend_name),
                    active_pid,
                );
                self.ebpf_first_fps = false;
            }

            // 目标长时间没有新帧时输出 0，避免悬浮窗沿用旧 FPS 误导用户。
            // 这不是 eBPF 失败，只是当前目标 Surface 没继续提交新帧。
            let fps_is_stale =
                self.ebpf_seen_frames && now.duration_since(self.ebpf_last_frame) >= FPS_EBPF_STALE;

            // 已确认的帧源停顿不解绑、不轮换符号，也不触发 SurfaceFlinger：
            // 游戏切后台、加载场景、严重卡顿或停在静态页面都可能长时间没有
            // queueBuffer；保留当前 attach，恢复提交帧后可以直接继续计数。

            if !probe_pending {
                self.poll_jank(
                    if fps_is_stale {
                        0.0
                    } else {
                        fps
                    },
                    true,
                );
            }

            if fps_is_stale && !self.ebpf_stale_zero_sent {
                println!(
                    "[FPS] 帧源停顿: PID={} 符号={} 连续{:.1}秒无新帧 最后FPS={:.1}",
                    active_pid,
                    cstr_lossy(appopt_ebpf_symbol_display(self.ctx)),
                    now.duration_since(self.ebpf_last_frame).as_secs_f64(),
                    self.last_ebpf_fps,
                );
                self.write_fps(0.0);
                self.last_output = Some(now);
                self.ebpf_stale_zero_sent = true;
            }

            if probe_state == FPS_EBPF_PROBE_EXHAUSTED && !self.ebpf_seen_frames {
                if self.ebpf_attempt_detailed {
                    println!(
                        "[FPS] eBPF 帧源耗尽: pkg={} 目标进程={} 有效帧源=0 原因=已验证全部可挂载符号",
                        self.pkg,
                        self.target_pids.len()
                    );
                } else if self.ebpf_retry_reported {
                    println!(
                        "[FPS] eBPF 重试结果: PID={} 状态=仍无首帧；保持 eBPF 主路径并按退避计划重试",
                        self.target_pid
                    );
                }
                println!(
                    "[FPS] eBPF 空闲保护: pkg={} 未收到首个帧事件，保持 eBPF 主路径并按退避计划重试；不切换 SurfaceFlinger",
                    self.pkg
                );
                appopt_ebpf_stop(self.ctx);
                self.ctx = ptr::null_mut();
                self.ebpf_retry_reported = false;
                self.schedule_ebpf_probe_retry(self.target_pid, Instant::now());
                thread::sleep(Duration::from_millis(120));
                return;
            }

            let should_output = self
                .last_output
                .map(|last| now.duration_since(last) >= FPS_WINDOW)
                .unwrap_or(true);
            if should_output && !fps_is_stale && !probe_pending {
                self.write_fps(fps);
                self.last_output = Some(now);
            }
            thread::sleep(Duration::from_millis(80));
        }

        fn start_fallback(&mut self) {
            if !self.fallback_allowed {
                return;
            }
            if self.fallback.is_none() {
                self.fallback_used = true;
                if !self.fallback_state_reported {
                    let retry_after = self
                        .ebpf_next_restart
                        .checked_duration_since(Instant::now())
                        .unwrap_or(Duration::ZERO);
                    println!(
                        "[FPS] 后端切换: eBPF → SurfaceFlinger Binder/CLI；eBPF将在{}后重试 pkg={}",
                        retry_delay_text(retry_after),
                        self.pkg,
                    );
                    self.fallback_state_reported = true;
                }
                self.fallback = SfFallback::new(self.pkg.clone());
            }
        }

        fn poll_fallback(&mut self) {
            self.start_fallback();
            let (fps, targeted) = self
                .fallback
                .as_mut()
                .map(|fallback| {
                    let fps = fallback.poll();
                    (fps, fallback.sample_is_targeted())
                })
                .unwrap_or((0.0, false));
            if targeted && fps > 0.0 && self.confirmed_backend.is_none() {
                self.confirmed_backend = Some("SurfaceFlinger".to_string());
            }
            // CLI 的全局合成帧率可以维持 UI 弱提示，但绝不能学习为目标应用基线。
            // 传 0 只用于让既有临时增强及时恢复，不会触发新的调度档位。
            self.poll_jank(if targeted { fps } else { 0.0 }, false);
            let now = Instant::now();
            let should_output = self
                .last_output
                .map(|last| now.duration_since(last) >= FPS_WINDOW)
                .unwrap_or(true);
            if should_output {
                self.write_fps(fps);
                self.last_output = Some(now);
            }
            thread::sleep(Duration::from_millis(300));
        }

        fn refresh_target_pids(&mut self) {
            if self.ctx.is_null() {
                return;
            }
            let now = Instant::now();
            let allow_full_scan = self.target_pids.is_empty()
                || self
                    .ebpf_last_full_target_scan
                    .is_none_or(|last| now.duration_since(last) >= FPS_EBPF_TARGET_FULL_SCAN);
            let next = collect_pkg_ebpf_pids(&self.pkg, &self.target_pids, allow_full_scan);
            if allow_full_scan {
                self.ebpf_last_full_target_scan = Some(now);
            }
            let previous = self.target_pids.clone();
            let pids = next.iter().copied().collect::<Vec<_>>();
            let rc = appopt_ebpf_set_target_pids(self.ctx, pids.as_ptr(), pids.len());
            if rc < 0 {
                let now = Instant::now();
                if self.target_error_log_due(now) {
                    eprintln!(
                        "[FPS] eBPF 目标进程更新失败: pkg={} err={}",
                        self.pkg,
                        cstr_lossy(appopt_ebpf_last_error(self.ctx))
                    );
                }
                return;
            }
            if rc as usize != next.len() {
                let now = Instant::now();
                if self.target_error_log_due(now) {
                    eprintln!(
                        "[FPS] eBPF 目标进程仅部分生效: pkg={} 请求={} 生效={} err={}",
                        self.pkg,
                        next.len(),
                        rc,
                        cstr_lossy(appopt_ebpf_last_error(self.ctx))
                    );
                }
                return;
            }

            let previous_frame_removed = self.last_frame_pid > 0
                && previous.contains(&self.last_frame_pid)
                && !next.contains(&self.last_frame_pid);
            let previous_target_removed = self.target_pid > 0
                && previous.contains(&self.target_pid)
                && !next.contains(&self.target_pid);
            let target_generation_changed = !next.is_empty()
                && (previous.is_empty()
                    || previous.is_disjoint(&next)
                    || previous_frame_removed
                    || previous_target_removed);
            self.target_pids = next;
            self.target_pid = appopt_ebpf_pid(self.ctx);
            if target_generation_changed {
                let now = Instant::now();
                self.ebpf_no_frame_retries = 0;
                self.ebpf_seen_frames = false;
                self.ebpf_stale_zero_sent = false;
                self.ebpf_last_frame = now;
                self.ebpf_last_restart = now;
                self.ebpf_first_fps = true;
                self.jank_last_sample = None;
                self.reset_ebpf_restart(self.target_pid, now);
            }
            if previous == self.target_pids {
                return;
            }
            let added = self
                .target_pids
                .difference(&previous)
                .copied()
                .map(|pid| pid.to_string())
                .collect::<Vec<_>>();
            let removed = previous
                .difference(&self.target_pids)
                .copied()
                .map(|pid| pid.to_string())
                .collect::<Vec<_>>();
            println!(
                "[FPS] 目标集合更新: {} → {} 新增=[{}] 移除=[{}]",
                previous.len(),
                self.target_pids.len(),
                if added.is_empty() { "-".to_string() } else { added.join(", ") },
                if removed.is_empty() { "-".to_string() } else { removed.join(", ") }
            );
        }

        fn stop(&mut self, reason: &str) {
            self.set_adaptive(false);
            if !self.ctx.is_null() {
                appopt_ebpf_stop(self.ctx);
                self.ctx = std::ptr::null_mut();
            }
            self.write_fps(0.0);
            self.fallback = None;
            self.socket.close();
            println!(
                "[FPS] 监测结束: pkg={} 原因={} 时长={:.1}秒 主后端={} 降级={} 最后帧源PID={}",
                self.pkg,
                reason,
                self.started_at.elapsed().as_secs_f64(),
                self.confirmed_backend.as_deref().unwrap_or("未确认"),
                if self.fallback_used { "已触发" } else { "未触发" },
                if self.last_frame_pid > 0 {
                    self.last_frame_pid.to_string()
                } else {
                    "未确认".to_string()
                }
            );
        }

        fn write_fps(&mut self, fps: f64) {
            if !self.output_enabled {
                return;
            }
            let fps = super::valid_fps_sample(fps).unwrap_or(0.0);
            if self.socket.send_fps(fps).is_ok() {
                return;
            }
            write_fps_file(fps);
        }

        fn set_output_enabled(&mut self, enabled: bool) {
            if self.output_enabled == enabled {
                return;
            }
            if !enabled {
                self.write_fps(0.0);
                self.socket.close();
            }
            self.output_enabled = enabled;
        }

        fn set_adaptive(&mut self, enabled: bool) {
            if self.adaptive_enabled == enabled {
                return;
            }
            self.adaptive_enabled = enabled;
            self.jank_last_sample = None;
            if enabled {
                if let Ok(pkg) = CString::new(self.pkg.as_str()) {
                    self.jank = appopt_jank_create(pkg.as_ptr());
                }
                println!("[boost] 已为 {} 开启卡顿时临时提速", self.pkg);
            } else if !self.jank.is_null() {
                appopt_jank_stop(self.jank);
                self.jank = ptr::null_mut();
                println!("[boost] 已为 {} 停止卡顿时临时提速并恢复参数", self.pkg);
            }
        }

        fn poll_jank(&mut self, fps: f64, use_ebpf_metrics: bool) {
            if !self.adaptive_enabled || self.jank.is_null() {
                return;
            }
            let now = Instant::now();
            if self
                .jank_last_sample
                .is_some_and(|last| now.duration_since(last) < FPS_JANK_SAMPLE_INTERVAL)
            {
                return;
            }
            self.jank_last_sample = Some(now);
            let mut metrics = AppOptFrameMetrics::default();
            let metrics_ptr = if use_ebpf_metrics
                && !self.ctx.is_null()
                && appopt_ebpf_metrics(self.ctx, &mut metrics) > 0
            {
                &metrics as *const AppOptFrameMetrics
            } else {
                ptr::null()
            };
            let pid = if use_ebpf_metrics && !self.ctx.is_null() {
                appopt_ebpf_pid(self.ctx)
            } else {
                self.target_pid
            };
            if appopt_jank_update(self.jank, pid, fps, metrics_ptr) > 0 {
                println!("[boost] {}", cstr_lossy(appopt_jank_last_event(self.jank)));
            }
        }

        fn schedule_ebpf_restart(&mut self, pid: i32, now: Instant) {
            // 当前后端刚退出，先等待 3 秒；若下一次重新加载仍失败，直接进入 10 秒档。
            self.ebpf_restart_failures = 1;
            self.ebpf_retry_pid = pid;
            self.ebpf_last_restart = now;
            self.ebpf_next_restart = now + super::ebpf_restart_delay(1);
            self.ebpf_last_relock_check = None;
        }

        fn schedule_ebpf_probe_retry(&mut self, pid: i32, now: Instant) {
            // 候选没有首帧不等于 eBPF 失效：应用可能只是停在首屏或暂未交互。
            // 逐次拉长重试间隔，避免空闲应用每几秒反复加载/卸载 BPF。
            self.ebpf_no_frame_retries = self.ebpf_no_frame_retries.saturating_add(1);
            let delay = super::ebpf_restart_delay(self.ebpf_no_frame_retries);
            self.ebpf_retry_pid = pid;
            self.ebpf_last_restart = now;
            self.ebpf_next_restart = now + delay;
            self.ebpf_last_relock_check = None;
            println!(
                "[FPS] eBPF 空闲重试退避: pkg={} 连续无首帧={} 下次重试={}秒",
                self.pkg,
                self.ebpf_no_frame_retries,
                delay.as_secs(),
            );
        }

        fn reset_ebpf_restart(&mut self, pid: i32, now: Instant) {
            self.ebpf_restart_failures = 0;
            self.ebpf_retry_pid = pid;
            self.ebpf_next_restart = now + super::ebpf_restart_delay(1);
            self.ebpf_last_relock_check = None;
        }

        fn record_ebpf_start_failure(
            &mut self,
            pid: i32,
            now: Instant,
            detailed_attempt: bool,
            retry_log: Option<u32>,
        ) {
            if self.ebpf_retry_pid != pid {
                self.ebpf_restart_failures = 0;
                self.ebpf_retry_pid = pid;
                self.ebpf_no_frame_retries = 0;
            }
            self.ebpf_restart_failures = self.ebpf_restart_failures.saturating_add(1);
            if self.ebpf_restart_failures >= FPS_EBPF_FALLBACK_FAILURES {
                self.fallback_allowed = true;
            }
            let delay = super::ebpf_restart_delay(self.ebpf_restart_failures);
            self.ebpf_next_restart = now + delay;
            if detailed_attempt {
                println!(
                    "[FPS] eBPF 重试退避: pkg={} PID={} 连续失败={} 下次重试={}秒",
                    self.pkg,
                    pid,
                    self.ebpf_restart_failures,
                    delay.as_secs()
                );
            } else if let Some(suppressed) = retry_log {
                println!(
                    "[FPS] eBPF 重试失败: pkg={} PID={} 连续失败={} err={} 下次重试={}秒{}",
                    self.pkg,
                    pid,
                    self.ebpf_restart_failures,
                    cstr_lossy(appopt_ebpf_last_start_error()),
                    delay.as_secs(),
                    suppressed_retry_note(suppressed)
                );
            }
        }

        fn take_retry_log_slot(&mut self, now: Instant) -> Option<u32> {
            if self
                .ebpf_last_retry_log
                .is_some_and(|last| now.duration_since(last) < FPS_EBPF_RETRY_LOG_INTERVAL)
            {
                self.ebpf_suppressed_retry_logs =
                    self.ebpf_suppressed_retry_logs.saturating_add(1);
                return None;
            }
            self.ebpf_last_retry_log = Some(now);
            Some(mem::take(&mut self.ebpf_suppressed_retry_logs))
        }

        fn target_error_log_due(&mut self, now: Instant) -> bool {
            if self
                .ebpf_last_target_error_log
                .is_some_and(|last| now.duration_since(last) < FPS_ERROR_LOG_INTERVAL)
            {
                return false;
            }
            self.ebpf_last_target_error_log = Some(now);
            true
        }
    }

    fn foreground_state_from_source(source: &str) -> &str {
        source.strip_prefix("前台助手+").unwrap_or(source)
    }

    fn ebpf_frame_source_label(backend: &str) -> String {
        match backend {
            "StatsMap" => "eBPF frame_stats map".to_string(),
            "RingBuf" => "eBPF RingBuf逐帧事件".to_string(),
            "PerfEvent" => "eBPF PerfEvent逐帧事件".to_string(),
            _ => format!("eBPF {backend}"),
        }
    }

    fn retry_delay_text(delay: Duration) -> String {
        let millis = delay.as_millis();
        if millis == 0 {
            "0秒".to_string()
        } else if millis % 1_000 == 0 {
            format!("{}秒", millis / 1_000)
        } else {
            format!("{:.1}秒", millis as f64 / 1_000.0)
        }
    }

    fn suppressed_retry_note(count: u32) -> String {
        if count == 0 {
            String::new()
        } else {
            format!("；已省略{count}次相同重试")
        }
    }

    fn start_ebpf_for_pkg(
        pkg: &str,
        pid: i32,
        source: &str,
        detailed_logging: bool,
    ) -> *mut AppOptEbpfCtx {
        // Rust 守护进程直接加载 bpf.o 并附加 libgui uprobe。
        // bridge 内部按 RingBuf -> StatsMap -> PerfEvent 顺序选择可用后端。
        let ctx = match (CString::new(FPS_BPF_OBJ), CString::new(pkg)) {
            (Ok(bpf_path), Ok(c_pkg)) => {
                appopt_ebpf_start_for_package(pid, bpf_path.as_ptr(), c_pkg.as_ptr())
            }
            _ => {
                eprintln!("[FPS] eBPF 启动跳过: 参数包含无效字符");
                ptr::null_mut()
            }
        };
        if ctx.is_null() {
            if !detailed_logging {
                return ctx;
            }
            eprintln!(
                "[FPS] 后端选择失败: eBPF三条后端均不可用 err={}",
                cstr_lossy(appopt_ebpf_last_start_error())
            );
        } else {
            let _ = appopt_ebpf_set_detailed_logging(ctx, if detailed_logging { 1 } else { 0 });
            if !detailed_logging {
                return ctx;
            }
            println!(
                "[FPS] 后端选择: {}",
                cstr_lossy(appopt_ebpf_backend_note(ctx))
            );
            println!(
                "[FPS] eBPF 挂载: pkg={} 来源={} 后端={} {}",
                pkg,
                source,
                cstr_lossy(appopt_ebpf_backend(ctx)),
                cstr_lossy(appopt_ebpf_startup_note(ctx)),
            );
        }
        ctx
    }

    impl Drop for FpsMonitor {
        fn drop(&mut self) {
            self.set_adaptive(false);
            if !self.ctx.is_null() {
                appopt_ebpf_stop(self.ctx);
                self.ctx = std::ptr::null_mut();
            }
            self.fallback = None;
            self.socket.close();
        }
    }
