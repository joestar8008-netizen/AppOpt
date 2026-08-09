use std::time::Duration;

fn valid_fps_sample(fps: f64) -> Option<f64> {
    (fps.is_finite() && (0.0..=300.0).contains(&fps)).then_some(fps)
}

fn select_active_timestats_layer(
    previous: &[(String, i64)],
    current: &[(String, i64)],
    preferred: Option<&str>,
) -> Option<usize> {
    let mut best: Option<(usize, i64)> = None;
    for (index, (name, frames)) in current.iter().enumerate() {
        let Some((_, old_frames)) = previous.iter().find(|(old_name, _)| old_name == name) else {
            continue;
        };
        let delta = frames.saturating_sub(*old_frames);
        if delta <= 0 {
            continue;
        }
        let replace = best.is_none_or(|(best_index, best_delta)| {
            delta > best_delta
                || (delta == best_delta
                    && preferred == Some(name.as_str())
                    && preferred != Some(current[best_index].0.as_str()))
        });
        if replace {
            best = Some((index, delta));
        }
    }
    best.map(|(index, _)| index)
        .or_else(|| {
            preferred.and_then(|preferred| {
                current
                    .iter()
                    .position(|(name, _)| name.as_str() == preferred)
            })
        })
        .or_else(|| (!current.is_empty()).then_some(0))
}

fn ebpf_restart_delay(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::from_secs(3),
        2 => Duration::from_secs(10),
        _ => Duration::from_secs(30),
    }
}

fn latency_probe_delay(failures: u32) -> Option<Duration> {
    match failures {
        0..=2 => Some(Duration::ZERO),
        3..=4 => Some(Duration::from_secs(1)),
        _ => None,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod imp {
    // Android/Linux FPS 实现聚合入口。
    //
    // 这里保持一个 imp 模块包住全部实现，是为了让非 Android 主机也能 cargo check：
    // Windows/其他平台会走下面的空 start_fps_thread，不编译 binder/eBPF 代码。
    include!("fps_core/preamble.rs");
    include!("fps_core/monitor.rs");
    include!("fps_core/command.rs");
    include!("fps_core/fallback.rs");
    include!("fps_core/binder.rs");
    include!("fps_core/socket.rs");
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod imp {
    pub fn start_fps_thread() -> Option<std::thread::JoinHandle<()>> {
        None
    }
}

pub use imp::start_fps_thread;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_restart_failures_back_off_without_growing_forever() {
        assert_eq!(ebpf_restart_delay(1), Duration::from_secs(3));
        assert_eq!(ebpf_restart_delay(2), Duration::from_secs(10));
        assert_eq!(ebpf_restart_delay(3), Duration::from_secs(30));
        assert_eq!(ebpf_restart_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn stale_latency_probe_has_fast_then_slow_retries() {
        assert_eq!(latency_probe_delay(1), Some(Duration::ZERO));
        assert_eq!(latency_probe_delay(2), Some(Duration::ZERO));
        assert_eq!(latency_probe_delay(3), Some(Duration::from_secs(1)));
        assert_eq!(latency_probe_delay(4), Some(Duration::from_secs(1)));
        assert_eq!(latency_probe_delay(5), None);
    }

    #[test]
    fn timestats_prefers_the_layer_with_positive_recent_growth() {
        let previous = vec![("old".to_string(), 20_000), ("active".to_string(), 100)];
        let current = vec![("old".to_string(), 20_000), ("active".to_string(), 160)];
        assert_eq!(
            select_active_timestats_layer(&previous, &current, Some("old")),
            Some(1)
        );
    }

    #[test]
    fn timestats_keeps_the_preferred_layer_when_nothing_advanced() {
        let previous = vec![("left".to_string(), 10), ("right".to_string(), 20)];
        let current = previous.clone();
        assert_eq!(
            select_active_timestats_layer(&previous, &current, Some("right")),
            Some(1)
        );
    }

    #[test]
    fn impossible_fps_samples_are_rejected() {
        assert_eq!(valid_fps_sample(60.0), Some(60.0));
        assert_eq!(valid_fps_sample(301.0), None);
        assert_eq!(valid_fps_sample(f64::NAN), None);
        assert_eq!(valid_fps_sample(f64::INFINITY), None);
    }
}
