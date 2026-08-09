use std::collections::VecDeque;

const FPS_WINDOW_NS: u64 = 1_000_000_000;
const MIN_FRAME_NS: u64 = 1_000_000;
const MAX_RECORDED_FRAME_NS: u64 = 1_000_000_000;
// Android 输入 ANR 的常见边界是 5 秒；低于该值仍可能是真实严重卡顿，不能当暂停丢掉。
const PAUSE_FRAME_NS: u64 = 5_000_000_000;
const MIN_STREAM_INTERVALS: usize = 8;
const MIN_STREAM_LIFETIME_NS: u64 = 150_000_000;
const MAX_PLAUSIBLE_FPS: f64 = 300.0;

pub(crate) const STREAM_STALE_NS: u64 = 2_000_000_000;
pub(crate) const MAX_STREAMS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FrameStreamKey {
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) surface_ptr: u64,
}

pub(crate) struct FpsStream {
    pub(crate) frame_times: VecDeque<u64>,
    frame_time_sum_ns: u64,
    last_ts: u64,
    first_seen_ns: u64,
    pub(crate) last_seen_ns: u64,
    pub(crate) cur_fps: f64,
    warmed_up: bool,
}

impl FpsStream {
    pub(crate) fn new(timestamp_ns: u64) -> Self {
        Self {
            frame_times: VecDeque::with_capacity(144),
            frame_time_sum_ns: 0,
            last_ts: 0,
            first_seen_ns: timestamp_ns,
            last_seen_ns: timestamp_ns,
            cur_fps: 0.0,
            warmed_up: false,
        }
    }

    pub(crate) fn on_frame(&mut self, timestamp_ns: u64) {
        if self.last_ts != 0 && timestamp_ns <= self.last_ts {
            self.last_seen_ns = self.last_seen_ns.max(timestamp_ns);
            return;
        }

        if self.last_ts != 0 {
            let delta = timestamp_ns.saturating_sub(self.last_ts);
            if delta > PAUSE_FRAME_NS {
                self.reset_after_pause(timestamp_ns);
            } else if delta >= MIN_FRAME_NS {
                let recorded = delta.min(MAX_RECORDED_FRAME_NS);
                self.frame_times.push_front(recorded);
                self.frame_time_sum_ns = self.frame_time_sum_ns.saturating_add(recorded);
                self.trim_window();
                self.update_fps();
            }
        }

        self.last_ts = timestamp_ns;
        self.last_seen_ns = timestamp_ns;
        self.update_warmup();
    }

    pub(crate) fn on_frame_batch(&mut self, prev_ts: u64, timestamp_ns: u64, frames: u64) {
        if frames == 0 || timestamp_ns <= prev_ts || timestamp_ns <= self.last_ts {
            self.last_seen_ns = self.last_seen_ns.max(timestamp_ns);
            return;
        }

        let delta = (timestamp_ns - prev_ts) / frames.max(1);
        if delta > PAUSE_FRAME_NS {
            self.reset_after_pause(timestamp_ns);
            self.last_ts = timestamp_ns;
            self.last_seen_ns = timestamp_ns;
            return;
        }
        if delta < MIN_FRAME_NS {
            self.last_ts = timestamp_ns;
            self.last_seen_ns = timestamp_ns;
            return;
        }
        let delta = delta.min(MAX_RECORDED_FRAME_NS);

        for _ in 0..frames.min(300) {
            self.frame_times.push_front(delta);
            self.frame_time_sum_ns = self.frame_time_sum_ns.saturating_add(delta);
        }
        self.trim_window();
        self.update_fps();
        self.last_ts = timestamp_ns;
        self.last_seen_ns = timestamp_ns;
        self.update_warmup();
    }

    pub(crate) fn selection_score(&self, now_ns: u64) -> f64 {
        if !self.is_stable() {
            return f64::NEG_INFINITY;
        }
        let age_ns = now_ns
            .saturating_sub(self.last_seen_ns)
            .min(STREAM_STALE_NS);
        let freshness = 1.0 - age_ns as f64 / STREAM_STALE_NS as f64;
        let coverage = self.frame_time_sum_ns.min(FPS_WINDOW_NS) as f64 / FPS_WINDOW_NS as f64;
        freshness * 1_000.0
            + coverage * 400.0
            + self.frame_times.len().min(300) as f64
            + self.cur_fps / 10.0
    }

    fn trim_window(&mut self) {
        while self.frame_time_sum_ns > FPS_WINDOW_NS && self.frame_times.len() > 1 {
            if let Some(old) = self.frame_times.pop_back() {
                self.frame_time_sum_ns = self.frame_time_sum_ns.saturating_sub(old);
            }
        }
    }

    fn update_fps(&mut self) {
        if self.frame_time_sum_ns > 0 {
            self.cur_fps =
                self.frame_times.len() as f64 * 1_000_000_000.0 / self.frame_time_sum_ns as f64;
        }
    }

    fn update_warmup(&mut self) {
        self.warmed_up |= self.frame_times.len() >= MIN_STREAM_INTERVALS
            && self.last_seen_ns.saturating_sub(self.first_seen_ns) >= MIN_STREAM_LIFETIME_NS;
    }

    fn reset_after_pause(&mut self, timestamp_ns: u64) {
        self.frame_times.clear();
        self.frame_time_sum_ns = 0;
        self.cur_fps = 0.0;
        self.first_seen_ns = timestamp_ns;
        self.warmed_up = false;
    }

    fn is_stable(&self) -> bool {
        self.warmed_up
            && !self.frame_times.is_empty()
            && self.cur_fps.is_finite()
            && (1.0..=MAX_PLAUSIBLE_FPS).contains(&self.cur_fps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_at_fps(fps: u64, frames: usize) -> FpsStream {
        let mut stream = FpsStream::new(1_000_000_000);
        let delta = 1_000_000_000 / fps;
        for index in 0..frames {
            stream.on_frame(1_000_000_000 + delta * index as u64);
        }
        stream
    }

    #[test]
    fn stable_refresh_rates_are_accepted() {
        for fps in [30, 60, 90, 120, 144, 165, 240] {
            let stream = stream_at_fps(fps, fps as usize + 1);
            assert!(stream.selection_score(stream.last_seen_ns).is_finite());
            assert!((stream.cur_fps - fps as f64).abs() < 0.2);
        }
    }

    #[test]
    fn startup_spikes_above_plausible_refresh_are_rejected() {
        let stream = stream_at_fps(600, 100);
        assert_eq!(
            stream.selection_score(stream.last_seen_ns),
            f64::NEG_INFINITY
        );
    }

    #[test]
    fn stream_needs_a_real_warmup_window() {
        let stream = stream_at_fps(120, 8);
        assert_eq!(
            stream.selection_score(stream.last_seen_ns),
            f64::NEG_INFINITY
        );
    }

    #[test]
    fn fresh_stream_outranks_stale_stream() {
        let fresh = stream_at_fps(120, 121);
        let stale = stream_at_fps(120, 121);
        let now = fresh.last_seen_ns;
        assert!(
            fresh.selection_score(now)
                > stale.selection_score(now.saturating_add(STREAM_STALE_NS / 2))
        );
    }

    #[test]
    fn stream_keys_do_not_collide_across_processes() {
        let left = FrameStreamKey {
            pid: 100,
            tid: 0,
            surface_ptr: 0x1234,
        };
        let right = FrameStreamKey { pid: 101, ..left };
        assert_ne!(left, right);
    }

    #[test]
    fn long_jank_frame_is_kept_after_warmup() {
        let mut stream = stream_at_fps(60, 70);
        let next = stream.last_seen_ns + 450_000_000;
        stream.on_frame(next);
        assert_eq!(stream.frame_times.front().copied(), Some(450_000_000));
        assert!(stream.selection_score(next).is_finite());
        assert!(stream.cur_fps < 45.0);
    }

    #[test]
    fn real_pause_starts_a_new_warmup_window() {
        let mut stream = stream_at_fps(60, 70);
        let next = stream.last_seen_ns + PAUSE_FRAME_NS + 1;
        stream.on_frame(next);
        assert!(stream.frame_times.is_empty());
        assert_eq!(stream.selection_score(next), f64::NEG_INFINITY);
    }

    #[test]
    fn multi_second_jank_is_not_mistaken_for_a_pause() {
        let mut stream = stream_at_fps(60, 70);
        let next = stream.last_seen_ns + 2_500_000_000;
        stream.on_frame(next);
        assert_eq!(
            stream.frame_times.front().copied(),
            Some(MAX_RECORDED_FRAME_NS)
        );
        assert!(stream.selection_score(next).is_finite());
    }
}
