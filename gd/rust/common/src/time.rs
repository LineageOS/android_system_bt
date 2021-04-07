///! Waking timers for Bluetooth. Implemented using timerfd, but supposed to feel similar to
///Tokio's time
use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// A single shot Alarm
pub struct Alarm {
    fd: AsyncFd<TimerFd>,
}

impl Alarm {
    /// Construct a new alarm
    pub fn new() -> Self {
        let timer = TimerFd::new(get_clock(), TimerFlags::empty()).unwrap();
        Self { fd: AsyncFd::new(timer).unwrap() }
    }

    /// Reset the alarm to duration, starting from now
    pub fn reset(&mut self, duration: Duration) {
        self.fd
            .get_ref()
            .set(Expiration::OneShot(TimeSpec::from(duration)), TimerSetTimeFlags::empty())
            .unwrap();
    }

    /// Stop the alarm if it is currently started
    pub fn cancel(&mut self) {
        self.reset(Duration::from_millis(0));
    }

    /// Completes when the alarm has expired
    pub async fn expired(&mut self) {
        drop(self.fd.readable().await.unwrap());
        // Will not block, since we have confirmed it is readable
        self.fd.get_ref().wait().unwrap();
    }
}

impl Default for Alarm {
    fn default() -> Self {
        Alarm::new()
    }
}

/// Similar to tokio's interval, except the first tick does *not* complete immediately
pub fn interval(period: Duration) -> Interval {
    let timer = TimerFd::new(get_clock(), TimerFlags::empty()).unwrap();
    timer.set(Expiration::Interval(TimeSpec::from(period)), TimerSetTimeFlags::empty()).unwrap();

    Interval { fd: AsyncFd::new(timer).unwrap() }
}

/// Future returned by interval()
pub struct Interval {
    fd: AsyncFd<TimerFd>,
}

impl Interval {
    /// Call this to get the future for the next tick of the interval
    pub async fn tick(&mut self) {
        drop(self.fd.readable().await.unwrap());
        // Will not block, since we have confirmed it is readable
        self.fd.get_ref().wait().unwrap();
    }
}

fn get_clock() -> ClockId {
    if cfg!(target_os = "android") {
        ClockId::CLOCK_BOOTTIME_ALARM
    } else {
        ClockId::CLOCK_BOOTTIME
    }
}

#[cfg(test)]
mod tests {
    use super::interval;
    use super::Alarm;
    use crate::assert_near;
    use std::time::{Duration, Instant};

    #[test]
    fn alarm_simple_case() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let timer = Instant::now();
            let mut alarm = Alarm::new();
            alarm.reset(Duration::from_millis(10));
            alarm.expired().await;

            assert_near!(timer.elapsed().as_millis(), 10, 3);
        });
    }

    #[test]
    fn interval_schedule_and_then_drop() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            interval(Duration::from_millis(10));
        });
    }

    #[test]
    fn interval_simple_case() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let timer = Instant::now();
            let mut interval = interval(Duration::from_millis(10));

            for n in 1..10 {
                interval.tick().await;
                println!("{}", n);
                assert_near!(timer.elapsed().as_millis(), 10 * n, 3);
            }
        });
    }
}
