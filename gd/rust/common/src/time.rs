///! Waking timers for Bluetooth. Implemented using timerfd, but supposed to feel similar to
///Tokio's time
use crate::ready;

use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use nix::unistd::close;
use std::future::Future;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{self, Poll};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// Similar to tokio's sleep()
pub fn sleep(duration: Duration) -> Sleep {
    let timer = TimerFd::new(get_clock(), TimerFlags::empty()).unwrap();
    timer
        .set(
            Expiration::OneShot(TimeSpec::from(duration)),
            TimerSetTimeFlags::empty(),
        )
        .unwrap();

    Sleep {
        fd: AsyncFd::new(timer).unwrap(),
    }
}

/// Future returned by sleep()
pub struct Sleep {
    fd: AsyncFd<TimerFd>,
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match ready!(self.fd.poll_read_ready(cx)) {
            Ok(_) => {
                // Will not block, since we have confirmed it is readable
                self.fd.get_ref().wait().unwrap();
                Poll::Ready(())
            }
            Err(e) => panic!("timer error: {}", e),
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        close(self.fd.as_raw_fd()).unwrap();
    }
}

/// Similar to tokio's interval, except the first tick does *not* complete immediately
pub fn interval(period: Duration) -> Interval {
    let timer = TimerFd::new(get_clock(), TimerFlags::empty()).unwrap();
    timer
        .set(
            Expiration::Interval(TimeSpec::from(period)),
            TimerSetTimeFlags::empty(),
        )
        .unwrap();

    Interval {
        fd: AsyncFd::new(timer).unwrap(),
    }
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

impl Drop for Interval {
    fn drop(&mut self) {
        close(self.fd.as_raw_fd()).unwrap();
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
    use super::sleep;
    use crate::assert_near;
    use std::time::{Duration, Instant};

    #[test]
    fn sleep_schedule_and_then_drop() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            sleep(Duration::from_millis(200));
        });
    }

    #[test]
    fn sleep_simple_case() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let timer = Instant::now();
            sleep(Duration::from_millis(10)).await;

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
