//! Reloading rules and enrichment without dropping traffic.
//!
//! Changing a rule used to mean restarting, and a restart means a gap in
//! coverage at exactly the moment somebody is actively responding to
//! something. It also means the operator hesitates before tuning, which
//! is worse: a sensor nobody adjusts drifts into being ignored.
//!
//! # The constraint that shapes this
//!
//! The rule set is read on the packet path, by every worker, for every
//! packet. Whatever replaces it must therefore be readable with no lock
//! and no atomic read-modify-write in the common case, because the
//! common case is "nothing has changed" and it happens millions of times
//! per second.
//!
//! [`Hot`] is that: a generation counter and a mutex-guarded `Arc`. The
//! mutex is touched only when the generation has moved, which is once
//! per reload. Readers hold a [`Cached`] — their own `Arc` plus the
//! generation it came from — so the steady-state cost of "is my copy
//! current?" is one relaxed atomic load and one integer compare.
//!
//! This is a hand-rolled `arc-swap`, and it is hand-rolled because the
//! full generality of that crate is not needed: there is exactly one
//! writer, reloads are rare, and readers can tolerate being one
//! generation stale for the length of a packet.
//!
//! # What a failed reload does
//!
//! Nothing. A rule file that does not parse leaves the previous rules
//! in place and increments a counter. The alternative — dropping to no
//! rules, or exiting — turns a typo into an outage, and a typo in a rule
//! file at 3am is not a hypothetical.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
#[cfg(any(unix, test))]
use std::time::Duration;

/// A value that can be replaced while readers are running.
pub struct Hot<T> {
    current: Mutex<Arc<T>>,
    generation: AtomicU64,
}

impl<T> Hot<T> {
    pub fn new(value: T) -> Arc<Hot<T>> {
        Arc::new(Hot { current: Mutex::new(Arc::new(value)), generation: AtomicU64::new(1) })
    }

    /// Publishes a new value. The generation is bumped *after* the slot
    /// is updated, so a reader that observes the new generation is
    /// guaranteed to find the new value when it takes the lock.
    pub fn store(&self, value: T) {
        {
            let mut slot = self.current.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Arc::new(value);
        }
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn load(&self) -> Arc<T> {
        Arc::clone(&self.current.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// A reader's cached view of a [`Hot`] value.
///
/// Created once per worker and refreshed only when the generation moves.
pub struct Cached<T> {
    generation: u64,
    value: Arc<T>,
}

impl<T> Cached<T> {
    pub fn new(hot: &Hot<T>) -> Cached<T> {
        Cached { generation: hot.generation(), value: hot.load() }
    }

    /// The current value, refreshing first if it has been replaced.
    ///
    /// Inlined and branch-predictable: the comparison is false on every
    /// packet except the first after a reload.
    #[inline]
    pub fn get(&mut self, hot: &Hot<T>) -> &Arc<T> {
        let g = hot.generation.load(Ordering::Acquire);
        if g != self.generation {
            self.value = hot.load();
            self.generation = g;
        }
        &self.value
    }

    /// The cached value without checking for a newer one. For call sites
    /// that have already refreshed this packet.
    #[inline]
    pub fn get_cached(&self) -> &Arc<T> {
        &self.value
    }
}

// =======================================================================
// Watching files
// =======================================================================

/// Tracks the modification time and size of a set of files.
///
/// Size as well as mtime because a filesystem with one-second mtime
/// granularity — which is still common on network storage — will happily
/// report an unchanged time for a file rewritten within the same second,
/// and a rule file is exactly the kind of thing that gets rewritten by a
/// script immediately after being generated.
pub struct Watch {
    paths: Vec<String>,
    seen: Vec<Option<(SystemTime, u64)>>,
}

impl Watch {
    pub fn new<I: IntoIterator<Item = String>>(paths: I) -> Watch {
        let paths: Vec<String> = paths.into_iter().collect();
        let seen = paths.iter().map(|p| stamp(p)).collect();
        Watch { paths, seen }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// True if any watched file has changed since the last call.
    ///
    /// A file that disappears is *not* a change: an editor that writes
    /// via rename leaves the path briefly absent, and reloading from a
    /// missing file would mean reloading from nothing. The change is
    /// picked up when it reappears.
    pub fn changed(&mut self) -> bool {
        let mut changed = false;
        for (i, p) in self.paths.iter().enumerate() {
            let now = stamp(p);
            if now.is_some() && now != self.seen[i] {
                self.seen[i] = now;
                changed = true;
            }
        }
        changed
    }
}

fn stamp(path: &str) -> Option<(SystemTime, u64)> {
    let md = std::fs::metadata(path).ok()?;
    Some((md.modified().ok()?, md.len()))
}

// =======================================================================
// Signals
// =======================================================================

/// Flags a signal handler sets, polled by ordinary code.
///
/// A handler may do almost nothing safely — not allocate, not lock, not
/// call most of libc. Setting an atomic flag is one of the few things it
/// may do, so that is all these do; the work happens on a normal thread
/// that notices the flag.
pub struct Signals {
    pub reload: Arc<AtomicBool>,
    pub reopen: Arc<AtomicBool>,
}

impl Default for Signals {
    fn default() -> Self {
        Signals { reload: Arc::new(AtomicBool::new(false)), reopen: Arc::new(AtomicBool::new(false)) }
    }
}

#[cfg(unix)]
mod imp {
    use super::*;

    static RELOAD: AtomicBool = AtomicBool::new(false);
    static REOPEN: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_hup(_: libc::c_int) {
        // SIGHUP means both things by convention: re-read configuration
        // and reopen logs. Doing both is what `logrotate`'s default
        // postrotate script expects, and what an operator typing
        // `kill -HUP` means.
        RELOAD.store(true, Ordering::Release);
        REOPEN.store(true, Ordering::Release);
    }

    extern "C" fn on_usr1(_: libc::c_int) {
        REOPEN.store(true, Ordering::Release);
    }

    pub fn install(signals: &Signals) -> std::io::Result<()> {
        // SAFETY: both handlers do nothing but store to a static atomic,
        // which is async-signal-safe.
        unsafe {
            libc::signal(libc::SIGHUP, on_hup as libc::sighandler_t);
            libc::signal(libc::SIGUSR1, on_usr1 as libc::sighandler_t);
        }
        let (reload, reopen) = (Arc::clone(&signals.reload), Arc::clone(&signals.reopen));
        // The handler cannot touch an `Arc`, so a small thread bridges
        // the statics to the shared flags the rest of the program polls.
        std::thread::Builder::new().name("argus-signals".into()).spawn(move || loop {
            if RELOAD.swap(false, Ordering::AcqRel) {
                reload.store(true, Ordering::Release);
            }
            if REOPEN.swap(false, Ordering::AcqRel) {
                reopen.store(true, Ordering::Release);
            }
            std::thread::sleep(Duration::from_millis(200));
        })?;
        Ok(())
    }

    pub const DESCRIPTION: &str = "SIGHUP reloads rules and reopens logs; SIGUSR1 reopens logs";
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub fn install(_signals: &Signals) -> std::io::Result<()> {
        Ok(())
    }

    pub const DESCRIPTION: &str = "no reload signal on this platform; rules reload from disk changes";
}

impl Signals {
    pub fn install(&self) -> std::io::Result<()> {
        imp::install(self)
    }

    pub fn description() -> &'static str {
        imp::DESCRIPTION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_sees_a_new_value_only_after_it_is_published() {
        let hot = Hot::new(vec![1u32]);
        let mut cached = Cached::new(&hot);
        assert_eq!(**cached.get(&hot), vec![1]);

        hot.store(vec![1, 2, 3]);
        assert_eq!(**cached.get(&hot), vec![1, 2, 3], "the next check picks the new value up");
    }

    /// The whole point of the generation counter: a reader that has not
    /// re-checked keeps a coherent old value rather than a torn one.
    #[test]
    fn a_stale_reader_holds_a_whole_old_value_not_a_partial_one() {
        let hot = Hot::new(vec![1u32, 2, 3]);
        let mut cached = Cached::new(&hot);
        let before = cached.get(&hot).clone();
        hot.store(vec![9, 9]);
        assert_eq!(*before, vec![1, 2, 3], "the old Arc stays valid and unchanged");
        assert_eq!(cached.get_cached().len(), 3, "an unchecked reader is stale, not broken");
        assert_eq!(cached.get(&hot).len(), 2);
    }

    #[test]
    fn generations_advance_once_per_store() {
        let hot = Hot::new(0u8);
        let g0 = hot.generation();
        hot.store(1);
        hot.store(2);
        assert_eq!(hot.generation(), g0 + 2);
    }

    #[test]
    fn readers_across_threads_converge_on_the_new_value() {
        let hot = Hot::new(0u64);
        let mut handles = Vec::new();
        for _ in 0..4 {
            let hot = Arc::clone(&hot);
            handles.push(std::thread::spawn(move || {
                let mut cached = Cached::new(&hot);
                // Spin until the writer's value is visible, which it must
                // become: `store` releases and `get` acquires.
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while **cached.get(&hot) != 42 {
                    assert!(std::time::Instant::now() < deadline, "a published value must become visible");
                    std::hint::spin_loop();
                }
            }));
        }
        hot.store(42);
        for h in handles {
            h.join().unwrap();
        }
    }

    fn temp(name: &str) -> String {
        std::env::temp_dir().join(format!("argus-watch-{}-{}", std::process::id(), name)).to_string_lossy().into_owned()
    }

    #[test]
    fn a_watch_notices_a_rewrite_even_within_one_second() {
        let p = temp("rules.txt");
        std::fs::write(&p, "one").unwrap();
        let mut w = Watch::new([p.clone()]);
        assert!(!w.changed(), "nothing has happened yet");

        // Same second, different length: this is the case an mtime-only
        // watch misses on a coarse-granularity filesystem.
        std::fs::write(&p, "one two three").unwrap();
        assert!(w.changed(), "a same-second rewrite of a different size is a change");
        assert!(!w.changed(), "and it is reported once");
        let _ = std::fs::remove_file(&p);
    }

    /// An editor writing via rename makes the path briefly absent.
    /// Treating that as a change would mean reloading from nothing.
    #[test]
    fn a_vanished_file_is_not_a_change() {
        let p = temp("gone.txt");
        std::fs::write(&p, "here").unwrap();
        let mut w = Watch::new([p.clone()]);
        std::fs::remove_file(&p).unwrap();
        assert!(!w.changed(), "absence is not a new version");
        std::fs::write(&p, "back, and different").unwrap();
        assert!(w.changed(), "its return is");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn watching_nothing_is_valid_and_quiet() {
        let mut w = Watch::new(Vec::<String>::new());
        assert!(w.is_empty());
        assert!(!w.changed());
    }
}
