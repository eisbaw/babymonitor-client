//! In-app SDL2 video window (TASK-0115, `gui` feature) — an alternative to the
//! ffmpeg/HTTP `stream` output.
//!
//! Instead of muxing the decoded feed to MPEG-TS and serving it over HTTP for an
//! external `vlc`/`mpv`, this renders the feed in OUR OWN window. The decode is
//! **in-process** via the `ffmpeg-the-third` libavcodec binding (NOT a subprocess
//! and NOT an MPEG-TS/HTTP hop): the live pump enqueues Annex-B NALs to a bounded
//! queue (so the KCP recv/ACK loop never blocks — the TASK-0085 fix is preserved),
//! and a dedicated presenter thread feeds them to a libavcodec H.264 decoder,
//! getting YUV420 frames it uploads straight into an SDL2 IYUV texture (the GPU
//! does YUV→RGB). Decision + the ffmpeg-7 pin rationale: `re/gui_window.md`.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use babymonitor_core::Error;
use ffmpeg_the_third as ff;
use sdl2::pixels::{Color, PixelFormatEnum};

/// Drain the OS event queue and report whether the user asked to close the window
/// (the X / window-manager close, or SDL_QUIT). We read the raw SDL event **type
/// integer** via FFI rather than the sdl2 crate's `Event` enum: under nix's
/// sdl2-compat (SDL3) the enum conversion panics on some event values (e.g. 0x207)
/// the 0.37 crate does not map, so the safe `poll_iter()` is unusable. Reading the
/// integer type sidesteps that — we act only on QUIT / window-close and discard
/// everything else. This is the single place the crate needs `unsafe` (a C poll +
/// union tag read), which is why the crate is `deny(unsafe_code)`, not `forbid`.
#[allow(unsafe_code)]
fn close_requested() -> bool {
    use sdl2::sys;
    let mut quit = false;
    // SAFETY: SDL_PumpEvents/SDL_PollEvent act on the process-global event queue of
    // the initialised event subsystem (the caller holds an EventPump for the loop's
    // lifetime). We only read `type_` (the union's common tag) and, for a window
    // event, `window.event`; the `&&` short-circuits so `window.event` is read only
    // when the event IS a window event. SDL_PollEvent initialises the active union
    // variant before returning 1 (a union needs no all-bytes-init), and we read only
    // those fields, so each read is of initialised memory.
    unsafe {
        sys::SDL_PumpEvents();
        let mut ev = std::mem::MaybeUninit::<sys::SDL_Event>::uninit();
        while sys::SDL_PollEvent(ev.as_mut_ptr()) == 1 {
            let ty = ev.assume_init_ref().type_;
            if ty == sys::SDL_EventType::SDL_QUIT as u32
                || (ty == sys::SDL_EventType::SDL_WINDOWEVENT as u32
                    && ev.assume_init_ref().window.event
                        == sys::SDL_WindowEventID::SDL_WINDOWEVENT_CLOSE as u8)
            {
                quit = true;
            }
        }
    }
    quit
}

/// Smoke-test: open an SDL2 window, animate a fill for `secs` seconds. Proves the
/// SDL2 stack links + a real window opens — no camera, no decoder. Returns the
/// presented-frame count so a headless caller can confirm it ran.
pub fn selftest(secs: u64) -> Result<u64, String> {
    let sdl = sdl2::init()?;
    let video = sdl.video()?;
    let window = video
        .window("babymonitor - gui selftest", 640, 360)
        .position_centered()
        .build()
        .map_err(|e| e.to_string())?;
    let mut canvas = window.into_canvas().build().map_err(|e| e.to_string())?;
    let _pump = sdl.event_pump()?; // keep the event subsystem alive for close_requested
    eprintln!("gui-selftest: SDL window open for {secs}s (or until you close it)…");
    let start = Instant::now();
    let mut frames = 0u64;
    loop {
        // Stop on the window's close button / SDL_QUIT (raw event types — see
        // `close_requested` — because the sdl2 0.37 Event enum panics on some
        // sdl2-compat (SDL3) event values).
        if close_requested() {
            break;
        }
        let t = start.elapsed().as_millis() as u32;
        canvas.set_draw_color(Color::RGB((t / 8 % 256) as u8, 80, 160));
        canvas.clear();
        canvas.present();
        frames += 1;
        if start.elapsed().as_secs() >= secs {
            break;
        }
        std::thread::sleep(Duration::from_millis(16));
    }
    eprintln!("gui-selftest: OK — presented {frames} frames");
    Ok(frames)
}

/// Bounded NAL queue depth (Annex-B chunks). Generous headroom so the pump never
/// blocks; drop-on-full keeps the KCP recv/ACK loop alive under a slow display.
const QUEUE_CHUNKS: usize = 512;

/// An in-app SDL video window sink: the pump writes Annex-B NALs via [`send`]
/// (never blocks), a presenter thread decodes them in-process (libavcodec) and
/// renders YUV frames into an SDL2 window, counting presented frames.
///
/// Both the live A/V sink (`stream --output window` under `live`) and the offline
/// `--replay-annexb` window path (gui-only) construct + drive this. Only
/// [`stats`](Self::stats) is live-only (the live ingress/egress trace is its sole
/// caller), so just that method carries the gui-only dead-code allow.
pub struct GuiSink {
    tx: Option<SyncSender<Vec<u8>>>,
    handle: Option<JoinHandle<Result<u64, String>>>,
    enqueued: AtomicU64,
    dropped: AtomicU64,
    /// Frames actually decoded + presented to the window (shared with the thread).
    presented: Arc<AtomicU64>,
}

impl GuiSink {
    /// Launch the presenter thread (it owns SDL + the decoder). The window opens
    /// once the thread initialises; if SDL/ffmpeg init fails the error surfaces at
    /// [`finish`](Self::finish).
    pub fn spawn(title: impl Into<String>) -> Result<Self, Error> {
        let win_title = title.into();
        let (tx, rx) = sync_channel::<Vec<u8>>(QUEUE_CHUNKS);
        let presented = Arc::new(AtomicU64::new(0));
        let presented_t = Arc::clone(&presented);
        let handle = std::thread::Builder::new()
            .name("gui-presenter".into())
            .spawn(move || present_loop(&win_title, &rx, &presented_t))
            .map_err(|e| Error::Transport(format!("spawning gui presenter thread: {e}")))?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
            enqueued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            presented,
        })
    }

    /// Enqueue one Annex-B NAL for the presenter. NEVER blocks: a full queue (slow
    /// display) drops the NAL + counts it so the recv/ACK loop is never starved.
    pub fn send(&self, nal: &[u8]) {
        let Some(tx) = &self.tx else { return };
        match tx.try_send(nal.to_vec()) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Relaxed) + 1;
                if n == 1 || n % 200 == 0 {
                    eprintln!(
                        "stream (live): gui queue full — dropped {n} NAL(s) (display behind)"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Relaxed);
            }
        }
    }

    /// `(enqueued, presented, dropped)` for the live ingress/egress trace — its only
    /// caller, so gui-only builds (offline replay) see it as dead.
    #[cfg_attr(not(feature = "live"), allow(dead_code))]
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.enqueued.load(Relaxed),
            self.presented.load(Relaxed),
            self.dropped.load(Relaxed),
        )
    }

    /// Close the queue, join the presenter, and report how many frames it rendered.
    pub fn finish(mut self) -> Result<(), Error> {
        drop(self.tx.take()); // close the queue → presenter drains + exits
        let presented = if let Some(h) = self.handle.take() {
            match h.join() {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(Error::Transport(format!("gui presenter: {e}"))),
                Err(_) => return Err(Error::Transport("gui presenter thread panicked".into())),
            }
        } else {
            self.presented.load(Relaxed)
        };
        eprintln!(
            "stream (live): gui window closed — presented {presented} frames ({} dropped)",
            self.dropped.load(Relaxed)
        );
        Ok(())
    }
}

/// The presenter thread body: own SDL + a libavcodec H.264 decoder, drain NALs
/// from `rx`, decode → YUV420 frame → SDL IYUV texture → present, counting frames.
fn present_loop(title: &str, rx: &Receiver<Vec<u8>>, presented: &AtomicU64) -> Result<u64, String> {
    ff::init().map_err(|e| format!("ffmpeg init: {e}"))?;
    // We feed the decoder one NAL per packet and drain after each, so libavcodec
    // logs "[h264 @ …] no frame!" (at its ERROR level, in this build) on every
    // receive_frame that doesn't yet have a full access unit — i.e. most calls.
    // That is pure noise for a video window, and since it shares the ERROR level
    // with genuine decode complaints it can't be filtered by severity. Silence
    // libav entirely: the window's health signal is the presented/dropped frame
    // counters, not decoder chatter (corruption shows as a stalled count / garbled
    // picture). Trade-off: real decode-error text is suppressed too.
    ff::util::log::set_level(ff::util::log::Level::Quiet);

    let sdl = sdl2::init()?;
    let video = sdl.video()?;
    let window = video
        .window(title, 960, 540)
        .position_centered()
        .resizable()
        .build()
        .map_err(|e| e.to_string())?;
    let mut canvas = window.into_canvas().build().map_err(|e| e.to_string())?;
    canvas.set_draw_color(Color::RGB(0, 0, 0));
    canvas.clear();
    canvas.present();
    let texture_creator = canvas.texture_creator();
    let _pump = sdl.event_pump()?; // keep the event subsystem alive for close_requested

    // In-process H.264 decoder (libavcodec).
    let codec = ff::decoder::find(ff::codec::Id::H264).ok_or("no libavcodec H.264 decoder")?;
    let context = ff::codec::context::Context::new_with_codec(codec);
    let mut decoder = context
        .decoder()
        .video()
        .map_err(|e| format!("opening H.264 decoder: {e}"))?;

    // `texture` holds an SDL `Texture<'r>` that BORROWS `texture_creator` (its `'r`
    // is the lifetime of that borrow). Because `texture` is declared *after*
    // `texture_creator`, it is dropped *before* it — so the borrow is always valid.
    // The drain logic lives in the free `present_frames` fn (not a closure) so the
    // `'r` lifetime can be named explicitly, tying the creator borrow to the stored
    // texture; a closure cannot relate two of its captures that way (E0597).
    let mut texture: Option<(sdl2::render::Texture, u32, u32)> = None;
    let mut frame = ff::frame::Video::empty();
    let mut count: u64 = 0;

    while let Ok(nal) = rx.recv() {
        // User closed the window (X button / SDL_QUIT) -> the window IS the app, so
        // stop the whole stream and exit. Raw event types (see `close_requested`)
        // because the sdl2 0.37 Event enum panics on some sdl2-compat (SDL3) values.
        if close_requested() {
            eprintln!("stream (gui): window closed — stopping the stream.");
            std::process::exit(0);
        }
        let packet = ff::Packet::copy(&nal);
        if decoder.send_packet(&packet).is_ok() {
            present_frames(
                &mut canvas,
                &texture_creator,
                &mut texture,
                &mut decoder,
                &mut frame,
                presented,
                &mut count,
            )?;
        }
    }
    // Flush the decoder at EOF.
    let _ = decoder.send_eof();
    present_frames(
        &mut canvas,
        &texture_creator,
        &mut texture,
        &mut decoder,
        &mut frame,
        presented,
        &mut count,
    )?;
    Ok(count)
}

/// Drain every frame the decoder has ready, uploading each into the SDL IYUV
/// texture and presenting it. The `'r` lifetime ties `texture_creator` to the
/// `Texture<'r>` stored in `texture`, so the borrow checker can prove the texture
/// never outlives the creator (the reason this is a free fn, not a closure).
#[allow(clippy::too_many_arguments)]
fn present_frames<'r>(
    canvas: &mut sdl2::render::Canvas<sdl2::video::Window>,
    texture_creator: &'r sdl2::render::TextureCreator<sdl2::video::WindowContext>,
    texture: &mut Option<(sdl2::render::Texture<'r>, u32, u32)>,
    decoder: &mut ff::decoder::Video,
    frame: &mut ff::frame::Video,
    presented: &AtomicU64,
    count: &mut u64,
) -> Result<(), String> {
    while decoder.receive_frame(frame).is_ok() {
        let w = frame.width();
        let h = frame.height();
        if w == 0 || h == 0 {
            continue;
        }
        // (Re)create the streaming IYUV texture when the size changes.
        if texture.as_ref().map(|t| (t.1, t.2)) != Some((w, h)) {
            let t = texture_creator
                .create_texture_streaming(PixelFormatEnum::IYUV, w, h)
                .map_err(|e| e.to_string())?;
            *texture = Some((t, w, h));
        }
        let (t, _, _) = texture.as_mut().unwrap();
        // YUV420P planes straight from libav into the texture (no swscale).
        t.update_yuv(
            None,
            frame.data(0),
            frame.stride(0),
            frame.data(1),
            frame.stride(1),
            frame.data(2),
            frame.stride(2),
        )
        .map_err(|e| e.to_string())?;
        canvas.clear();
        canvas.copy(t, None, None)?;
        canvas.present();
        *count += 1;
        presented.store(*count, Relaxed);
    }
    Ok(())
}
