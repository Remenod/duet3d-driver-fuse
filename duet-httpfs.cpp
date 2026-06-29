// duet-httpfs.cpp — High-performance FUSE driver for Duet RepRapFirmware HTTP API
//
// Bottlenecks fixed vs Python original:
//   ✓ Multi-threaded FUSE (was nothreads=True)
//   ✓ Per-thread libcurl handles — zero lock contention on HTTP
//   ✓ LRU file cache with configurable size limit (was unbounded → OOM risk)
//   ✓ Dir cache TTL 5 s, shared_mutex for reads (was 2 s, single lock)
//   ✓ Async background upload queue (write returns immediately)
//   ✓ Session reconnect only on 401/transport error (was every half-timeout)
//   ✓ DNS cache disabled → external NAT/port-forward changes are transparent
//   ✓ HTTP redirects followed → port-forward can 3xx to new target
//   ✓ Retry on transport errors, not just 401
//   ✓ Zero Python GIL
//
// Correctness / robustness fixes — the "reads sometimes return 0 bytes" bug had
// several independent causes, all fixed here:
//   ✓ readdir (the DOMINANT cause): it handed the kernel an incomplete stat
//     (file type only) under FUSE_FILL_DIR_PLUS, so after a single `ls` the
//     kernel cached every file as size 0 and then answered read() with instant
//     EOF — without ever calling op_read. readdir now fills the real size and
//     timestamps (via the same fill_stat getattr uses).
//   ✓ rr_download occasionally returns an empty/truncated HTTP 200 under load:
//     downloads are now validated against the printer-reported size (and
//     Content-Length), short bodies are retried, and a verified-bad body
//     surfaces EIO instead of being cached and served as 0 bytes. A would-be-
//     empty result is double-checked against a fresh listing so a transient
//     size-0 listing cannot poison the cache.
//   ✓ getattr reports the cached buffer length when a dirty/transient-0 listing
//     would otherwise make the kernel clamp read() to 0 bytes.
//   ✓ Uploads are serialised per file and kept as POSTs across redirects, so a
//     file is never hit by two concurrent/again-degraded-to-GET requests.
//
// Efficiency:
//   ✓ Download bytes are moved (not copied) into the cache; HttpResult carries
//     raw bytes instead of a std::string round-trip.
//   ✓ url_encode reuses the per-thread curl handle (no alloc/free per request).
//   ✓ Per-path locks use a fixed stripe pool (was an unbounded, leaking map).
//
// Build:
//   # Install deps (Arch / Manjaro)
//   sudo pacman -S fuse3 libcurl-gnutls
//   # OR Debian/Ubuntu: sudo apt install libfuse3-dev libcurl4-openssl-dev
//
//   # Get nlohmann/json (single header, no extra build step)
//   wget -q -O json.hpp \
//     https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
//
//   g++ -O2 -std=c++17 -o duet-httpfs duet-httpfs.cpp \
//       $(pkg-config --cflags --libs fuse3 libcurl) -lpthread
//
// Usage:
//   DUET_PASSWORD="" DUET_ROOT="/" \
//     ./duet-httpfs http://192.168.0.x:80 ~/duet_printer [fuse-opts]
//
//   Extra options (before any FUSE options):
//     --cache-mb=N    LRU file cache in MiB  (default 256)
//     --dir-ttl=N     Dir cache TTL seconds  (default 5)
//     --log=PATH      Log file               (default /tmp/duet-httpfs.log)
//
// IP-transparency note:
//   If an external iptables/nftables/socat rule redirects traffic
//   (e.g. 192.168.0.x:80 → 10.x.x.x:8xxx), this driver is fully compatible:
//     • CURLOPT_DNS_CACHE_TIMEOUT=0  — no stale DNS
//     • CURLOPT_FOLLOWLOCATION=1     — follows 3xx redirects
//     • transport errors → session reconnect → fresh TCP connection
//   The URL you pass on the command line never needs to change.

#define FUSE_USE_VERSION 35

// ─── POSIX / system ──────────────────────────────────────────────────────────
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

// ─── C++ ─────────────────────────────────────────────────────────────────────
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ─── FUSE ────────────────────────────────────────────────────────────────────
#include <fuse3/fuse.h>

// ─── libcurl ─────────────────────────────────────────────────────────────────
#include <curl/curl.h>

// ─── nlohmann/json ───────────────────────────────────────────────────────────
#include "json.hpp"
using json = nlohmann::json;

using namespace std::chrono_literals;

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  Config                                                                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

struct Config {
    std::string base_url;
    std::string password;
    std::string remote_root = "/";
    std::string mountpoint;
    std::string log_file    = "/tmp/duet-httpfs.log";
    size_t      cache_mb    = 256;
    double      dir_ttl_s   = 5.0;
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  Logging                                                                  ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

static FILE*      g_log     = nullptr;
static std::mutex g_log_mtx;

__attribute__((format(printf, 1, 2)))
static void logf(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap;
    va_start(ap, fmt);
    {
        std::lock_guard<std::mutex> lk(g_log_mtx);
        vfprintf(g_log, fmt, ap);
        fflush(g_log);
    }
    va_end(ap);
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  HTTP layer — per-thread libcurl easy handles                            ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

static size_t curl_write_cb(void* ptr, size_t sz, size_t nm, void* ud) {
    auto* v = static_cast<std::vector<uint8_t>*>(ud);
    auto  n = sz * nm;
    v->insert(v->end(), (const uint8_t*)ptr, (const uint8_t*)ptr + n);
    return n;
}

struct TlsCurl {
    CURL* h = nullptr;

    TlsCurl() {
        h = curl_easy_init();
        if (!h) throw std::runtime_error("curl_easy_init failed");

        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION,   curl_write_cb);
        curl_easy_setopt(h, CURLOPT_TIMEOUT,          60L);
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT,   10L);

        // Keep-alive to amortise TCP handshake cost
        curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE,     1L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPIDLE,      5L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPINTVL,     5L);

        // ── IP-transparency ────────────────────────────────────────────────
        // No DNS caching: if external NAT/forward changes the target address,
        // the next connection sees the new route immediately.
        curl_easy_setopt(h, CURLOPT_DNS_CACHE_TIMEOUT, 0L);

        // Follow HTTP redirects so a port-forward can 301/302 to a new host.
        curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION,    1L);
        curl_easy_setopt(h, CURLOPT_MAXREDIRS,         5L);

        // Keep POSTs as POSTs across redirects. Without this, a 301/302 on an
        // rr_upload silently degrades to a GET and the upload body is dropped.
        curl_easy_setopt(h, CURLOPT_POSTREDIR, (long)CURL_REDIR_POST_ALL);

        // Reuse connections when possible (latency wins).
        curl_easy_setopt(h, CURLOPT_FORBID_REUSE,      0L);
    }

    ~TlsCurl() { if (h) curl_easy_cleanup(h); }

    TlsCurl(const TlsCurl&)            = delete;
    TlsCurl& operator=(const TlsCurl&) = delete;
};

// One CURL handle per FUSE worker thread, created on first use, destroyed
// when the thread exits.  Zero serialization between threads.
static thread_local std::unique_ptr<TlsCurl> tls_curl;
static CURL* get_curl() {
    if (!tls_curl) tls_curl = std::make_unique<TlsCurl>();
    return tls_curl->h;
}

static std::string url_encode(const std::string& s) {
    if (s.empty()) return {};
    // Reuse this thread's curl handle for escaping instead of allocating and
    // freeing a fresh handle on every call (this is on the hot path of every
    // request). curl_easy_escape does not touch transfer state, and escaping
    // always happens sequentially before the request on the same thread.
    char* enc = curl_easy_escape(get_curl(), s.c_str(), (int)s.size());
    if (!enc) throw std::runtime_error("curl_easy_escape failed");
    std::string r = enc;
    curl_free(enc);
    return r;
}

struct HttpResult {
    long                 code = 0;  // -1 = transport error
    std::vector<uint8_t> body;      // raw bytes; avoids a copy on file download
};

static std::string json_scalar_to_string(const json& j, const char* key,
                                         const std::string& fallback = "") {
    if (!j.contains(key) || j.at(key).is_null()) return fallback;

    const auto& v = j.at(key);
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number_unsigned()) return std::to_string(v.get<unsigned long long>());
    if (v.is_number_integer())  return std::to_string(v.get<long long>());
    if (v.is_number_float())    return std::to_string(v.get<double>());
    if (v.is_boolean())         return v.get<bool>() ? "true" : "false";

    return fallback;
}

static std::string normalize_base_url(std::string url) {
    if (url.find("://") == std::string::npos)
        url = "http://" + url;

    const auto scheme_pos = url.find("://");
    const size_t min_len = (scheme_pos == std::string::npos) ? 0 : scheme_pos + 3;
    while (url.size() > min_len && url.back() == '/')
        url.pop_back();
    return url;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  HTTP concurrency limiter                                                 ║
// ║                                                                           ║
// ║  RepRapFirmware runs on a single-core MCU and serves HTTP from a small    ║
// ║  number of internal worker slots. Hammering it with many parallel         ║
// ║  requests (as happens during `cp -r` of hundreds of files through a       ║
// ║  multi-threaded FUSE) causes the firmware to return malformed/empty       ║
// ║  responses or HTTP 503. We cap concurrent HTTP requests to a small        ║
// ║  number to keep the printer happy while still benefiting from             ║
// ║  multi-threaded FUSE on the local side (cache hits, etc.).                ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

class HttpSemaphore {
public:
    explicit HttpSemaphore(int max) : permits_(max) {}
    void acquire() {
        std::unique_lock lk(mtx_);
        cv_.wait(lk, [this] { return permits_ > 0; });
        --permits_;
    }
    void release() {
        {
            std::lock_guard lk(mtx_);
            ++permits_;
        }
        cv_.notify_one();
    }
private:
    std::mutex              mtx_;
    std::condition_variable cv_;
    int                     permits_;
};

class HttpPermit {
public:
    explicit HttpPermit(HttpSemaphore& s) : s_(s) { s_.acquire(); }
    ~HttpPermit() { s_.release(); }
    HttpPermit(const HttpPermit&)            = delete;
    HttpPermit& operator=(const HttpPermit&) = delete;
private:
    HttpSemaphore& s_;
};

// Global limiter: RRF tolerates 2-3 concurrent HTTP requests reliably.
// We use 2 to be conservative — the bottleneck is the printer, not the
// network, so adding more parallelism doesn't help anyway.
static HttpSemaphore g_http_sem(2);

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  Session — Duet rr_connect / X-Session-Key management                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

class Session {
public:
    explicit Session(std::string url, std::string pw)
        : base_(std::move(url)), pw_(std::move(pw)) {}

    bool connect() {
        std::unique_lock lk(mtx_);
        return do_connect();
    }

    HttpResult get(const std::string& ep, const std::string& qs) {
        return with_retry("GET", ep, qs, {});
    }

    HttpResult post(const std::string& ep, const std::string& qs,
                    std::vector<uint8_t> body) {
        return with_retry("POST", ep, qs, std::move(body));
    }

private:
    std::string base_, pw_;
    std::mutex  mtx_;
    std::string session_key_;

    bool do_connect() {
        // Called with mtx_ held
        HttpPermit permit(g_http_sem);

        CURL* c   = get_curl();
        std::string url = base_ + "/rr_connect?password=" +
                          url_encode(pw_) + "&sessionKey=yes";

        std::vector<uint8_t> buf;
        curl_easy_setopt(c, CURLOPT_URL,       url.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPGET,   1L);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, nullptr);

        CURLcode rc = curl_easy_perform(c);
        if (rc != CURLE_OK) {
            logf("[session] connect curl error: %s\n", curl_easy_strerror(rc));
            return false;
        }
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        if (code != 200) { logf("[session] connect HTTP %ld\n", code); return false; }

        try {
            auto j = json::parse(buf.begin(), buf.end());
            int err = j.value("err", 1);
            if (err != 0) {
                logf("[session] rr_connect err=%d\n", err);
                return false;
            }

            // RRF documents sessionKey as a JSON number, while some client
            // code historically treated it as a string. Convert any scalar
            // value to text because the HTTP header must be textual.
            session_key_ = json_scalar_to_string(j, "sessionKey", "");
        } catch (const std::exception& e) {
            logf("[session] parse: %s\n", e.what());
            return false;
        }
        logf("[session] connected, key=%s\n", session_key_.c_str());
        return true;
    }

    HttpResult do_request(CURL* c,
                          const std::string& method,
                          const std::string& ep,
                          const std::string& qs,
                          const std::vector<uint8_t>& body,
                          const std::string& key)
    {
        // Throttle global HTTP concurrency — see HttpSemaphore comment.
        HttpPermit permit(g_http_sem);

        std::string url = base_ + ep + (qs.empty() ? "" : "?" + qs);
        std::vector<uint8_t> buf;

        struct curl_slist* hdrs = nullptr;
        if (!key.empty()) {
            std::string h = "X-Session-Key: " + key;
            hdrs = curl_slist_append(hdrs, h.c_str());
        }

        curl_easy_setopt(c, CURLOPT_URL,       url.c_str());
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);

        if (method == "POST") {
            curl_easy_setopt(c, CURLOPT_POST,          1L);
            curl_easy_setopt(c, CURLOPT_POSTFIELDS,    body.data());
            curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
        } else {
            // Clear any POST state left on this reused thread-local handle
            // before switching to GET. HTTPGET already resets the method, but
            // a stale POSTFIELDS pointer on a reused handle is a foot-gun.
            curl_easy_setopt(c, CURLOPT_POSTFIELDS, nullptr);
            curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
        }

        CURLcode rc = curl_easy_perform(c);
        if (hdrs) curl_slist_free_all(hdrs);

        if (rc != CURLE_OK) {
            logf("[http] %s %s: %s\n",
                 method.c_str(), ep.c_str(), curl_easy_strerror(rc));
            return {-1, {}};
        }
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);

        // Defence-in-depth against truncated transfers that libcurl did not
        // already flag as CURLE_PARTIAL_FILE: if the server advertised a
        // Content-Length larger than what we actually received, treat the
        // response as a transport error so with_retry() fetches it again.
        // Short bodies under load are one of the ways the printer produces the
        // intermittent 0-byte reads this driver is meant to avoid.
        curl_off_t clen = -1;
        curl_easy_getinfo(c, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &clen);
        if (clen >= 0 && (curl_off_t)buf.size() < clen) {
            logf("[http] %s %s: short body %zu < Content-Length %lld\n",
                 method.c_str(), ep.c_str(),
                 buf.size(), (long long)clen);
            return {-1, {}};
        }
        return {code, std::move(buf)};
    }

    HttpResult with_retry(const std::string& method,
                          const std::string& ep,
                          const std::string& qs,
                          std::vector<uint8_t> body)
    {
        CURL* c = get_curl();

        std::string key;
        {
            std::lock_guard lk(mtx_);
            key = session_key_;
        }

        auto r = do_request(c, method, ep, qs, body, key);

        // Retry on:
        //   401 → expired session, reconnect.
        //   -1  → transport error, may need fresh connection.
        //   503 → RRF busy (returned during heavy I/O or while another
        //         file operation is in flight). Back off and retry.
        // We retry up to 5 times with exponential backoff capped at 1 s.
        // This is critical for `cp -r` style workloads where the printer
        // can momentarily refuse to serve a request.
        int attempts = 0;
        while ((r.code == 401 || r.code == -1 || r.code == 503) && attempts < 5) {
            ++attempts;
            int backoff_ms = std::min(50 * (1 << (attempts - 1)), 1000);
            if (r.code == 401 || r.code == -1) {
                logf("[http] retry %d after code=%ld (%s %s)\n",
                     attempts, r.code, method.c_str(), ep.c_str());
                {
                    std::unique_lock lk(mtx_);
                    do_connect();
                    key = session_key_;
                }
            } else {
                // 503: printer busy. Just wait.
                logf("[http] retry %d (busy 503) after %d ms (%s %s)\n",
                     attempts, backoff_ms, method.c_str(), ep.c_str());
            }
            std::this_thread::sleep_for(
                std::chrono::milliseconds(backoff_ms));
            r = do_request(c, method, ep, qs, body, key);
        }
        return r;
    }
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  File cache — LRU, thread-safe, configurable size limit                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

struct FileData {
    std::vector<uint8_t>                buf;
    std::atomic<bool>                   dirty{false};
    std::chrono::steady_clock::time_point mtime{std::chrono::steady_clock::now()};
    mutable std::mutex                  mtx;       // guards buf, mtime, write_gen
    uint64_t                            write_gen = 0;  // bumped on every modification
};

class FileCache {
public:
    explicit FileCache(size_t limit_bytes)
        : limit_(limit_bytes), used_(0) {}

    std::shared_ptr<FileData> get(const std::string& p) {
        std::lock_guard lk(map_mtx_);
        auto it = index_.find(p);
        if (it == index_.end()) return nullptr;
        lru_.splice(lru_.begin(), lru_, it->second.lru_it);
        return it->second.fd;
    }

    void put(const std::string& p, std::shared_ptr<FileData> fd) {
        std::lock_guard lk(map_mtx_);
        _remove(p);
        size_t sz = fd->buf.size();
        _evict(sz);
        lru_.push_front(p);
        index_[p] = {fd, sz, lru_.begin()};
        used_ += sz;
    }

    // Call after resizing fd->buf while holding fd->mtx
    void notify_resize(const std::string& p, size_t new_sz) {
        std::lock_guard lk(map_mtx_);
        auto it = index_.find(p);
        if (it == index_.end()) return;
        used_ = used_ - it->second.sz + new_sz;
        it->second.sz = new_sz;
    }

    void remove(const std::string& p) {
        std::lock_guard lk(map_mtx_);
        _remove(p);
    }

    // All dirty entries, for flush-on-shutdown
    std::vector<std::pair<std::string, std::shared_ptr<FileData>>> dirty_all() {
        std::lock_guard lk(map_mtx_);
        std::vector<std::pair<std::string, std::shared_ptr<FileData>>> r;
        for (auto& [p, n] : index_)
            if (n.fd->dirty.load()) r.emplace_back(p, n.fd);
        return r;
    }

    // Re-key after rename
    void rename(const std::string& from, const std::string& to) {
        std::lock_guard lk(map_mtx_);
        auto it = index_.find(from);
        if (it == index_.end()) return;
        auto node = std::move(it->second);
        index_.erase(it);
        *node.lru_it = to;
        index_[to]   = std::move(node);
    }

private:
    struct Node {
        std::shared_ptr<FileData>       fd;
        size_t                          sz;
        std::list<std::string>::iterator lru_it;
    };

    std::mutex map_mtx_;
    std::unordered_map<std::string, Node> index_;
    std::list<std::string>               lru_;   // front = most-recently-used
    size_t limit_, used_;

    void _remove(const std::string& p) {
        auto it = index_.find(p);
        if (it == index_.end()) return;
        used_ -= it->second.sz;
        lru_.erase(it->second.lru_it);
        index_.erase(it);
    }

    void _evict(size_t need) {
        while (!lru_.empty() && used_ + need > limit_) {
            const std::string& oldest = lru_.back();
            auto it = index_.find(oldest);
            if (it != index_.end()) {
                if (it->second.fd->dirty.load()) break; // never evict dirty
                used_ -= it->second.sz;
                index_.erase(it);
            }
            lru_.pop_back();
        }
    }
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  Directory cache — TTL-based, shared_mutex for concurrent reads           ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

struct DirEntry {
    std::string name;
    bool        is_dir;
    int64_t     size;
    std::string date_str; // "YYYY-MM-DDTHH:MM:SS"
};

class DirCache {
public:
    using Clock = std::chrono::steady_clock;

    explicit DirCache(Clock::duration ttl) : ttl_(ttl) {}

    std::optional<std::vector<DirEntry>> get(const std::string& p) const {
        std::shared_lock lk(mtx_);
        auto it = map_.find(p);
        if (it == map_.end()) return std::nullopt;
        if (Clock::now() - it->second.ts > ttl_) return std::nullopt;
        return it->second.entries;
    }

    void put(const std::string& p, std::vector<DirEntry> e) {
        std::unique_lock lk(mtx_);
        map_[p] = {std::move(e), Clock::now()};
    }

    void invalidate(const std::string& p) {
        std::unique_lock lk(mtx_);
        map_.erase(p);
        // Also the parent so ls in parent sees the updated entry
        auto pos = p.rfind('/');
        std::string par = (pos == 0 || pos == std::string::npos)
                        ? "/" : p.substr(0, pos);
        map_.erase(par);
    }

    void clear() {
        std::unique_lock lk(mtx_);
        map_.clear();
    }

private:
    struct Entry { std::vector<DirEntry> entries; Clock::time_point ts; };
    mutable std::shared_mutex mtx_;
    std::unordered_map<std::string, Entry> map_;
    Clock::duration ttl_;
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  DuetFS — core logic                                                      ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

class DuetFS {
public:
    explicit DuetFS(const Config& cfg)
        : sess_(cfg.base_url, cfg.password)
        , remote_root_(clean_root(cfg.remote_root))
        , fcache_(cfg.cache_mb * 1024ULL * 1024)
        , dcache_(std::chrono::duration_cast<DirCache::Clock::duration>(
                      std::chrono::duration<double>(cfg.dir_ttl_s)))
        , uid_(getuid()), gid_(getgid())
    {
        if (!sess_.connect())
            throw std::runtime_error("Cannot connect to Duet at " + cfg.base_url);
        upload_thread_ = std::thread([this] { upload_worker(); });
    }

    ~DuetFS() {
        // Flush everything synchronously before exiting
        for (auto& [p, fd] : fcache_.dirty_all()) {
            try { do_upload(p, fd); }
            catch (const std::exception& e) {
                logf("[shutdown] upload %s failed: %s\n", p.c_str(), e.what());
            }
        }
        {
            std::lock_guard lk(uq_mtx_);
            uq_stop_ = true;
        }
        uq_cv_.notify_all();
        if (upload_thread_.joinable()) upload_thread_.join();
    }

    // ── FUSE operations ───────────────────────────────────────────────────

    int op_getattr(const char* path, struct stat* st,
                   struct fuse_file_info* /*fi*/) noexcept
    {
        try {
            auto item = find_item(path);
            fill_stat(st, item, path);
            return 0;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                   off_t /*off*/, struct fuse_file_info* /*fi*/,
                   enum fuse_readdir_flags /*flags*/) noexcept
    {
        try {
            auto entries = list_dir(path);
            filler(buf, ".",  nullptr, 0, FUSE_FILL_DIR_PLUS);
            filler(buf, "..", nullptr, 0, FUSE_FILL_DIR_PLUS);

            // Hand the kernel a COMPLETE stat (size + timestamps), not just the
            // file type. This is critical: with FUSE_FILL_DIR_PLUS the kernel
            // caches these attributes as authoritative (readdirplus). If we set
            // only st_mode, every file is cached as size 0 — and the kernel
            // then answers read() with instant EOF (0 bytes) WITHOUT ever
            // calling op_read. That is the dominant cause of the "ls shows 0 /
            // cat returns nothing" symptom: an `ls` poisons the attribute cache
            // and the next read of any file comes back empty until the cache
            // expires. Filling the real size (from the dir listing, via the
            // same fill_stat used by getattr) is what makes `ls -l` correct and
            // makes reads actually return data.
            const std::string prefix =
                (std::strcmp(path, "/") == 0) ? std::string() : std::string(path);
            for (const auto& e : entries) {
                struct stat st{};
                ItemInfo info{e.is_dir, e.size, e.date_str};
                const std::string full = prefix + "/" + e.name;
                fill_stat(&st, info, full.c_str());
                filler(buf, e.name.c_str(), &st, 0, FUSE_FILL_DIR_PLUS);
            }
            return 0;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_open(const char* path, struct fuse_file_info* fi) noexcept {
        try {
            auto item = find_item(path);
            if (item.is_dir) return -EISDIR;
            // Pre-load existing content for writable opens so a partial write
            // (at a non-zero offset) sees the real file — UNLESS the caller
            // passed O_TRUNC, which means it is going to replace the whole file
            // and a download would be wasted. A failure here (throws) fails the
            // open, surfacing the error early. We deliberately do NOT cache a
            // per-handle FileData pointer in fi->fh: with a multithreaded FUSE
            // loop that is both a data race on the pointer and a correctness
            // hazard if the (clean) cache entry is evicted under it. Resolving
            // by path each op keeps the cache the single source of truth — and
            // for an HTTP-backed FS the map lookup is noise next to the round
            // trip it avoids.
            if ((fi->flags & (O_WRONLY | O_RDWR)) && !(fi->flags & O_TRUNC))
                load_for_modify(path);
            return 0;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_create(const char* path, mode_t /*mode*/,
                  struct fuse_file_info* /*fi*/) noexcept
    {
        try {
            auto fd   = std::make_shared<FileData>();
            fd->dirty = true;
            ++fd->write_gen;
            fcache_.put(path, fd);
            dcache_.invalidate(parent(path));
            return 0;
        }
        catch (...) { return -EIO; }
    }

    int op_read(const char* path, char* buf, size_t size,
                off_t offset, struct fuse_file_info* /*fi*/) noexcept
    {
        try {
            auto fd = ensure_cached(path);
            std::lock_guard lk(fd->mtx);
            if ((size_t)offset >= fd->buf.size()) return 0;
            size_t n = std::min(size, fd->buf.size() - (size_t)offset);
            std::memcpy(buf, fd->buf.data() + offset, n);
            return (int)n;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_write(const char* path, const char* buf, size_t size,
                 off_t offset, struct fuse_file_info* /*fi*/) noexcept
    {
        try {
            auto fd = load_for_modify(path);   // existing content, or empty
            {
                std::lock_guard lk(fd->mtx);
                auto end = (size_t)offset + size;
                if (fd->buf.size() < end) fd->buf.resize(end, 0);
                std::memcpy(fd->buf.data() + offset, buf, size);
                fd->dirty = true;
                fd->mtime = std::chrono::steady_clock::now();
                ++fd->write_gen;
            }
            fcache_.notify_resize(path, fd->buf.size());
            return (int)size;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_truncate(const char* path, off_t length,
                    struct fuse_file_info* /*fi*/) noexcept
    {
        try {
            std::shared_ptr<FileData> fd;
            if (length == 0) {
                // Discarding all content — no point fetching the original just
                // to throw it away (the common O_TRUNC overwrite path).
                fd = fcache_.get(path);
                if (!fd) {
                    std::lock_guard plk(path_lock(path));
                    fd = fcache_.get(path);
                    if (!fd) {
                        fd = std::make_shared<FileData>();
                        fcache_.put(path, fd);
                    }
                }
            } else {
                // Shrink/extend keeps the existing prefix, so we need it.
                fd = load_for_modify(path);
            }
            {
                std::lock_guard lk(fd->mtx);
                fd->buf.resize((size_t)length, 0);
                fd->dirty = true;
                fd->mtime = std::chrono::steady_clock::now();
                ++fd->write_gen;
            }
            fcache_.notify_resize(path, (size_t)length);
            return 0;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_flush(const char* path, struct fuse_file_info* /*fi*/) noexcept {
        return upload_sync(path);
    }

    int op_fsync(const char* path, int /*ds*/,
                 struct fuse_file_info* /*fi*/) noexcept {
        return upload_sync(path);
    }

    int op_release(const char* path, struct fuse_file_info* /*fi*/) noexcept {
        // Only schedule an upload if the file is actually dirty. A plain
        // read-only open should not generate any HTTP traffic on close.
        auto fd = fcache_.get(path);
        if (fd && fd->dirty.load()) enqueue_upload(path);
        return 0;
    }

    int op_unlink(const char* path) noexcept {
        try {
            auto r = sess_.get("/rr_delete",
                               "name=" + url_encode(remote(path)));
            if (r.code != 200) return -EIO;
            auto j = json::parse(r.body.begin(), r.body.end());
            if (j.value("err", 1) != 0) return -EIO;
            fcache_.remove(path);
            dcache_.invalidate(parent(path));
            return 0;
        } catch (...) { return -EIO; }
    }

    int op_mkdir(const char* path, mode_t /*m*/) noexcept {
        try {
            auto r = sess_.get("/rr_mkdir",
                               "dir=" + url_encode(remote(path)));
            if (r.code != 200) return -EIO;
            auto j = json::parse(r.body.begin(), r.body.end());
            if (j.value("err", 1) != 0) return -EIO;
            dcache_.invalidate(parent(path));
            return 0;
        } catch (...) { return -EIO; }
    }

    int op_rmdir(const char* path) noexcept { return op_unlink(path); }

    int op_rename(const char* old_path, const char* new_path,
                  unsigned /*flags*/) noexcept
    {
        try {
            upload_sync(old_path);
            auto r = sess_.get("/rr_move",
                               "old=" + url_encode(remote(old_path)) +
                               "&new=" + url_encode(remote(new_path)) +
                               "&deleteexisting=yes");
            if (r.code != 200) return -EIO;
            auto j = json::parse(r.body.begin(), r.body.end());
            if (j.value("err", 1) != 0) return -EIO;
            fcache_.rename(old_path, new_path);
            dcache_.invalidate(parent(old_path));
            dcache_.invalidate(parent(new_path));
            return 0;
        } catch (...) { return -EIO; }
    }

    int op_chmod (const char*, mode_t, struct fuse_file_info*) noexcept { return 0; }
    int op_chown (const char*, uid_t, gid_t, struct fuse_file_info*) noexcept { return 0; }
    int op_utimens(const char*, const struct timespec*,
                   struct fuse_file_info*) noexcept { return 0; }

    int op_access(const char* path, int /*mode*/) noexcept {
        try { find_item(path); return 0; }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_statfs(const char* /*path*/, struct statvfs* sv) noexcept {
        sv->f_bsize   = 4096;
        sv->f_frsize  = 4096;
        sv->f_blocks  = 1024ULL * 1024;
        sv->f_bfree   = 512ULL  * 1024;
        sv->f_bavail  = 512ULL  * 1024;
        sv->f_files   = 100000;
        sv->f_ffree   = 50000;
        sv->f_favail  = 50000;
        sv->f_namemax = 255;
        return 0;
    }

private:
    Session     sess_;
    std::string remote_root_;
    FileCache   fcache_;
    DirCache    dcache_;
    uid_t uid_;
    gid_t gid_;

    // ── Per-path locks (lock striping) ────────────────────────────────────
    //    Serialise concurrent downloads/uploads of the SAME file so two FUSE
    //    threads don't hammer the printer with redundant requests and don't
    //    race on cache insertion. A fixed pool of stripe mutexes keyed by
    //    hash(path) bounds memory — the old per-path map inserted a mutex for
    //    every path ever touched and never erased them (an unbounded leak under
    //    `cp -r` / long-lived mounts). Same path → same stripe; distinct paths
    //    very rarely collide, and at HTTP concurrency 2 the contention is nil.
    static constexpr size_t kPathLockStripes = 64;
    std::array<std::mutex, kPathLockStripes> path_locks_;

    std::mutex& path_lock(const std::string& p) {
        return path_locks_[std::hash<std::string>{}(p) % kPathLockStripes];
    }

    // ── Async upload queue ────────────────────────────────────────────────
    std::thread              upload_thread_;
    std::mutex               uq_mtx_;
    std::condition_variable  uq_cv_;
    std::deque<std::string>  uq_queue_;
    std::unordered_set<std::string> uq_pending_;
    bool uq_stop_ = false;

    void enqueue_upload(const std::string& p) {
        std::lock_guard lk(uq_mtx_);
        if (!uq_pending_.count(p)) {
            uq_pending_.insert(p);
            uq_queue_.push_back(p);
            uq_cv_.notify_one();
        }
    }

    void upload_worker() {
        while (true) {
            std::string path;
            {
                std::unique_lock lk(uq_mtx_);
                uq_cv_.wait(lk, [this] {
                    return !uq_queue_.empty() || uq_stop_;
                });
                if (uq_stop_ && uq_queue_.empty()) return;
                if (uq_queue_.empty()) continue;
                path = uq_queue_.front();
                uq_queue_.pop_front();
                uq_pending_.erase(path);
            }
            auto fd = fcache_.get(path);
            if (!fd) continue;
            try { do_upload(path, fd); }
            catch (const std::exception& e) {
                logf("[upload-async] %s failed: %s\n", path.c_str(), e.what());
            }
        }
    }

    // ── Path helpers ──────────────────────────────────────────────────────

    static std::string clean_root(const std::string& r) {
        if (r.empty()) return "/";
        std::string s = r;
        if (s.front() != '/') s = "/" + s;
        while (s.size() > 1 && s.back() == '/') s.pop_back();
        return s;
    }

    std::string remote(const std::string& local) const {
        std::string l = local;
        if (l.empty() || l.front() != '/') l = "/" + l;
        while (l.size() > 1 && l.back() == '/') l.pop_back();
        if (remote_root_ == "/") return l;
        if (l == "/") return remote_root_;
        return remote_root_ + l;
    }

    static std::string parent(const std::string& p) {
        if (p == "/" || p.empty()) return "/";
        auto pos = p.rfind('/');
        if (pos == 0) return "/";
        return p.substr(0, pos);
    }

    static std::string basename_of(const std::string& p) {
        auto pos = p.rfind('/');
        return pos == std::string::npos ? p : p.substr(pos + 1);
    }

    static time_t parse_date(const std::string& s) {
        if (s.empty()) return time(nullptr);
        struct tm tm{};
        if (sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d",
                   &tm.tm_year, &tm.tm_mon,  &tm.tm_mday,
                   &tm.tm_hour, &tm.tm_min,  &tm.tm_sec) == 6)
        {
            tm.tm_year -= 1900;
            tm.tm_mon  -= 1;
            tm.tm_isdst = -1;
            return mktime(&tm);
        }
        return time(nullptr);
    }

    // ── Directory listing (with cache) ────────────────────────────────────

    std::vector<DirEntry> list_dir(const std::string& local) {
        if (auto c = dcache_.get(local)) return *c;

        std::string rem = remote(local);
        std::vector<DirEntry> result;
        int first = 0;

        while (true) {
            std::string qs = "dir=" + url_encode(rem) +
                             "&first=" + std::to_string(first) +
                             "&max=1000";
            auto r = sess_.get("/rr_filelist", qs);

            if (r.code == -1) throw_io();
            if (r.code == 404) throw_noent();
            if (r.code != 200) throw_io();

            auto j   = json::parse(r.body.begin(), r.body.end());
            int  err = j.value("err", 0);
            if (err == 2) throw_noent();
            if (err != 0) throw_io();

            for (const auto& f : j.value("files", json::array())) {
                DirEntry e;
                e.name     = f.value("name", "");
                e.is_dir   = f.value("type", "f") == "d";
                e.size     = f.value("size", 0LL);
                e.date_str = f.value("date", "");
                if (!e.name.empty()) result.push_back(std::move(e));
            }

            int next = j.value("next", 0);
            if (!next) break;
            first = next;
        }

        dcache_.put(local, result);
        return result;
    }

    // ── Find item info ────────────────────────────────────────────────────

    struct ItemInfo {
        bool        is_dir   = false;
        int64_t     size     = 0;
        std::string date_str;
    };

    ItemInfo find_item(const std::string& local) {
        if (local == "/" || local.empty()) return {true, 4096, {}};

        const std::string par  = parent(local);
        const std::string name = basename_of(local);

        for (const auto& e : list_dir(par))
            if (e.name == name)
                return {e.is_dir, e.size, e.date_str};

        // Newly-created file not yet visible in dir listing
        if (auto fd = fcache_.get(local)) {
            std::lock_guard lk(fd->mtx);
            return {false, (int64_t)fd->buf.size(), {}};
        }

        throw_noent();
        __builtin_unreachable();
    }

    void fill_stat(struct stat* st, const ItemInfo& info, const char* path) {
        std::memset(st, 0, sizeof(*st));
        st->st_uid  = uid_;
        st->st_gid  = gid_;
        st->st_ino  = std::hash<std::string>{}(std::string(path)) & 0xFFFFFFFF;

        time_t t    = parse_date(info.date_str);
        st->st_atime = st->st_mtime = st->st_ctime = t;

        if (info.is_dir) {
            st->st_mode  = S_IFDIR | 0755;
            st->st_nlink = 2;
            st->st_size  = 4096;
        } else {
            st->st_mode  = S_IFREG | 0644;
            st->st_nlink = 1;
            st->st_size  = info.size;

            if (auto fd = fcache_.get(std::string(path))) {
                std::lock_guard lk(fd->mtx);
                if (fd->dirty.load()) {
                    // Dirty: the cached buffer is the only truth (the new data
                    // is not on the printer yet). Report its size and mtime.
                    st->st_size  = (off_t)fd->buf.size();
                    auto dur     = fd->mtime.time_since_epoch();
                    st->st_mtime = st->st_ctime =
                        std::chrono::duration_cast<std::chrono::seconds>(dur).count();
                } else if (info.size == 0 && !fd->buf.empty()) {
                    // Clean: trust the fresh listing size, EXCEPT use the cached
                    // length as a floor when the listing transiently reports 0
                    // for a file we hold non-empty bytes for — otherwise the
                    // kernel clamps read() to 0 (the stat-side 0-byte symptom).
                    // Letting a non-zero listing win preserves freshness for
                    // files changed out-of-band on the printer.
                    st->st_size = (off_t)fd->buf.size();
                }
            }
        }
    }

    // ── Download / upload ─────────────────────────────────────────────────

    static std::chrono::milliseconds backoff_ms(int attempt) {
        // 50, 100, 200, … capped at 1000 ms
        return std::chrono::milliseconds(
            std::min(50 * (1 << (attempt - 1)), 1000));
    }

    // One-shot authoritative size of `local` via a fresh rr_filelist that does
    // NOT read or write the directory cache. Returns the size, or -1 if the
    // entry is not found or the request fails. Used only to double-check a
    // would-be-empty download against a possibly stale size-0 dir listing.
    int64_t probe_size_fresh(const std::string& local) {
        try {
            const std::string rem  = remote(parent(local));
            const std::string name = basename_of(local);
            int first = 0;
            while (true) {
                std::string qs = "dir=" + url_encode(rem) +
                                 "&first=" + std::to_string(first) + "&max=1000";
                auto r = sess_.get("/rr_filelist", qs);
                if (r.code != 200) return -1;
                auto j = json::parse(r.body.begin(), r.body.end());
                if (j.value("err", 0) != 0) return -1;
                for (const auto& f : j.value("files", json::array()))
                    if (f.value("name", "") == name)
                        return f.value("size", 0LL);
                int next = j.value("next", 0);
                if (!next) break;
                first = next;
            }
        } catch (...) { /* treat as unknown */ }
        return -1;
    }

    // Download `local` into `fd`, validating the received byte count against
    // the size the printer reported for the file (expected_size, or -1 when it
    // is unknown).
    //
    // This is the core fix for intermittent 0-byte reads: RRF occasionally
    // answers rr_download with an HTTP 200 carrying an empty or truncated body
    // while it is busy. The old code accepted any 200 and cached it, so a
    // single bad response poisoned the cache and every later read of that file
    // returned 0 bytes until eviction. Here a body whose length disagrees with
    // the expected size is never accepted: we retry the whole download with
    // backoff, and finally surface EIO (a visible error) rather than silently
    // caching and serving short data.
    void download_into(const std::string& local, FileData& fd,
                       int64_t expected_size) {
        const int kMaxAttempts = 5;
        for (int attempt = 1; ; ++attempt) {
            auto r = sess_.get("/rr_download",
                               "name=" + url_encode(remote(local)));
            if (r.code == 404) throw_noent();
            if (r.code != 200) {
                if (attempt < kMaxAttempts) {
                    std::this_thread::sleep_for(backoff_ms(attempt));
                    continue;
                }
                throw_io();
            }

            const int64_t got = (int64_t)r.body.size();

            // (1) Truncation: a body SHORTER than the size the printer reported
            //     is the under-load failure mode. We use `<` (not `!=`) so a
            //     file that legitimately GREW on the printer since our (≤dir_ttl
            //     stale) listing is accepted at its real, larger length instead
            //     of spuriously failing with EIO.
            bool bad = (expected_size > 0 && got < expected_size);

            // (2) Empty body while the listing also claims size 0: that size
            //     may itself be a stale/transient 0, so an empty 200 (the
            //     printer's glitch response) would silently poison the cache
            //     for a non-empty file. Confirm with a FRESH listing (bypassing
            //     the dir cache) before accepting 0 bytes. Only fires on empty
            //     results, so the extra round-trip is rare.
            if (!bad && got == 0 && expected_size <= 0) {
                int64_t fresh = probe_size_fresh(local);
                if (fresh > 0) bad = true;
            }

            if (bad) {
                logf("[download] %s: bad body (got %lld, expected %lld) "
                     "attempt %d/%d\n", local.c_str(), (long long)got,
                     (long long)expected_size, attempt, kMaxAttempts);
                if (attempt < kMaxAttempts) {
                    std::this_thread::sleep_for(backoff_ms(attempt));
                    continue;
                }
                throw_io();   // never cache a truncated/empty download
            }

            std::lock_guard lk(fd.mtx);
            fd.buf   = std::move(r.body);   // move, no extra copy
            fd.dirty = false;
            fd.mtime = std::chrono::steady_clock::now();
            return;
        }
    }

    // Read path: return the cached FileData, downloading (and validating) it on
    // a miss. Throws ENOENT if the file does not exist.
    std::shared_ptr<FileData> ensure_cached(const std::string& local) {
        if (auto fd = fcache_.get(local)) return fd;

        std::lock_guard plk(path_lock(local));
        if (auto fd = fcache_.get(local)) return fd;   // filled while we waited

        auto item = find_item(local);                  // throws ENOENT if absent
        if (item.is_dir) throw_isdir();

        auto fd = std::make_shared<FileData>();
        download_into(local, *fd, item.size);          // validated; throws on error
        fcache_.put(local, fd);
        return fd;
    }

    // Write path: return the cached FileData, loading existing content (so a
    // partial write sees the real file) or starting empty for a brand-new file.
    std::shared_ptr<FileData> load_for_modify(const std::string& local) {
        if (auto fd = fcache_.get(local)) return fd;

        std::lock_guard plk(path_lock(local));
        if (auto fd = fcache_.get(local)) return fd;

        auto fd = std::make_shared<FileData>();
        bool    exists   = true;
        int64_t expected = -1;
        try {
            auto item = find_item(local);
            if (item.is_dir) throw_isdir();
            expected = item.size;
        } catch (const std::system_error& e) {
            if (e.code().value() == ENOENT) exists = false;   // brand-new file
            else throw;
        }
        if (exists) download_into(local, *fd, expected);      // validated
        fcache_.put(local, fd);
        return fd;
    }

    void do_upload(const std::string& local,
                   std::shared_ptr<FileData> fd)
    {
        if (!fd->dirty.load()) return;

        // Serialise uploads (and downloads) of the same file. flush/fsync/
        // rename and the async upload worker can otherwise POST the same name
        // concurrently, and RRF returns malformed/empty responses when hit by
        // parallel requests for the same resource — the very condition behind
        // the intermittent 0-byte reads. Same path → same stripe.
        std::lock_guard plk(path_lock(local));
        if (!fd->dirty.load()) return;   // another uploader already flushed it

        // Snapshot data under lock and capture the write generation so
        // we can detect whether any concurrent write happened.
        std::vector<uint8_t> data;
        uint64_t              gen_before;
        {
            std::lock_guard lk(fd->mtx);
            data       = fd->buf;
            gen_before = fd->write_gen;
        }

        auto r = sess_.post("/rr_upload",
                            "name=" + url_encode(remote(local)),
                            std::move(data));

        if (r.code != 200) {
            logf("[upload] %s HTTP %ld\n", local.c_str(), r.code);
            throw_io();
        }

        try {
            auto j = json::parse(r.body.begin(), r.body.end());
            if (j.value("err", 1) != 0) {
                logf("[upload] %s err=%d\n", local.c_str(), j.value("err", -1));
                throw_io();
            }
        } catch (const json::parse_error&) { /* non-JSON body is ok */ }

        // Clear `dirty` only if no write happened during the upload.
        // Otherwise the next flush/release will re-upload the new data.
        bool reupload = false;
        {
            std::lock_guard lk(fd->mtx);
            if (fd->write_gen == gen_before) {
                fd->dirty.store(false);
            } else {
                reupload = true;
                logf("[upload] %s: write occurred during upload, "
                     "leaving dirty=true (will re-upload)\n", local.c_str());
            }
            fd->mtime = std::chrono::steady_clock::now();
        }
        // Re-enqueue outside fd->mtx: never hold a FileData lock across the
        // upload-queue lock (keeps the lock order simple and deadlock-free).
        if (reupload) enqueue_upload(local);
        dcache_.invalidate(parent(local));
        logf("[upload] %s ok\n", local.c_str());
    }

    int upload_sync(const std::string& local) noexcept {
        try {
            auto fd = fcache_.get(local);
            if (fd) do_upload(local, fd);
            return 0;
        } catch (...) { return -EIO; }
    }

    // ── Error helpers ─────────────────────────────────────────────────────

    [[noreturn]] static void throw_noent() {
        throw std::system_error(ENOENT, std::generic_category());
    }
    [[noreturn]] static void throw_io() {
        throw std::system_error(EIO, std::generic_category());
    }
    [[noreturn]] static void throw_isdir() {
        throw std::system_error(EISDIR, std::generic_category());
    }
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  FUSE operation shims                                                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

static DuetFS* g_fs = nullptr;

static int f_getattr(const char* p, struct stat* s, struct fuse_file_info* fi)
    { return g_fs->op_getattr(p, s, fi); }

static int f_readdir(const char* p, void* buf, fuse_fill_dir_t fill,
                     off_t off, struct fuse_file_info* fi,
                     enum fuse_readdir_flags fl)
    { return g_fs->op_readdir(p, buf, fill, off, fi, fl); }

static int f_open(const char* p, struct fuse_file_info* fi)
    { return g_fs->op_open(p, fi); }

static int f_create(const char* p, mode_t m, struct fuse_file_info* fi)
    { return g_fs->op_create(p, m, fi); }

static int f_read(const char* p, char* buf, size_t sz,
                  off_t off, struct fuse_file_info* fi)
    { return g_fs->op_read(p, buf, sz, off, fi); }

static int f_write(const char* p, const char* buf, size_t sz,
                   off_t off, struct fuse_file_info* fi)
    { return g_fs->op_write(p, buf, sz, off, fi); }

static int f_truncate(const char* p, off_t len, struct fuse_file_info* fi)
    { return g_fs->op_truncate(p, len, fi); }

static int f_flush(const char* p, struct fuse_file_info* fi)
    { return g_fs->op_flush(p, fi); }

static int f_fsync(const char* p, int ds, struct fuse_file_info* fi)
    { return g_fs->op_fsync(p, ds, fi); }

static int f_release(const char* p, struct fuse_file_info* fi)
    { return g_fs->op_release(p, fi); }

static int f_unlink(const char* p)
    { return g_fs->op_unlink(p); }

static int f_mkdir(const char* p, mode_t m)
    { return g_fs->op_mkdir(p, m); }

static int f_rmdir(const char* p)
    { return g_fs->op_rmdir(p); }

static int f_rename(const char* o, const char* n, unsigned flags)
    { return g_fs->op_rename(o, n, flags); }

static int f_chmod(const char* p, mode_t m, struct fuse_file_info* fi)
    { return g_fs->op_chmod(p, m, fi); }

static int f_chown(const char* p, uid_t u, gid_t g, struct fuse_file_info* fi)
    { return g_fs->op_chown(p, u, g, fi); }

static int f_utimens(const char* p, const struct timespec tv[2],
                     struct fuse_file_info* fi)
    { return g_fs->op_utimens(p, tv, fi); }

static int f_access(const char* p, int m)
    { return g_fs->op_access(p, m); }

static int f_statfs(const char* p, struct statvfs* sv)
    { return g_fs->op_statfs(p, sv); }

static const fuse_operations k_ops = [] {
    fuse_operations ops{};
    ops.getattr  = f_getattr;
    ops.readdir  = f_readdir;
    ops.open     = f_open;
    ops.create   = f_create;
    ops.read     = f_read;
    ops.write    = f_write;
    ops.truncate = f_truncate;
    ops.flush    = f_flush;
    ops.fsync    = f_fsync;
    ops.release  = f_release;
    ops.unlink   = f_unlink;
    ops.mkdir    = f_mkdir;
    ops.rmdir    = f_rmdir;
    ops.rename   = f_rename;
    ops.chmod    = f_chmod;
    ops.chown    = f_chown;
    ops.utimens  = f_utimens;
    ops.access   = f_access;
    ops.statfs   = f_statfs;
    return ops;
}();

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  main                                                                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

static void usage(const char* prog) {
    fprintf(stderr,
        "Usage: DUET_PASSWORD='' DUET_ROOT='/' %s <url> <mountpoint> [opts]\n"
        "\n"
        "  --cache-mb=N    LRU file cache MiB  (default 256)\n"
        "  --dir-ttl=N     Dir cache TTL sec   (default 5)\n"
        "  --log=PATH      Log file            (default /tmp/duet-httpfs.log)\n"
        "\n"
        "  Remaining options are forwarded to FUSE (e.g. -o allow_root)\n"
        "\n"
        "IP-transparency:\n"
        "  External NAT/port-forwarding (e.g. iptables DNAT, socat) is fully\n"
        "  supported.  DNS is never cached and HTTP redirects are followed,\n"
        "  so route changes are picked up on the next connection without\n"
        "  restarting the driver.\n",
        prog);
}

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(argv[0]); return 2; }

    Config cfg;
    cfg.base_url    = normalize_base_url(argv[1]);
    cfg.mountpoint  = argv[2];
    cfg.password    = getenv("DUET_PASSWORD") ? getenv("DUET_PASSWORD") : "";
    cfg.remote_root = getenv("DUET_ROOT")     ? getenv("DUET_ROOT")     : "/";

    // Parse our options; forward the rest to FUSE
    std::vector<char*> fuse_argv = {argv[0], argv[2]};
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if      (a.rfind("--cache-mb=", 0) == 0) cfg.cache_mb  = std::stoul(a.substr(11));
        else if (a.rfind("--dir-ttl=",  0) == 0) cfg.dir_ttl_s = std::stod (a.substr(10));
        else if (a.rfind("--log=",      0) == 0) cfg.log_file  = a.substr(6);
        else fuse_argv.push_back(argv[i]);
    }

    g_log = fopen(cfg.log_file.c_str(), "a");
    if (!g_log) perror(cfg.log_file.c_str());

    logf("\n=== duet-httpfs  url=%s  root=%s  cache=%zuMB  dir-ttl=%.1fs ===\n",
         cfg.base_url.c_str(), cfg.remote_root.c_str(),
         cfg.cache_mb, cfg.dir_ttl_s);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    try {
        DuetFS fs(cfg);
        g_fs = &fs;

        // -f  = foreground (required when we manage our own lifetime)
        fuse_argv.push_back(const_cast<char*>("-f"));

        int ret = fuse_main((int)fuse_argv.size(), fuse_argv.data(),
                            &k_ops, nullptr);
        g_fs = nullptr;
        curl_global_cleanup();
        if (g_log) fclose(g_log);
        return ret;

    } catch (const std::exception& e) {
        fprintf(stderr, "fatal: %s\n", e.what());
        curl_global_cleanup();
        if (g_log) fclose(g_log);
        return 1;
    }
}
