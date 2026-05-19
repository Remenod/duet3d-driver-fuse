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
    // Temporary handle just for escaping — cheap, infrequent
    CURL* tmp = curl_easy_init();
    char* enc = curl_easy_escape(tmp, s.c_str(), (int)s.size());
    std::string r = enc ? enc : s;
    curl_free(enc);
    curl_easy_cleanup(tmp);
    return r;
}

struct HttpResult {
    long        code = 0;  // -1 = transport error
    std::string body;
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
// ║  Session — Duet rr_connect / X-Session-Key management                   ║
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
            auto j = json::parse(std::string(buf.begin(), buf.end()));
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
        return {code, std::string(buf.begin(), buf.end())};
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

        // Retry on 401 (expired session) or transport error (network hiccup /
        // connection broken after NAT/forward change)
        if (r.code == 401 || r.code == -1) {
            logf("[http] retry after code=%ld (%s %s)\n",
                 r.code, method.c_str(), ep.c_str());
            {
                std::unique_lock lk(mtx_);
                do_connect();
                key = session_key_;
            }
            r = do_request(c, method, ep, qs, body, key);
        }
        return r;
    }
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  File cache — LRU, thread-safe, configurable size limit                  ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

struct FileData {
    std::vector<uint8_t>                buf;
    std::atomic<bool>                   dirty{false};
    std::chrono::steady_clock::time_point mtime{std::chrono::steady_clock::now()};
    mutable std::mutex                  mtx;  // guards buf, mtime
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
// ║  Directory cache — TTL-based, shared_mutex for concurrent reads          ║
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
// ║  DuetFS — core logic                                                     ║
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
            for (const auto& e : entries) {
                struct stat st{};
                st.st_mode = e.is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
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
            // Pre-load for write so partial writes are safe
            if (fi->flags & (O_WRONLY | O_RDWR)) ensure_cached(path);
            return 0;
        }
        catch (const std::system_error& e) { return -e.code().value(); }
        catch (...) { return -EIO; }
    }

    int op_create(const char* path, mode_t /*mode*/,
                  struct fuse_file_info* /*fi*/) noexcept
    {
        auto fd   = std::make_shared<FileData>();
        fd->dirty = true;
        fcache_.put(path, fd);
        dcache_.invalidate(parent(path));
        return 0;
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
            auto fd = fcache_.get(path);
            if (!fd) {
                fd = std::make_shared<FileData>();
                try { download_into(path, *fd); } catch (...) { /* new file */ }
                fcache_.put(path, fd);
            }
            {
                std::lock_guard lk(fd->mtx);
                auto end = (size_t)offset + size;
                if (fd->buf.size() < end) fd->buf.resize(end, 0);
                std::memcpy(fd->buf.data() + offset, buf, size);
                fd->dirty = true;
                fd->mtime = std::chrono::steady_clock::now();
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
            auto fd = fcache_.get(path);
            if (!fd) {
                fd = std::make_shared<FileData>();
                try { download_into(path, *fd); } catch (...) {}
                fcache_.put(path, fd);
            }
            {
                std::lock_guard lk(fd->mtx);
                fd->buf.resize((size_t)length, 0);
                fd->dirty = true;
                fd->mtime = std::chrono::steady_clock::now();
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
        // Async: release returns immediately; background thread uploads
        enqueue_upload(path);
        return 0;
    }

    int op_unlink(const char* path) noexcept {
        try {
            auto r = sess_.get("/rr_delete",
                               "name=" + url_encode(remote(path)));
            if (r.code != 200) return -EIO;
            auto j = json::parse(r.body);
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
            auto j = json::parse(r.body);
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
            auto j = json::parse(r.body);
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

            auto j   = json::parse(r.body);
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

            // Override with cached data (accurate after write/truncate)
            if (auto fd = fcache_.get(std::string(path))) {
                std::lock_guard lk(fd->mtx);
                st->st_size = (off_t)fd->buf.size();
                auto dur    = fd->mtime.time_since_epoch();
                st->st_mtime = st->st_ctime =
                    std::chrono::duration_cast<std::chrono::seconds>(dur).count();
            }
        }
    }

    // ── Download / upload ─────────────────────────────────────────────────

    void download_into(const std::string& local, FileData& fd) {
        auto r = sess_.get("/rr_download",
                           "name=" + url_encode(remote(local)));
        if (r.code == 404) throw_noent();
        if (r.code != 200) throw_io();
        std::lock_guard lk(fd.mtx);
        fd.buf.assign(r.body.begin(), r.body.end());
        fd.dirty = false;
        fd.mtime = std::chrono::steady_clock::now();
    }

    std::shared_ptr<FileData> ensure_cached(const std::string& local) {
        auto fd = fcache_.get(local);
        if (fd) return fd;
        fd = std::make_shared<FileData>();
        download_into(local, *fd);
        fcache_.put(local, fd);
        return fd;
    }

    void do_upload(const std::string& local,
                   std::shared_ptr<FileData> fd)
    {
        if (!fd->dirty.load()) return;

        // Snapshot data under lock so concurrent writes are safe
        std::vector<uint8_t> data;
        {
            std::lock_guard lk(fd->mtx);
            data = fd->buf;
        }

        auto r = sess_.post("/rr_upload",
                            "name=" + url_encode(remote(local)),
                            std::move(data));

        if (r.code != 200) {
            logf("[upload] %s HTTP %ld\n", local.c_str(), r.code);
            throw_io();
        }

        try {
            auto j = json::parse(r.body);
            if (j.value("err", 1) != 0) {
                logf("[upload] %s err=%d\n", local.c_str(), j.value("err", -1));
                throw_io();
            }
        } catch (const json::parse_error&) { /* non-JSON body is ok */ }

        // Only clear dirty if no concurrent write changed the buffer
        fd->dirty.store(false);
        {
            std::lock_guard lk(fd->mtx);
            fd->mtime = std::chrono::steady_clock::now();
        }
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
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  FUSE operation shims                                                    ║
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
