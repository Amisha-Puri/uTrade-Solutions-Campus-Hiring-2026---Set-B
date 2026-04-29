/**
 * ============================================================
 *  uTrade Rate Limiter — C++17  (Windows / Dev-C++ / MinGW)
 * ============================================================
 *  Algorithms : Fixed Window | Sliding Window Log | Token Bucket
 *  Transport  : HTTP/1.1 server via Winsock2
 *  Safety     : std::mutex per client + global registry lock
 *
 *  HOW TO BUILD IN Dev-C++:
 *   Tools -> Compiler Options -> Add these linker flags:
 *     -lws2_32 -mthreads
 *   Make sure "Language standard" is set to C++17 or GNU C++17.
 *
 *  Endpoints (once running):
 *    POST http://localhost:8080/request?client_id=alice&algo=fixed
 *    POST http://localhost:8080/request?client_id=alice&algo=sliding
 *    POST http://localhost:8080/request?client_id=alice&algo=token
 *    GET  http://localhost:8080/stats
 *    POST http://localhost:8080/config   body: {"max_requests":5,"window_seconds":10}
 *
 *  The program:
 *    1. Runs the multi-threaded test harness (150 requests, 5 clients)
 *    2. Starts the HTTP server on port 8080
 * ============================================================
 */

// ── Windows / Winsock2 must come FIRST ──────────────────────
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601   // Windows 7+
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
// Link: -lws2_32   (add in Dev-C++ Compiler Options -> Linker)

// ── Standard library ────────────────────────────────────────
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>


// ──────────────────────────────────────────────
//  Config
// ──────────────────────────────────────────────
struct Config {
    int max_requests   = 10;
    int window_seconds = 60;
};

// ──────────────────────────────────────────────
//  Result
// ──────────────────────────────────────────────
enum class Decision { ALLOWED, RATE_LIMITED };

struct RequestResult {
    std::string timestamp;
    std::string client_id;
    std::string algorithm;
    Decision    decision;
};

// ──────────────────────────────────────────────
//  Time helpers
// ──────────────────────────────────────────────
using Clock = std::chrono::steady_clock;

static double now_seconds() {
    static const auto origin = Clock::now();
    return std::chrono::duration<double>(Clock::now() - origin).count();
}

static std::string wall_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt  = system_clock::to_time_t(now);
    auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&tt), "%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

static std::string decision_str(Decision d) {
    return d == Decision::ALLOWED ? "ALLOWED" : "RATE_LIMITED";
}

// ══════════════════════════════════════════════
//  Algorithm 1 — Fixed Window
//  Simple counter that resets every T seconds.
//  Pro: O(1) time & space.  Con: burst at window edge.
// ══════════════════════════════════════════════
class FixedWindow {
    std::mutex mtx_;
    int    max_req_;
    double window_sec_;
    int    count_        = 0;
    double window_start_ = 0.0;
public:
    FixedWindow(int max_req, double window_sec)
        : max_req_(max_req), window_sec_(window_sec),
          window_start_(now_seconds()) {}

    Decision check() {
        std::lock_guard<std::mutex> lk(mtx_);
        double now = now_seconds();
        if (now - window_start_ >= window_sec_) {
            window_start_ = now;
            count_        = 0;
        }
        if (count_ < max_req_) { ++count_; return Decision::ALLOWED; }
        return Decision::RATE_LIMITED;
    }

    void reconfigure(int mr, double ws) {
        std::lock_guard<std::mutex> lk(mtx_);
        max_req_      = mr;  window_sec_   = ws;
        count_        = 0;   window_start_ = now_seconds();
    }
};

// ══════════════════════════════════════════════
//  Algorithm 2 — Sliding Window Log
//  Keeps a deque of timestamps; evicts those older
//  than T seconds on every call.
//  Pro: perfectly accurate.  Con: O(N) memory.
// ══════════════════════════════════════════════
class SlidingWindowLog {
    std::mutex         mtx_;
    std::deque<double> log_;
    int    max_req_;
    double window_sec_;
public:
    SlidingWindowLog(int max_req, double window_sec)
        : max_req_(max_req), window_sec_(window_sec) {}

    Decision check() {
        std::lock_guard<std::mutex> lk(mtx_);
        double now    = now_seconds();
        double cutoff = now - window_sec_;
        while (!log_.empty() && log_.front() < cutoff)
            log_.pop_front();
        if ((int)log_.size() < max_req_) {
            log_.push_back(now);
            return Decision::ALLOWED;
        }
        return Decision::RATE_LIMITED;
    }

    void reconfigure(int mr, double ws) {
        std::lock_guard<std::mutex> lk(mtx_);
        max_req_ = mr;  window_sec_ = ws;  log_.clear();
    }
};

// ══════════════════════════════════════════════
//  Algorithm 3 — Token Bucket
//  Tokens refill continuously at rate N/T per second.
//  Pro: handles bursts gracefully.  Con: slightly complex.
// ══════════════════════════════════════════════
class TokenBucket {
    std::mutex mtx_;
    double capacity_;
    double tokens_;
    double refill_rate_;   // tokens / second
    double last_refill_;
public:
    TokenBucket(int max_req, double window_sec)
        : capacity_((double)max_req),
          tokens_((double)max_req),
          refill_rate_((double)max_req / window_sec),
          last_refill_(now_seconds()) {}

    Decision check() {
        std::lock_guard<std::mutex> lk(mtx_);
        double now     = now_seconds();
        double elapsed = now - last_refill_;
        tokens_      = std::min(capacity_, tokens_ + elapsed * refill_rate_);
        last_refill_ = now;
        if (tokens_ >= 1.0) { tokens_ -= 1.0; return Decision::ALLOWED; }
        return Decision::RATE_LIMITED;
    }

    void reconfigure(int mr, double ws) {
        std::lock_guard<std::mutex> lk(mtx_);
        capacity_    = (double)mr;
        refill_rate_ = (double)mr / ws;
        tokens_      = capacity_;
        last_refill_ = now_seconds();
    }
};

// ──────────────────────────────────────────────
//  Per-client bundle — holds all 3 algorithms
// ──────────────────────────────────────────────
struct ClientLimiter {
    FixedWindow      fixed;
    SlidingWindowLog sliding;
    TokenBucket      token;

    ClientLimiter(int mr, double ws)
        : fixed(mr,ws), sliding(mr,ws), token(mr,ws) {}

    void reconfigure(int mr, double ws) {
        fixed.reconfigure(mr,ws);
        sliding.reconfigure(mr,ws);
        token.reconfigure(mr,ws);
    }
};

// ──────────────────────────────────────────────
//  Per-client stats (lock-free counters)
// ──────────────────────────────────────────────
struct ClientStats {
    std::atomic<long> total{0};
    std::atomic<long> allowed{0};
    std::atomic<long> rejected{0};
};

// ══════════════════════════════════════════════
//  RateLimiter — central thread-safe registry
// ══════════════════════════════════════════════
class RateLimiter {
    mutable std::mutex registry_mtx_;
    std::unordered_map<std::string, ClientLimiter*> limiters_;
    std::unordered_map<std::string, ClientStats*>   stats_;
    std::unordered_map<std::string, Config>         client_cfg_;

    Config cfg_;
    std::atomic<long> g_total_{0}, g_allowed_{0}, g_rejected_{0};

public:
    explicit RateLimiter(Config cfg) : cfg_(cfg) {}

    ~RateLimiter() {
        for (auto& p : limiters_) delete p.second;
        for (auto& p : stats_)    delete p.second;
    }

    // Assign a custom limit to one client
    void set_client_config(const std::string& cid, Config cc) {
        std::lock_guard<std::mutex> lk(registry_mtx_);
        client_cfg_[cid] = cc;
        if (limiters_.count(cid))
            limiters_[cid]->reconfigure(cc.max_requests, cc.window_seconds);
    }

    // Core entry point — called from every thread
    RequestResult process(const std::string& cid,
                          const std::string& algo = "fixed") {
        ClientLimiter* lim;
        ClientStats*   st;
        {
            std::lock_guard<std::mutex> lk(registry_mtx_);
            if (!limiters_.count(cid)) {
                Config cc = client_cfg_.count(cid) ? client_cfg_[cid] : cfg_;
                limiters_[cid] = new ClientLimiter(cc.max_requests,
                                                   cc.window_seconds);
                stats_[cid]    = new ClientStats();
            }
            lim = limiters_[cid];
            st  = stats_[cid];
        }
        // Lock released — algo runs in parallel for different clients

        Decision d;
        if      (algo == "sliding") d = lim->sliding.check();
        else if (algo == "token")   d = lim->token.check();
        else                        d = lim->fixed.check();

        st->total++;  g_total_++;
        if (d == Decision::ALLOWED) { st->allowed++; g_allowed_++; }
        else                        { st->rejected++; g_rejected_++; }

        return { wall_timestamp(), cid, algo, d };
    }

    // Live reconfiguration
    void update_config(Config nc) {
        std::lock_guard<std::mutex> lk(registry_mtx_);
        cfg_ = nc;
        for (auto& p : limiters_) {
            if (!client_cfg_.count(p.first))
                p.second->reconfigure(nc.max_requests, nc.window_seconds);
        }
    }

    Config get_config() const {
        std::lock_guard<std::mutex> lk(registry_mtx_);
        return cfg_;
    }

    // JSON for GET /stats
    std::string stats_json() const {
        std::lock_guard<std::mutex> lk(registry_mtx_);
        std::ostringstream o;
        o << "{\n"
          << "  \"global\": {\n"
          << "    \"total\":"    << g_total_   << ",\n"
          << "    \"allowed\":"  << g_allowed_ << ",\n"
          << "    \"rejected\":" << g_rejected_<< "\n  },\n"
          << "  \"config\": {\"max_requests\":" << cfg_.max_requests
          <<               ",\"window_seconds\":" << cfg_.window_seconds << "},\n"
          << "  \"clients\": {\n";
        bool first = true;
        for (auto& p : stats_) {
            if (!first) o << ",\n";
            first = false;
            o << "    \"" << p.first << "\":"
              << "{\"total\":"    << p.second->total
              << ",\"allowed\":"  << p.second->allowed
              << ",\"rejected\":" << p.second->rejected << "}";
        }
        o << "\n  }\n}";
        return o.str();
    }

    // Console summary
    void print_summary() const {
        std::lock_guard<std::mutex> lk(registry_mtx_);
        std::cout << "\n+------------------------------------------------+\n";
        std::cout <<   "|          RATE LIMITER — FINAL SUMMARY         |\n";
        std::cout <<   "+------------------------------------------------+\n";
        std::cout << "  Global Total   : " << g_total_   << "\n";
        std::cout << "  Global Allowed : " << g_allowed_ << "\n";
        std::cout << "  Global Rejected: " << g_rejected_<< "\n\n";
        std::cout << "  " << std::left
                  << std::setw(12) << "Client"
                  << std::setw(8)  << "Total"
                  << std::setw(10) << "Allowed"
                  << std::setw(10) << "Rejected" << "\n";
        std::cout << "  " << std::string(40, '-') << "\n";
        for (auto& p : stats_) {
            std::cout << "  " << std::setw(12) << p.first
                      << std::setw(8)  << p.second->total
                      << std::setw(10) << p.second->allowed
                      << std::setw(10) << p.second->rejected << "\n";
        }
        std::cout << "\n";
    }
};

// ══════════════════════════════════════════════
//  Multi-threaded Test Harness
//  5 threads, 30 requests each = 150 total
//  client3 gets a custom tighter limit (5 req)
// ══════════════════════════════════════════════
void run_test_harness(RateLimiter& rl) {
    std::cout << "+------------------------------------------------+\n";
    std::cout << "|  TEST HARNESS: 150 requests across 5 clients  |\n";
    std::cout << "|  (concurrent threads, mixed algorithms)        |\n";
    std::cout << "+------------------------------------------------+\n\n";

    const int N_CLIENTS = 5;
    const int REQ_EACH  = 30;
    const std::vector<std::string> algos = {"fixed", "sliding", "token"};

    std::vector<std::thread> threads;
    std::mutex print_mtx;

    // client3 gets a tighter per-client limit
    rl.set_client_config("client3", {5, 60});

    for (int c = 0; c < N_CLIENTS; ++c) {
        std::string cid = "client" + std::to_string(c);
        threads.emplace_back([&, cid, c]() {
            std::mt19937 rng(c);
            for (int i = 0; i < REQ_EACH; ++i) {
                std::string algo = algos[rng() % algos.size()];
                auto res = rl.process(cid, algo);
                {
                    std::lock_guard<std::mutex> lk(print_mtx);
                    std::cout << "  [" << res.timestamp << "]"
                              << "  client=" << std::left << std::setw(10) << res.client_id
                              << "  algo="   << std::setw(9) << res.algorithm
                              << "  ==>  "   << decision_str(res.decision) << "\n";
                }
                // Random sleep to stress-test concurrency
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(rng() % 10));
            }
        });
    }
    for (auto& t : threads) t.join();
    rl.print_summary();
}

// ══════════════════════════════════════════════
//  HTTP Server — Winsock2
// ══════════════════════════════════════════════
static std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ) {
        if (s[i] == '%' && i + 2 < s.size()) {
            char hex[3] = { s[i+1], s[i+2], 0 };
            out += (char)std::strtol(hex, nullptr, 16);
            i += 3;
        } else if (s[i] == '+') { out += ' '; ++i; }
        else                    { out += s[i++]; }
    }
    return out;
}

static std::unordered_map<std::string,std::string>
parse_query(const std::string& qs) {
    std::unordered_map<std::string,std::string> m;
    std::istringstream ss(qs);
    std::string tok;
    while (std::getline(ss, tok, '&')) {
        auto eq = tok.find('=');
        if (eq == std::string::npos) continue;
        m[url_decode(tok.substr(0,eq))] = url_decode(tok.substr(eq+1));
    }
    return m;
}

static bool json_int(const std::string& body,
                     const std::string& key, int& out) {
    auto pos = body.find("\"" + key + "\"");
    if (pos == std::string::npos) return false;
    pos = body.find(':', pos);
    if (pos == std::string::npos) return false;
    try { out = std::stoi(body.substr(pos+1)); return true; }
    catch (...) { return false; }
}

// Winsock send wrapper
static void send_response(SOCKET sock, int code,
                           const std::string& ct,
                           const std::string& body) {
    std::string reason = (code==200)?"OK":(code==400)?"Bad Request":"Not Found";
    std::ostringstream hdr;
    hdr << "HTTP/1.1 " << code << " " << reason << "\r\n"
        << "Content-Type: " << ct << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Connection: close\r\n\r\n";
    std::string full = hdr.str() + body;
    ::send(sock, full.data(), (int)full.size(), 0);
}

// Handles one accepted socket in its own thread
static void handle_client(SOCKET sock, RateLimiter& rl) {
    char buf[4096] = {};
    int  n = ::recv(sock, buf, sizeof(buf)-1, 0);
    if (n <= 0) { closesocket(sock); return; }

    std::string req(buf, n);

    // Parse request line
    auto lend = req.find("\r\n");
    if (lend == std::string::npos) { closesocket(sock); return; }
    std::istringstream ls(req.substr(0, lend));
    std::string method, path_full;
    ls >> method >> path_full;

    // Split path / query-string
    std::string path, qs;
    auto qp = path_full.find('?');
    if (qp != std::string::npos) {
        path = path_full.substr(0, qp);
        qs   = path_full.substr(qp+1);
    } else { path = path_full; }

    // Body (POST /config)
    std::string body_text;
    auto bp = req.find("\r\n\r\n");
    if (bp != std::string::npos) body_text = req.substr(bp+4);

    if (method == "POST" && path == "/request") {
        auto params  = parse_query(qs);
        auto cid_it  = params.find("client_id");
        auto algo_it = params.find("algo");
        if (cid_it == params.end()) {
            send_response(sock, 400, "text/plain", "Missing client_id");
            closesocket(sock); return;
        }
        std::string cid  = cid_it->second;
        std::string algo = (algo_it != params.end()) ? algo_it->second : "fixed";
        auto res = rl.process(cid, algo);
        std::ostringstream o;
        o << "{\n"
          << "  \"timestamp\": \"" << res.timestamp  << "\",\n"
          << "  \"client_id\": \"" << res.client_id  << "\",\n"
          << "  \"algorithm\": \"" << res.algorithm  << "\",\n"
          << "  \"result\": \""    << decision_str(res.decision) << "\"\n"
          << "}";
        send_response(sock, 200, "application/json", o.str());

    } else if (method == "GET" && path == "/stats") {
        send_response(sock, 200, "application/json", rl.stats_json());

    } else if (method == "POST" && path == "/config") {
        int mr = -1, ws = -1;
        json_int(body_text, "max_requests",   mr);
        json_int(body_text, "window_seconds", ws);
        Config nc = rl.get_config();
        if (mr > 0) nc.max_requests   = mr;
        if (ws > 0) nc.window_seconds = ws;
        rl.update_config(nc);
        std::ostringstream o;
        o << "{\"max_requests\":" << nc.max_requests
          << ",\"window_seconds\":" << nc.window_seconds << "}";
        send_response(sock, 200, "application/json", o.str());

    } else {
        send_response(sock, 404, "text/plain", "Not found");
    }
    closesocket(sock);
}

void run_http_server(RateLimiter& rl, int port) {
    // --- Winsock init ---
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n"; return;
    }

    SOCKET srv = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        std::cerr << "socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup(); return;
    }

    // Allow port reuse
    int opt = 1;
    ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR,
                 (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((u_short)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(srv, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << "\n";
        closesocket(srv); WSACleanup(); return;
    }
    ::listen(srv, SOMAXCONN);

    std::cout << "\n+--------------------------------------------------+\n";
    std::cout <<   "|   uTrade Rate Limiter  --  HTTP Server           |\n";
    std::cout <<   "+--------------------------------------------------+\n";
    std::cout <<   "|  POST /request?client_id=X[&algo=fixed|sliding   |\n";
    std::cout <<   "|                              |token]              |\n";
    std::cout <<   "|  GET  /stats                                      |\n";
    std::cout <<   "|  POST /config   {\"max_requests\":N,               |\n";
    std::cout <<   "|                  \"window_seconds\":T}             |\n";
    std::cout <<   "+--------------------------------------------------+\n";
    std::cout <<   "  Listening on http://127.0.0.1:" << port << "\n\n";

    while (true) {
        sockaddr_in cli{};
        int clilen = sizeof(cli);
        SOCKET cfd = ::accept(srv, (sockaddr*)&cli, &clilen);
        if (cfd == INVALID_SOCKET) continue;
        // Each connection handled in a detached thread
        std::thread([cfd, &rl]() { handle_client(cfd, rl); }).detach();
    }
    // (unreachable — server runs until process killed)
    closesocket(srv);
    WSACleanup();
}

// ══════════════════════════════════════════════
//  main
// ══════════════════════════════════════════════
int main(int argc, char* argv[]) {
    Config cfg;
    cfg.max_requests   = 10;
    cfg.window_seconds = 60;
    int  port        = 8080;
    bool test_mode   = false;
    bool server_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--test")   test_mode   = true;
        else if (a == "--server") server_mode = true;
        else if (a.rfind("--port=",0) == 0)
            port = std::stoi(a.substr(7));
        else if (a.rfind("--max_requests=",0) == 0)
            cfg.max_requests = std::stoi(a.substr(15));
        else if (a.rfind("--window_seconds=",0) == 0)
            cfg.window_seconds = std::stoi(a.substr(17));
    }

    // Default: run both
    if (!test_mode && !server_mode)
        test_mode = server_mode = true;

    RateLimiter rl(cfg);

    if (test_mode)   run_test_harness(rl);
    if (server_mode) run_http_server(rl, port);

    return 0;
}
