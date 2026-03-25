#include <sys/types.h>
#include <sys/stat.h>
#include <gtk/gtk.h>
#include <libssh/libssh.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <pthread.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <queue>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <functional>
#include <map>
#include <set>
#include <csignal>
#include <sys/wait.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <errno.h>

struct VPNConfig {
    std::string name;
    std::string host;
    int port = 22;
    std::string username;
    std::string password;
};

struct ExcludeRule {
    std::string value;
    bool is_domain;
};

struct AppState {
    std::atomic<bool> connected{false};
    std::atomic<bool> connecting{false};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};
    std::atomic<double> speed_up{0};
    std::atomic<double> speed_down{0};
    std::chrono::steady_clock::time_point connect_time;
    uint64_t prev_sent = 0;
    uint64_t prev_recv = 0;

    std::vector<VPNConfig> configs;
    int selected_config = -1;
    std::vector<ExcludeRule> excludes;

    pid_t proxy_pid = -1;
    int tun_fd = -1;
    ssh_session ssh = nullptr;
    ssh_channel channel = nullptr;
    std::atomic<bool> stop_threads{false};
    std::thread forward_thread;
    std::thread reverse_thread;

    std::mutex log_mutex;
    std::queue<std::string> log_queue;

    std::string config_path;
    std::string exclude_path;

    GtkWidget *window;
    GtkWidget *btn_connect;
    GtkWidget *lbl_time;
    GtkWidget *lbl_up;
    GtkWidget *lbl_down;
    GtkWidget *lbl_speed_up;
    GtkWidget *lbl_speed_down;
    GtkWidget *config_listbox;
    GtkWidget *btn_routing;

    GtkWidget *dlg_add;
    GtkWidget *add_host;
    GtkWidget *add_port;
    GtkWidget *add_user;
    GtkWidget *add_pass;
    GtkWidget *add_name;

    GtkWidget *dlg_routing;
    GtkWidget *exclude_listbox;
    GtkWidget *exclude_entry;

    std::map<int, std::string> ping_results;
    std::mutex ping_mutex;
};

static AppState app;

static std::string get_config_dir() {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    std::string dir = std::string(home) + "/.config/sshvpn";
    std::string cmd = "mkdir -p " + dir;
    system(cmd.c_str());
    return dir;
}

static void save_configs() {
    std::ofstream f(app.config_path);
    for (auto &c : app.configs) {
        f << c.name << "\t" << c.host << "\t" << c.port << "\t"
          << c.username << "\t" << c.password << "\n";
    }
}

static void load_configs() {
    app.configs.clear();
    std::ifstream f(app.config_path);
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        VPNConfig c;
        std::string port_str;
        if (std::getline(ss, c.name, '\t') &&
            std::getline(ss, c.host, '\t') &&
            std::getline(ss, port_str, '\t') &&
            std::getline(ss, c.username, '\t') &&
            std::getline(ss, c.password, '\t')) {
            c.port = std::atoi(port_str.c_str());
            if (c.port <= 0) c.port = 22;
            app.configs.push_back(c);
        }
    }
}

static void save_excludes() {
    std::ofstream f(app.exclude_path);
    for (auto &e : app.excludes) {
        f << (e.is_domain ? "domain" : "ip") << "\t" << e.value << "\n";
    }
}

static void load_excludes() {
    app.excludes.clear();
    std::ifstream f(app.exclude_path);
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string type, val;
        if (std::getline(ss, type, '\t') && std::getline(ss, val)) {
            while (!val.empty() && (val.back() == '\n' || val.back() == '\r' || val.back() == '\t'))
                val.pop_back();
            if (!val.empty())
                app.excludes.push_back({val, type == "domain"});
        }
    }
}

static std::string fmt_bytes(uint64_t b) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    if (b < 1024) ss << b << " B";
    else if (b < 1048576) ss << b / 1024.0 << " KB";
    else if (b < 1073741824ULL) ss << b / 1048576.0 << " MB";
    else ss << b / 1073741824.0 << " GB";
    return ss.str();
}

static std::string fmt_speed(double s) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    if (s < 1024) ss << s << " B/s";
    else if (s < 1048576) ss << s / 1024.0 << " KB/s";
    else ss << s / 1048576.0 << " MB/s";
    return ss.str();
}

static std::string fmt_duration(int secs) {
    int h = secs / 3600, m = (secs % 3600) / 60, s2 = secs % 60;
    std::ostringstream ss;
    ss << std::setfill('0') << std::setw(2) << h << ":"
       << std::setfill('0') << std::setw(2) << m << ":"
       << std::setfill('0') << std::setw(2) << s2;
    return ss.str();
}

static std::vector<std::string> resolve_domain(const std::string &domain) {
    std::vector<std::string> ips;
    std::set<std::string> seen;
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    auto do_resolve = [&](const std::string &name) {
        res = nullptr;
        if (getaddrinfo(name.c_str(), nullptr, &hints, &res) == 0 && res) {
            for (p = res; p; p = p->ai_next) {
                char buf[INET_ADDRSTRLEN];
                struct sockaddr_in *addr = (struct sockaddr_in *)p->ai_addr;
                inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
                std::string ip(buf);
                if (seen.find(ip) == seen.end()) {
                    seen.insert(ip);
                    ips.push_back(ip);
                }
            }
            freeaddrinfo(res);
        }
    };

    std::string d = domain;
    if (!d.empty() && d[0] == '.') d = d.substr(1);
    if (d.empty()) return ips;

    do_resolve(d);

    const char *prefixes[] = {"www.", "mail.", "api.", "cdn.", "m.", "static.",
                              "img.", "video.", "music.", "auth.", "login.",
                              "accounts.", "play.", "maps."};
    for (auto pfx : prefixes) {
        do_resolve(std::string(pfx) + d);
    }

    return ips;
}

static std::string resolve_host_to_ip(const std::string &host) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
        char buf[INET_ADDRSTRLEN];
        struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
        freeaddrinfo(res);
        return std::string(buf);
    }
    return host;
}

static std::string get_default_iface() {
    FILE *p = popen("ip route | grep '^default' | head -1 | awk '{print $5}'", "r");
    if (!p) return "";
    char buf[128]{};
    fgets(buf, sizeof(buf), p);
    pclose(p);
    std::string iface(buf);
    while (!iface.empty() && (iface.back() == '\n' || iface.back() == '\r')) iface.pop_back();
    return iface;
}

static int tcp_ping(const std::string &host, int port, int timeout_ms) {
    std::string ip = resolve_host_to_ip(host);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    auto start = std::chrono::steady_clock::now();

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret == 0) {
        close(sock);
        auto end = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(sock + 1, nullptr, &wset, nullptr, &tv);
    auto end = std::chrono::steady_clock::now();
    int ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (ret > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        close(sock);
        if (err == 0) return ms;
        return -1;
    }

    close(sock);
    return -1;
}

static void vpn_connect_thread() {
    if (app.selected_config < 0 || app.selected_config >= (int)app.configs.size()) {
        app.connecting = false;
        return;
    }

    auto &cfg = app.configs[app.selected_config];

    setenv("SSHPASS", cfg.password.c_str(), 1);

    std::string server_ip = resolve_host_to_ip(cfg.host);

    bool has_domain_excludes = false;
    for (auto &e : app.excludes) {
        if (e.is_domain) { has_domain_excludes = true; break; }
    }

    std::vector<std::string> args;
    args.push_back("sshuttle");

    if (!has_domain_excludes) {
        args.push_back("--dns");
    }

    args.push_back("-r");
    args.push_back(cfg.username + "@" + cfg.host + ":" + std::to_string(cfg.port));
    args.push_back("0.0.0.0/0");

    args.push_back("-x");
    args.push_back(server_ip + "/32");

    if (server_ip != cfg.host) {
        args.push_back("-x");
        args.push_back(cfg.host + "/32");
    }

    std::set<std::string> excluded_ips;
    excluded_ips.insert(server_ip);

    for (auto &e : app.excludes) {
        if (e.is_domain) {
            auto ips = resolve_domain(e.value);
            for (auto &ip : ips) {
                if (excluded_ips.find(ip) == excluded_ips.end()) {
                    excluded_ips.insert(ip);
                    args.push_back("-x");
                    args.push_back(ip + "/32");
                }
            }
        } else {
            if (!e.value.empty()) {
                args.push_back("-x");
                if (e.value.find('/') == std::string::npos)
                    args.push_back(e.value + "/32");
                else
                    args.push_back(e.value);
            }
        }
    }

    args.push_back("--ssh-cmd");
    args.push_back("sshpass -e ssh -o StrictHostKeyChecking=no -o BatchMode=no");

    std::vector<char*> argv;
    for (auto &a : args) argv.push_back((char*)a.c_str());
    argv.push_back(nullptr);

    app.proxy_pid = fork();
    if (app.proxy_pid == 0) {
        execvp("sshuttle", argv.data());
        _exit(1);
    }

    if (app.proxy_pid < 0) {
        app.connecting = false;
        return;
    }

    sleep(5);

    int status;
    pid_t result = waitpid(app.proxy_pid, &status, WNOHANG);
    if (result == 0) {
        app.connected = true;
        app.connecting = false;
        app.connect_time = std::chrono::steady_clock::now();
        app.bytes_sent = 0;
        app.bytes_recv = 0;
        app.prev_sent = 0;
        app.prev_recv = 0;
    } else {
        app.proxy_pid = -1;
        app.connecting = false;
    }
}

static void vpn_disconnect() {
    if (app.proxy_pid > 0) {
        kill(app.proxy_pid, SIGTERM);
        int wait_count = 0;
        while (wait_count < 20) {
            int status;
            pid_t r = waitpid(app.proxy_pid, &status, WNOHANG);
            if (r > 0) break;
            usleep(250000);
            wait_count++;
        }
        int status;
        if (waitpid(app.proxy_pid, &status, WNOHANG) == 0) {
            kill(app.proxy_pid, SIGKILL);
            waitpid(app.proxy_pid, nullptr, 0);
        }
        app.proxy_pid = -1;
    }
    app.connected = false;
    app.connecting = false;
}

static void read_net_stats() {
    static std::string iface_cache;
    if (iface_cache.empty()) {
        iface_cache = get_default_iface();
        if (iface_cache.empty()) iface_cache = "eth0";
    }

    std::string path_rx = "/sys/class/net/" + iface_cache + "/statistics/rx_bytes";
    std::string path_tx = "/sys/class/net/" + iface_cache + "/statistics/tx_bytes";

    auto read_val = [](const std::string &path) -> uint64_t {
        std::ifstream f(path);
        uint64_t v = 0;
        f >> v;
        return v;
    };

    static uint64_t base_rx = 0, base_tx = 0;
    static bool first = true;

    uint64_t rx = read_val(path_rx);
    uint64_t tx = read_val(path_tx);

    if (first) {
        base_rx = rx;
        base_tx = tx;
        first = false;
    }

    app.bytes_recv = rx - base_rx;
    app.bytes_sent = tx - base_tx;
}

static void refresh_config_list();

static gboolean update_ping_ui(gpointer) {
    refresh_config_list();
    return FALSE;
}

static gboolean update_ui(gpointer) {
    if (app.connected) {
        auto now = std::chrono::steady_clock::now();
        int secs = std::chrono::duration_cast<std::chrono::seconds>(now - app.connect_time).count();
        gtk_label_set_text(GTK_LABEL(app.lbl_time), fmt_duration(secs).c_str());

        read_net_stats();

        uint64_t sent = app.bytes_sent.load();
        uint64_t recv = app.bytes_recv.load();

        app.speed_up = (double)(sent - app.prev_sent);
        app.speed_down = (double)(recv - app.prev_recv);
        app.prev_sent = sent;
        app.prev_recv = recv;

        gtk_label_set_text(GTK_LABEL(app.lbl_up), ("↑ " + fmt_bytes(sent)).c_str());
        gtk_label_set_text(GTK_LABEL(app.lbl_down), ("↓ " + fmt_bytes(recv)).c_str());
        gtk_label_set_text(GTK_LABEL(app.lbl_speed_up), fmt_speed(app.speed_up).c_str());
        gtk_label_set_text(GTK_LABEL(app.lbl_speed_down), fmt_speed(app.speed_down).c_str());

        gtk_button_set_label(GTK_BUTTON(app.btn_connect), "Disconnect");
    } else if (app.connecting) {
        gtk_label_set_text(GTK_LABEL(app.lbl_time), "connecting...");
        gtk_button_set_label(GTK_BUTTON(app.btn_connect), "Connecting...");
    } else {
        gtk_label_set_text(GTK_LABEL(app.lbl_time), "00:00:00");
        gtk_label_set_text(GTK_LABEL(app.lbl_up), "↑ 0 B");
        gtk_label_set_text(GTK_LABEL(app.lbl_down), "↓ 0 B");
        gtk_label_set_text(GTK_LABEL(app.lbl_speed_up), "0 B/s");
        gtk_label_set_text(GTK_LABEL(app.lbl_speed_down), "0 B/s");
        gtk_button_set_label(GTK_BUTTON(app.btn_connect), "Connect");
    }

    int status;
    if (app.connected && app.proxy_pid > 0) {
        pid_t r = waitpid(app.proxy_pid, &status, WNOHANG);
        if (r > 0) {
            app.connected = false;
            app.proxy_pid = -1;
        }
    }

    return TRUE;
}

static void show_edit_dialog(int idx);

static void refresh_config_list() {
    int sel = app.selected_config;

    GList *children = gtk_container_get_children(GTK_CONTAINER(app.config_listbox));
    for (GList *l = children; l; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);

    for (int i = 0; i < (int)app.configs.size(); i++) {
        auto &c = app.configs[i];

        std::string ping_str;
        {
            std::lock_guard<std::mutex> lock(app.ping_mutex);
            auto it = app.ping_results.find(i);
            if (it != app.ping_results.end())
                ping_str = it->second;
        }

        std::string label = c.name + "  (" + c.username + "@" + c.host + ":" + std::to_string(c.port) + ")";
        if (!ping_str.empty())
            label += "  " + ping_str;

        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_container_set_border_width(GTK_CONTAINER(hbox), 4);

        GtkWidget *lbl = gtk_label_new(label.c_str());
        gtk_label_set_xalign(GTK_LABEL(lbl), 0);
        gtk_widget_set_hexpand(lbl, TRUE);
        gtk_box_pack_start(GTK_BOX(hbox), lbl, TRUE, TRUE, 0);

        GtkWidget *btn_del = gtk_button_new_with_label("✕");
        gtk_widget_set_size_request(btn_del, 30, -1);
        g_object_set_data(G_OBJECT(btn_del), "idx", GINT_TO_POINTER(i));
        g_signal_connect(btn_del, "clicked", G_CALLBACK(+[](GtkWidget *w, gpointer) {
            int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "idx"));
            if (idx >= 0 && idx < (int)app.configs.size()) {
                app.configs.erase(app.configs.begin() + idx);
                {
                    std::lock_guard<std::mutex> lock(app.ping_mutex);
                    app.ping_results.erase(idx);
                }
                if (app.selected_config == idx) app.selected_config = -1;
                else if (app.selected_config > idx) app.selected_config--;
                save_configs();
                refresh_config_list();
            }
        }), nullptr);

        GtkWidget *btn_edit = gtk_button_new_with_label("✎");
        gtk_widget_set_size_request(btn_edit, 30, -1);
        g_object_set_data(G_OBJECT(btn_edit), "idx", GINT_TO_POINTER(i));
        g_signal_connect(btn_edit, "clicked", G_CALLBACK(+[](GtkWidget *w, gpointer) {
            int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "idx"));
            show_edit_dialog(idx);
        }), nullptr);

        gtk_box_pack_end(GTK_BOX(hbox), btn_del, FALSE, FALSE, 0);
        gtk_box_pack_end(GTK_BOX(hbox), btn_edit, FALSE, FALSE, 0);

        gtk_container_add(GTK_CONTAINER(row), hbox);
        gtk_list_box_insert(GTK_LIST_BOX(app.config_listbox), row, -1);
    }

    gtk_widget_show_all(app.config_listbox);

    if (sel >= 0 && sel < (int)app.configs.size()) {
        GtkListBoxRow *row = gtk_list_box_get_row_at_index(
            GTK_LIST_BOX(app.config_listbox), sel);
        if (row) gtk_list_box_select_row(GTK_LIST_BOX(app.config_listbox), row);
    }
}

static void show_edit_dialog(int idx) {
    if (idx < 0 || idx >= (int)app.configs.size()) return;
    auto &c = app.configs[idx];

    GtkWidget *dlg = gtk_dialog_new_with_buttons("Edit VPN", GTK_WINDOW(app.window),
        (GtkDialogFlags)(GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT),
        nullptr);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 16);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);

    auto make_field = [&](int row, const char *label_text, const std::string &val) -> GtkWidget* {
        GtkWidget *lbl = gtk_label_new(label_text);
        gtk_label_set_xalign(GTK_LABEL(lbl), 1);
        gtk_grid_attach(GTK_GRID(grid), lbl, 0, row, 1, 1);
        GtkWidget *entry = gtk_entry_new();
        gtk_widget_set_hexpand(entry, TRUE);
        gtk_entry_set_width_chars(GTK_ENTRY(entry), 30);
        gtk_entry_set_text(GTK_ENTRY(entry), val.c_str());
        gtk_grid_attach(GTK_GRID(grid), entry, 1, row, 1, 1);
        return entry;
    };

    GtkWidget *e_name = make_field(0, "Name:", c.name);
    GtkWidget *e_host = make_field(1, "IP Address:", c.host);
    GtkWidget *e_port = make_field(2, "Port:", std::to_string(c.port));
    GtkWidget *e_user = make_field(3, "Username:", c.username);
    GtkWidget *e_pass = make_field(4, "Password:", c.password);
    gtk_entry_set_visibility(GTK_ENTRY(e_pass), FALSE);

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(btn_box, GTK_ALIGN_END);
    gtk_widget_set_margin_top(btn_box, 12);
    gtk_grid_attach(GTK_GRID(grid), btn_box, 0, 5, 2, 1);

    GtkWidget *btn_cancel = gtk_button_new_with_label("Cancel");
    gtk_box_pack_start(GTK_BOX(btn_box), btn_cancel, FALSE, FALSE, 0);
    g_signal_connect(btn_cancel, "clicked", G_CALLBACK(+[](GtkWidget *w, gpointer) {
        gtk_widget_destroy(gtk_widget_get_toplevel(w));
    }), nullptr);

    GtkWidget *btn_save = gtk_button_new_with_label("Save");
    GtkStyleContext *ctx = gtk_widget_get_style_context(btn_save);
    gtk_style_context_add_class(ctx, "suggested-action");
    gtk_box_pack_start(GTK_BOX(btn_box), btn_save, FALSE, FALSE, 0);

    struct EditData {
        int idx;
        GtkWidget *dlg;
        GtkWidget *e_name, *e_host, *e_port, *e_user, *e_pass;
    };
    auto *ed = new EditData{idx, dlg, e_name, e_host, e_port, e_user, e_pass};

    g_signal_connect(btn_save, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer data) {
        auto *ed = static_cast<EditData*>(data);
        if (ed->idx < 0 || ed->idx >= (int)app.configs.size()) { delete ed; return; }
        auto &c = app.configs[ed->idx];
        c.name     = gtk_entry_get_text(GTK_ENTRY(ed->e_name));
        c.host     = gtk_entry_get_text(GTK_ENTRY(ed->e_host));
        c.port     = atoi(gtk_entry_get_text(GTK_ENTRY(ed->e_port)));
        c.username = gtk_entry_get_text(GTK_ENTRY(ed->e_user));
        c.password = gtk_entry_get_text(GTK_ENTRY(ed->e_pass));
        if (c.port <= 0) c.port = 22;
        if (c.name.empty()) c.name = c.host;
        save_configs();
        refresh_config_list();
        gtk_widget_destroy(ed->dlg);
        delete ed;
    }), ed);

    g_signal_connect(dlg, "destroy", G_CALLBACK(+[](GtkWidget *, gpointer) {
    }), nullptr);

    gtk_widget_show_all(dlg);
}

static void refresh_exclude_list() {
    if (!app.exclude_listbox) return;

    GList *children = gtk_container_get_children(GTK_CONTAINER(app.exclude_listbox));
    for (GList *l = children; l; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);

    for (int i = 0; i < (int)app.excludes.size(); i++) {
        auto &e = app.excludes[i];

        std::string display;
        if (e.is_domain) {
            auto ips = resolve_domain(e.value);
            display = "🌐 " + e.value + "  [" + std::to_string(ips.size()) + " IPs]";
        } else {
            display = "📍 " + e.value;
        }

        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);

        GtkWidget *lbl = gtk_label_new(display.c_str());
        gtk_label_set_xalign(GTK_LABEL(lbl), 0);
        gtk_widget_set_hexpand(lbl, TRUE);
        gtk_box_pack_start(GTK_BOX(hbox), lbl, TRUE, TRUE, 0);

        GtkWidget *btn_del = gtk_button_new_with_label("✕");
        gtk_widget_set_size_request(btn_del, 30, -1);
        g_object_set_data(G_OBJECT(btn_del), "idx", GINT_TO_POINTER(i));
        g_signal_connect(btn_del, "clicked", G_CALLBACK(+[](GtkWidget *w, gpointer) {
            int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "idx"));
            if (idx >= 0 && idx < (int)app.excludes.size()) {
                app.excludes.erase(app.excludes.begin() + idx);
                save_excludes();
                refresh_exclude_list();
            }
        }), nullptr);
        gtk_box_pack_end(GTK_BOX(hbox), btn_del, FALSE, FALSE, 0);

        gtk_container_add(GTK_CONTAINER(row), hbox);
        gtk_list_box_insert(GTK_LIST_BOX(app.exclude_listbox), row, -1);
    }

    gtk_widget_show_all(app.exclude_listbox);
}

static void on_connect_clicked(GtkWidget *, gpointer) {
    if (app.connecting) return;

    if (app.connected) {
        std::thread([]() { vpn_disconnect(); }).detach();
        return;
    }

    if (app.selected_config < 0) {
        GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(app.window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
            "Select a VPN configuration first");
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return;
    }

    app.connecting = true;
    std::thread(vpn_connect_thread).detach();
}

static void on_config_selected(GtkListBox *, GtkListBoxRow *row, gpointer) {
    if (!row) {
        app.selected_config = -1;
        return;
    }
    app.selected_config = gtk_list_box_row_get_index(row);
}

static void show_add_dialog() {
    app.dlg_add = gtk_dialog_new_with_buttons("Add VPN", GTK_WINDOW(app.window),
        (GtkDialogFlags)(GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT),
        nullptr);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(app.dlg_add));
    gtk_container_set_border_width(GTK_CONTAINER(content), 16);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);

    auto add_field = [&](int row, const char *label) -> GtkWidget* {
        GtkWidget *lbl = gtk_label_new(label);
        gtk_label_set_xalign(GTK_LABEL(lbl), 1);
        gtk_grid_attach(GTK_GRID(grid), lbl, 0, row, 1, 1);
        GtkWidget *entry = gtk_entry_new();
        gtk_widget_set_hexpand(entry, TRUE);
        gtk_entry_set_width_chars(GTK_ENTRY(entry), 30);
        gtk_grid_attach(GTK_GRID(grid), entry, 1, row, 1, 1);
        return entry;
    };

    app.add_name = add_field(0, "Name:");
    app.add_host = add_field(1, "IP Address:");
    app.add_port = add_field(2, "Port:");
    gtk_entry_set_text(GTK_ENTRY(app.add_port), "22");
    app.add_user = add_field(3, "Username:");
    app.add_pass = add_field(4, "Password:");
    gtk_entry_set_visibility(GTK_ENTRY(app.add_pass), FALSE);

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(btn_box, GTK_ALIGN_END);
    gtk_widget_set_margin_top(btn_box, 12);
    gtk_grid_attach(GTK_GRID(grid), btn_box, 0, 5, 2, 1);

    GtkWidget *btn_cancel = gtk_button_new_with_label("Cancel");
    gtk_box_pack_start(GTK_BOX(btn_box), btn_cancel, FALSE, FALSE, 0);
    g_signal_connect(btn_cancel, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        gtk_widget_destroy(app.dlg_add);
    }), nullptr);

    GtkWidget *btn_save = gtk_button_new_with_label("Save");
    GtkStyleContext *ctx = gtk_widget_get_style_context(btn_save);
    gtk_style_context_add_class(ctx, "suggested-action");
    gtk_box_pack_start(GTK_BOX(btn_box), btn_save, FALSE, FALSE, 0);
    g_signal_connect(btn_save, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        VPNConfig c;
        c.name     = gtk_entry_get_text(GTK_ENTRY(app.add_name));
        c.host     = gtk_entry_get_text(GTK_ENTRY(app.add_host));
        c.port     = atoi(gtk_entry_get_text(GTK_ENTRY(app.add_port)));
        c.username = gtk_entry_get_text(GTK_ENTRY(app.add_user));
        c.password = gtk_entry_get_text(GTK_ENTRY(app.add_pass));

        if (c.host.empty() || c.username.empty()) {
            GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(app.dlg_add),
                GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
                "IP Address and Username are required");
            gtk_dialog_run(GTK_DIALOG(dlg));
            gtk_widget_destroy(dlg);
            return;
        }

        if (c.port <= 0) c.port = 22;
        if (c.name.empty()) c.name = c.host;

        app.configs.push_back(c);
        save_configs();
        refresh_config_list();
        gtk_widget_destroy(app.dlg_add);
    }), nullptr);

    gtk_widget_show_all(app.dlg_add);
}

static std::string clean_input_domain(const std::string &raw) {
    std::string s = raw;
    while (!s.empty() && s[0] == ' ') s.erase(0, 1);
    while (!s.empty() && s.back() == ' ') s.pop_back();

    auto pos = s.find("://");
    if (pos != std::string::npos) s = s.substr(pos + 3);

    bool looks_like_ip = true;
    for (char ch : s) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '-') {
            looks_like_ip = false;
            break;
        }
    }

    if (!looks_like_ip) {
        pos = s.find('/');
        if (pos != std::string::npos) s = s.substr(0, pos);
        pos = s.find(':');
        if (pos != std::string::npos) s = s.substr(0, pos);
    }

    while (!s.empty() && s.back() == '.') s.pop_back();

    return s;
}

static bool is_ip_value(const std::string &val) {
    for (char ch : val) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '-') {
            return false;
        }
    }
    return true;
}

static void add_exclude_values(const std::string &text) {
    std::istringstream ss(text);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::string cleaned = clean_input_domain(item);
        if (cleaned.empty()) continue;

        bool exists = false;
        for (auto &e : app.excludes) {
            if (e.value == cleaned) { exists = true; break; }
        }
        if (exists) continue;

        bool ip = is_ip_value(cleaned);
        app.excludes.push_back({cleaned, !ip});
    }
    save_excludes();
    refresh_exclude_list();
}

static void ping_all_configs() {
    std::thread([]() {
        for (int i = 0; i < (int)app.configs.size(); i++) {
            {
                std::lock_guard<std::mutex> lock(app.ping_mutex);
                app.ping_results[i] = "⏳";
            }
            g_idle_add(update_ping_ui, nullptr);

            int ms = tcp_ping(app.configs[i].host, app.configs[i].port, 5000);

            {
                std::lock_guard<std::mutex> lock(app.ping_mutex);
                if (ms >= 0) {
                    std::string color;
                    if (ms < 100) color = "🟢";
                    else if (ms < 300) color = "🟡";
                    else color = "🔴";
                    app.ping_results[i] = color + " " + std::to_string(ms) + " ms";
                } else {
                    app.ping_results[i] = "🔴 timeout";
                }
            }
            g_idle_add(update_ping_ui, nullptr);
        }
    }).detach();
}

static void show_routing_dialog() {
    app.dlg_routing = gtk_dialog_new_with_buttons("Routing Exclusions",
        GTK_WINDOW(app.window),
        (GtkDialogFlags)(GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT),
        nullptr);
    gtk_window_set_default_size(GTK_WINDOW(app.dlg_routing), 500, 400);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(app.dlg_routing));
    gtk_container_set_border_width(GTK_CONTAINER(content), 12);

    GtkWidget *lbl_info = gtk_label_new(
        "Excluded domains/IPs bypass VPN.\n"
        "Domains are resolved to IPs at connect time.\n"
        "When domain exclusions are active, DNS goes directly.");
    gtk_label_set_xalign(GTK_LABEL(lbl_info), 0);
    gtk_label_set_line_wrap(GTK_LABEL(lbl_info), TRUE);
    gtk_box_pack_start(GTK_BOX(content), lbl_info, FALSE, FALSE, 4);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(content), sep, FALSE, FALSE, 4);

    GtkWidget *add_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_box_pack_start(GTK_BOX(content), add_box, FALSE, FALSE, 4);

    app.exclude_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.exclude_entry),
        "example.com, 1.2.3.4, 10.0.0.0/24 (comma-separated)");
    gtk_widget_set_hexpand(app.exclude_entry, TRUE);
    gtk_box_pack_start(GTK_BOX(add_box), app.exclude_entry, TRUE, TRUE, 0);

    GtkWidget *btn_add_exc = gtk_button_new_with_label("Add");
    gtk_box_pack_start(GTK_BOX(add_box), btn_add_exc, FALSE, FALSE, 0);
    g_signal_connect(btn_add_exc, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        const char *val = gtk_entry_get_text(GTK_ENTRY(app.exclude_entry));
        if (!val || strlen(val) == 0) return;
        add_exclude_values(std::string(val));
        gtk_entry_set_text(GTK_ENTRY(app.exclude_entry), "");
    }), nullptr);

    g_signal_connect(app.exclude_entry, "activate", G_CALLBACK(+[](GtkWidget *, gpointer) {
        const char *val = gtk_entry_get_text(GTK_ENTRY(app.exclude_entry));
        if (!val || strlen(val) == 0) return;
        add_exclude_values(std::string(val));
        gtk_entry_set_text(GTK_ENTRY(app.exclude_entry), "");
    }), nullptr);

    GtkWidget *scroll = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 4);

    app.exclude_listbox = gtk_list_box_new();
    gtk_container_add(GTK_CONTAINER(scroll), app.exclude_listbox);

    refresh_exclude_list();

    GtkWidget *btn_close = gtk_button_new_with_label("Close");
    gtk_widget_set_halign(btn_close, GTK_ALIGN_END);
    gtk_box_pack_end(GTK_BOX(content), btn_close, FALSE, FALSE, 4);
    g_signal_connect(btn_close, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        gtk_widget_destroy(app.dlg_routing);
    }), nullptr);

    gtk_widget_show_all(app.dlg_routing);
}

static void activate(GtkApplication *gtkapp, gpointer) {
    std::string cfg_dir = get_config_dir();
    app.config_path  = cfg_dir + "/configs.txt";
    app.exclude_path = cfg_dir + "/excludes.txt";
    load_configs();
    load_excludes();

    app.window = gtk_application_window_new(gtkapp);
    gtk_window_set_title(GTK_WINDOW(app.window), "SSH VPN");
    gtk_window_set_default_size(GTK_WINDOW(app.window), 420, 580);
    gtk_window_set_resizable(GTK_WINDOW(app.window), TRUE);

    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css,
        "window { background-color: #2d2d2d; }"
        "label { color: #e0e0e0; }"
        ".time-label { font-size: 24px; font-weight: bold; color: #ffffff; font-family: monospace; }"
        ".stats-label { font-size: 13px; color: #b0b0b0; font-family: monospace; }"
        ".speed-label { font-size: 11px; color: #808080; font-family: monospace; }"
        ".connect-btn { font-size: 14px; font-weight: bold; padding: 8px 32px; }"
        ".section-label { font-size: 12px; color: #909090; font-weight: bold; }"
        "button { background: #404040; color: #e0e0e0; border: 1px solid #555; border-radius: 4px; }"
        "button:hover { background: #505050; }"
        "button.suggested-action { background: #2196F3; color: white; }"
        "button.destructive-action { background: #f44336; color: white; }"
        "list { background: #363636; }"
        "list row { background: #363636; color: #e0e0e0; }"
        "list row:selected { background: #1565C0; }"
        "entry { background: #404040; color: #e0e0e0; border: 1px solid #555; }"
        "scrolledwindow { background: #363636; }"
        , -1, nullptr);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(main_box), 16);
    gtk_container_add(GTK_CONTAINER(app.window), main_box);

    app.lbl_time = gtk_label_new("00:00:00");
    GtkStyleContext *ctx = gtk_widget_get_style_context(app.lbl_time);
    gtk_style_context_add_class(ctx, "time-label");
    gtk_widget_set_halign(app.lbl_time, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(main_box), app.lbl_time, FALSE, FALSE, 2);

    app.btn_connect = gtk_button_new_with_label("Connect");
    ctx = gtk_widget_get_style_context(app.btn_connect);
    gtk_style_context_add_class(ctx, "connect-btn");
    gtk_style_context_add_class(ctx, "suggested-action");
    gtk_widget_set_halign(app.btn_connect, GTK_ALIGN_CENTER);
    g_signal_connect(app.btn_connect, "clicked", G_CALLBACK(on_connect_clicked), nullptr);
    gtk_box_pack_start(GTK_BOX(main_box), app.btn_connect, FALSE, FALSE, 8);

    GtkWidget *stats_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(stats_grid), 2);
    gtk_grid_set_column_spacing(GTK_GRID(stats_grid), 16);
    gtk_widget_set_halign(stats_grid, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(main_box), stats_grid, FALSE, FALSE, 4);

    app.lbl_up = gtk_label_new("↑ 0 B");
    ctx = gtk_widget_get_style_context(app.lbl_up);
    gtk_style_context_add_class(ctx, "stats-label");
    gtk_grid_attach(GTK_GRID(stats_grid), app.lbl_up, 0, 0, 1, 1);

    app.lbl_speed_up = gtk_label_new("0 B/s");
    ctx = gtk_widget_get_style_context(app.lbl_speed_up);
    gtk_style_context_add_class(ctx, "speed-label");
    gtk_grid_attach(GTK_GRID(stats_grid), app.lbl_speed_up, 1, 0, 1, 1);

    app.lbl_down = gtk_label_new("↓ 0 B");
    ctx = gtk_widget_get_style_context(app.lbl_down);
    gtk_style_context_add_class(ctx, "stats-label");
    gtk_grid_attach(GTK_GRID(stats_grid), app.lbl_down, 0, 1, 1, 1);

    app.lbl_speed_down = gtk_label_new("0 B/s");
    ctx = gtk_widget_get_style_context(app.lbl_speed_down);
    gtk_style_context_add_class(ctx, "speed-label");
    gtk_grid_attach(GTK_GRID(stats_grid), app.lbl_speed_down, 1, 1, 1, 1);

    GtkWidget *sep1 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_box), sep1, FALSE, FALSE, 8);

    GtkWidget *mid_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(mid_box, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(main_box), mid_box, FALSE, FALSE, 4);

    app.btn_routing = gtk_button_new_with_label("⚙  Routing Exclusions");
    g_signal_connect(app.btn_routing, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        show_routing_dialog();
    }), nullptr);
    gtk_box_pack_start(GTK_BOX(mid_box), app.btn_routing, FALSE, FALSE, 0);

    GtkWidget *btn_ping = gtk_button_new_with_label("Ping All");
    g_signal_connect(btn_ping, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        if (app.configs.empty()) return;
        ping_all_configs();
    }), nullptr);
    gtk_box_pack_start(GTK_BOX(mid_box), btn_ping, FALSE, FALSE, 0);

    GtkWidget *sep2 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_box), sep2, FALSE, FALSE, 8);

    GtkWidget *lbl_configs = gtk_label_new("CONFIGURATIONS");
    ctx = gtk_widget_get_style_context(lbl_configs);
    gtk_style_context_add_class(ctx, "section-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_configs), 0);
    gtk_box_pack_start(GTK_BOX(main_box), lbl_configs, FALSE, FALSE, 2);

    GtkWidget *scroll = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(main_box), scroll, TRUE, TRUE, 4);

    app.config_listbox = gtk_list_box_new();
    g_signal_connect(app.config_listbox, "row-selected", G_CALLBACK(on_config_selected), nullptr);
    gtk_container_add(GTK_CONTAINER(scroll), app.config_listbox);

    refresh_config_list();

    GtkWidget *btn_add = gtk_button_new_with_label("＋  Add VPN");
    ctx = gtk_widget_get_style_context(btn_add);
    gtk_style_context_add_class(ctx, "suggested-action");
    gtk_widget_set_halign(btn_add, GTK_ALIGN_CENTER);
    g_signal_connect(btn_add, "clicked", G_CALLBACK(+[](GtkWidget *, gpointer) {
        show_add_dialog();
    }), nullptr);
    gtk_box_pack_start(GTK_BOX(main_box), btn_add, FALSE, FALSE, 8);

    g_timeout_add(1000, update_ui, nullptr);

    g_signal_connect(app.window, "destroy", G_CALLBACK(+[](GtkWidget *, gpointer) {
        vpn_disconnect();
    }), nullptr);

    gtk_widget_show_all(app.window);
}

int main(int argc, char *argv[]) {
    GtkApplication *gtkapp = gtk_application_new("com.minedg.sshvpn", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gtkapp, "activate", G_CALLBACK(activate), nullptr);
    int status = g_application_run(G_APPLICATION(gtkapp), argc, argv);
    g_object_unref(gtkapp);
    return status;
}
