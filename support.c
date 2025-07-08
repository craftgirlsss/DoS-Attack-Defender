/*
 * DoS Detection and Mitigation Daemon
 * Supports TCP (port 80), UDP, and ICMP DoS detection
 * Logs attacks to SQLite and blocks malicious IPs using iptables
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sqlite3.h>
#include <time.h>
#include <sys/types.h> // Added for pid_t
#include <sys/wait.h> // Added for waitpid
#include <signal.h> // Added for signal handling

// ==============================================================================
// KONFIGURASI PENTING - SESUAIKAN DENGAN KEBUTUHAN ANDA!
// ==============================================================================

// THRESHOLD: Jumlah paket maksimum dari satu IP dalam TIME_WINDOW sebelum diblokir.
// Contoh: 50 paket dalam 5 detik
#define THRESHOLD 50

// TIME_WINDOW: Jendela waktu (dalam detik) untuk menghitung paket.
// Contoh: Dalam 5 detik, jika ada lebih dari THRESHOLD paket, blokir.
#define TIME_WINDOW 3 // seconds

// INTERFACE: Interface jaringan yang akan dimonitor.
// Pastikan ini sesuai dengan interface yang terhubung ke internet/jaringan Anda.
// Contoh: "eth0", "ens33", "enp0s3", "wlan0".
// Untuk menemukan interface yang benar, gunakan perintah 'ip a' atau 'ifconfig'.
#define INTERFACE "eth0" // network interface

// DB_PATH: Lokasi file database SQLite.
#define DB_PATH "/var/log/dos_attacks.db"

// ==============================================================================

// IP tracking structure
typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t timestamps[THRESHOLD]; // Array untuk menyimpan timestamp paket
    int count;                   // Jumlah paket dalam jendela waktu
    int blocked;                 // Status apakah IP sudah diblokir
    time_t last_activity;        // Waktu aktivitas terakhir untuk cleanup
} IPLog;

#define MAX_IPS 1024 // Maksimum IP yang bisa dilacak secara bersamaan
IPLog ip_logs[MAX_IPS];
int ip_count = 0; // Jumlah IP yang sedang dilacak
sqlite3 *db;      // Pointer ke database SQLite

// Fungsi untuk membuat tabel di database jika belum ada
void create_db_table() {
    char *err_msg = 0;
    const char *sql_create = "CREATE TABLE IF NOT EXISTS attacks ("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                             "ip TEXT NOT NULL,"
                             "protocol TEXT NOT NULL,"
                             "timestamp INTEGER NOT NULL);"; // Ubah TEXT ke INTEGER untuk timestamp

    int rc = sqlite3_exec(db, sql_create, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating table: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

// Fungsi untuk mencatat serangan ke SQLite
void log_to_sqlite(const char *ip, const char *protocol, time_t block_time) {
    char *err_msg = 0;
    char sql[256];
    snprintf(sql, sizeof(sql),
             "INSERT INTO attacks (ip, protocol, timestamp) VALUES ('%s', '%s', %ld);",
             ip, protocol, block_time); // Menggunakan %ld untuk time_t

    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error logging attack: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

// Fungsi untuk memblokir IP menggunakan iptables
void block_ip(const char *ip) {
    char cmd[128];
    // Gunakan -I (Insert) agar aturan ditambahkan di awal rantai INPUT
    // Ini memastikan aturan DROP segera diterapkan sebelum aturan lain.
    snprintf(cmd, sizeof(cmd), "iptables -I INPUT -s %s -j DROP", ip);
    printf("Blocking IP: %s using command: %s\n", ip, cmd); // Untuk debugging
    system(cmd); // Eksekusi perintah iptables
    // Menambahkan log ke syslog juga bisa menjadi ide bagus
    // system("logger -p auth.notice 'DoS Detection: Blocked IP %s'", ip);
}

// Fungsi untuk mencari atau membuat entri log IP
IPLog* find_or_create_log(const char *ip) {
    // Cari IP yang sudah ada
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_logs[i].ip, ip) == 0) {
            ip_logs[i].last_activity = time(NULL); // Update waktu aktivitas terakhir
            return &ip_logs[i];
        }
    }

    // Jika IP belum ada, cari slot kosong atau slot terlama untuk ditimpa
    if (ip_count < MAX_IPS) {
        // Jika masih ada slot kosong, gunakan
        strncpy(ip_logs[ip_count].ip, ip, INET_ADDRSTRLEN - 1); // -1 untuk null terminator
        ip_logs[ip_count].ip[INET_ADDRSTRLEN - 1] = '\0'; // Pastikan null terminated
        ip_logs[ip_count].count = 0;
        ip_logs[ip_count].blocked = 0;
        ip_logs[ip_count].last_activity = time(NULL);
        return &ip_logs[ip_count++];
    } else {
        // Jika array penuh, cari IP yang paling tidak aktif untuk diganti (simple eviction)
        int oldest_index = -1;
        time_t oldest_time = time(NULL);

        for (int i = 0; i < MAX_IPS; i++) {
            // Jangan ganti IP yang sedang diblokir atau yang baru aktif
            if (!ip_logs[i].blocked && ip_logs[i].last_activity < oldest_time) {
                oldest_time = ip_logs[i].last_activity;
                oldest_index = i;
            }
        }

        if (oldest_index != -1) {
            // Reset dan gunakan kembali slot yang paling tidak aktif
            printf("Evicting IP %s to make space for new IP.\n", ip_logs[oldest_index].ip);
            strncpy(ip_logs[oldest_index].ip, ip, INET_ADDRSTRLEN - 1);
            ip_logs[oldest_index].ip[INET_ADDRSTRLEN - 1] = '\0';
            ip_logs[oldest_index].count = 0;
            ip_logs[oldest_index].blocked = 0;
            ip_logs[oldest_index].last_activity = time(NULL);
            return &ip_logs[oldest_index];
        }
        // Jika tidak ada slot yang bisa diganti (misal semua diblokir), return NULL
        fprintf(stderr, "IPLog array full and no inactive IPs to evict. Cannot track new IP: %s\n", ip);
        return NULL;
    }
}

// Fungsi untuk menganalisis paket
void analyze_packet(const struct ip *ip_header) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    const char *protocol_name = NULL;
    int suspicious = 0;

    // Periksa jenis protokol dan port/tipe yang relevan
    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp = (struct tcphdr *)((u_char*)ip_header + (ip_header->ip_hl * 4));
        // Bisa juga memonitor SYN_FLOOD dengan memeriksa flag SYN
        // if (tcp->th_flags & TH_SYN && !(tcp->th_flags & TH_ACK)) {
        //     protocol_name = "TCP_SYN";
        //     suspicious = 1;
        // }
        // Untuk DoS attack umum, port 80 (HTTP) sering jadi target
        if (ntohs(tcp->th_dport) == 80) { // Monitor trafik ke port 80 (HTTP)
            protocol_name = "TCP_HTTP";
            suspicious = 1;
        }
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // UDP flood sering menargetkan port tertentu, tapi bisa juga port acak
        protocol_name = "UDP";
        suspicious = 1; // Semua UDP dianggap suspicious untuk deteksi flood
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        // ICMP flood (ping flood)
        protocol_name = "ICMP";
        suspicious = 1;
    }

    if (!suspicious || !protocol_name) {
        return; // Bukan jenis paket yang kita pantau
    }

    IPLog *log = find_or_create_log(src_ip);
    if (!log || log->blocked) {
        return; // IP tidak bisa dilacak atau sudah diblokir
    }

    time_t now = time(NULL);

    // Filter timestamp yang sudah kadaluarsa
    int new_count = 0;
    for (int i = 0; i < log->count; i++) {
        if (now - log->timestamps[i] < TIME_WINDOW) {
            log->timestamps[new_count++] = log->timestamps[i];
        }
    }

    // Tambahkan timestamp paket saat ini
    if (new_count < THRESHOLD) { // Pastikan tidak melebihi kapasitas array timestamps
        log->timestamps[new_count++] = now;
    } else {
        // Jika array timestamps penuh tapi belum melebihi THRESHOLD,
        // ini berarti ada paket yang sangat cepat. Bisa jadi pertanda serangan.
        // Jika THRESHOLD tercapai, biarkan logika di bawah yang menangani.
    }
    log->count = new_count;

    // Deteksi dan blokir jika melebihi ambang batas
    if (log->count >= THRESHOLD) { // Gunakan >= untuk memastikan terpicu tepat pada threshold
        printf("Detected DoS attack from IP: %s (Protocol: %s). Count: %d, Threshold: %d. Blocking...\n",
               src_ip, protocol_name, log->count, THRESHOLD);
        block_ip(src_ip);
        log_to_sqlite(src_ip, protocol_name, now);
        log->blocked = 1; // Tandai sebagai sudah diblokir
    }
}

// Handler paket dari pcap
void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    // Pastikan ukuran paket cukup besar untuk header IP (14 byte Ethernet + 20 byte IP minimum)
    if (header->len < 14 + sizeof(struct ip)) {
        return;
    }
    const struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header size is 14 bytes
    analyze_packet(ip_header);
}

// Signal handler untuk SIGINT (Ctrl+C)
void sig_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nShutting down DoS Detection Daemon...\n");
        if (db) {
            sqlite3_close(db); // Tutup database
        }
        // Mungkin tambahkan logika untuk menghapus aturan iptables yang ditambahkan
        // Tapi biasanya aturan dibiarkan tetap ada sampai reboot atau dihapus manual
        exit(0); // Keluar dari program
    }
}

int main() {
    // Daemonize the process
    pid_t pid = fork();

    if (pid < 0) {
        fprintf(stderr, "Fork failed\n");
        return 1;
    }

    if (pid > 0) {
        // Parent process, exit
        printf("DoS Detection Daemon started with PID: %d\n", pid);
        return 0;
    }

    // Child process continues
    // Create a new session to detach from the controlling terminal
    if (setsid() < 0) {
        fprintf(stderr, "setsid failed\n");
        return 1;
    }

    // Change the current working directory to the root directory
    // or another appropriate directory.
    if (chdir("/") < 0) {
        fprintf(stderr, "chdir failed\n");
        return 1;
    }

    // Close all open file descriptors
    // This is important to detach from the terminal and prevent issues.
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Register signal handler for SIGINT
    signal(SIGINT, sig_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Deteksi interface yang aktif
    char *dev;
    char default_interface[PCAP_ERRBUF_SIZE];

    if (strcmp(INTERFACE, "") == 0) { // Jika INTERFACE kosong, coba cari default
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 1;
        }
        strncpy(default_interface, dev, PCAP_ERRBUF_SIZE - 1);
        default_interface[PCAP_ERRBUF_SIZE - 1] = '\0';
        printf("Using default interface: %s\n", default_interface);
    } else {
        strncpy(default_interface, INTERFACE, PCAP_ERRBUF_SIZE - 1);
        default_interface[PCAP_ERRBUF_SIZE - 1] = '\0';
        printf("Using configured interface: %s\n", default_interface);
    }

    // Buka device untuk menangkap paket
    // Promiscuous mode (1) agar bisa melihat semua paket, bukan hanya yang ditujukan ke kita.
    // Timeout 1000ms.
    handle = pcap_open_live(default_interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device %s: %s\n", default_interface, errbuf);
        return 1;
    }

    // Buka database SQLite
    if (sqlite3_open(DB_PATH, &db)) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        pcap_close(handle);
        return 1;
    }
    create_db_table(); // Panggil fungsi untuk memastikan tabel ada

    printf("DoS Detection Daemon running. Monitoring %s for DoS attacks...\n", default_interface);
    printf("Threshold: %d packets in %d seconds.\n", THRESHOLD, TIME_WINDOW);
    printf("Attack logs will be stored in: %s\n", DB_PATH);

    // Loop untuk menangkap paket
    pcap_loop(handle, 0, packet_handler, NULL);

    // Kode ini tidak akan dieksekusi selama pcap_loop berjalan
    // Kecuali jika ada sinyal atau error yang menghentikan loop
    sqlite3_close(db);
    pcap_close(handle);

    return 0;
}