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
 #include <sys/types.h>
 #include <sys/wait.h>
 #include <signal.h>
 
 #define THRESHOLD 100
 #define TIME_WINDOW 10 // seconds
 #define INTERFACE "eth0" // network interface
 #define DB_PATH "/var/log/dos_attacks.db"
 
 // IP tracking structure
 typedef struct {
     char ip[INET_ADDRSTRLEN];
     time_t timestamps[THRESHOLD];
     int count;
     int blocked;
 } IPLog;
 
 #define MAX_IPS 1024
 IPLog ip_logs[MAX_IPS];
 int ip_count = 0;
 sqlite3 *db;
 
 void log_to_sqlite(const char *ip, const char *protocol) {
     char *err_msg = 0;
     char sql[256];
     time_t now = time(NULL);
     snprintf(sql, sizeof(sql),
              "INSERT INTO attacks (ip, protocol, timestamp) VALUES ('%s', '%s', '%ld');",
              ip, protocol, now);
     sqlite3_exec(db, sql, 0, 0, &err_msg);
 }
 
 void block_ip(const char *ip) {
     char cmd[128];
     snprintf(cmd, sizeof(cmd), "iptables -A INPUT -s %s -j DROP", ip);
     system(cmd);
 }
 
 IPLog* find_or_create_log(const char *ip) {
     for (int i = 0; i < ip_count; i++) {
         if (strcmp(ip_logs[i].ip, ip) == 0) return &ip_logs[i];
     }
     if (ip_count >= MAX_IPS) return NULL;
     strncpy(ip_logs[ip_count].ip, ip, INET_ADDRSTRLEN);
     ip_logs[ip_count].count = 0;
     ip_logs[ip_count].blocked = 0;
     return &ip_logs[ip_count++];
 }
 
 void analyze_packet(const struct ip *ip_header) {
     char src_ip[INET_ADDRSTRLEN];
     inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
 
     const char *protocol = NULL;
     int suspicious = 0;
 
     if (ip_header->ip_p == IPPROTO_TCP) {
         const struct tcphdr *tcp = (struct tcphdr *)((u_char*)ip_header + (ip_header->ip_hl * 4));
         if (ntohs(tcp->th_dport) == 80) {
             protocol = "TCP";
             suspicious = 1;
         }
     } else if (ip_header->ip_p == IPPROTO_UDP) {
         protocol = "UDP";
         suspicious = 1;
     } else if (ip_header->ip_p == IPPROTO_ICMP) {
         protocol = "ICMP";
         suspicious = 1;
     }
 
     if (!suspicious || !protocol) return;
 
     IPLog *log = find_or_create_log(src_ip);
     if (!log || log->blocked) return;
 
     time_t now = time(NULL);
 
     // Shift timestamps to keep only recent
     int new_count = 0;
     for (int i = 0; i < log->count; i++) {
         if (now - log->timestamps[i] < TIME_WINDOW) {
             log->timestamps[new_count++] = log->timestamps[i];
         }
     }
     log->timestamps[new_count++] = now;
     log->count = new_count;
 
     if (log->count > THRESHOLD) {
         block_ip(src_ip);
         log_to_sqlite(src_ip, protocol);
         log->blocked = 1;
     }
 }
 
 void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
     const struct ip *ip_header = (struct ip *)(packet + 14); // skip ethernet
     analyze_packet(ip_header);
 }
 
 int main() {
     char errbuf[PCAP_ERRBUF_SIZE];
     pcap_t *handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
     if (!handle) {
         fprintf(stderr, "Could not open device: %s\n", errbuf);
         return 1;
     }
 
     if (sqlite3_open(DB_PATH, &db)) {
         fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
         return 1;
     }
 
     const char *sql_create = "CREATE TABLE IF NOT EXISTS attacks ("
                              "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                              "ip TEXT,"
                              "protocol TEXT,"
                              "timestamp TEXT);";
     char *err_msg = 0;
     sqlite3_exec(db, sql_create, 0, 0, &err_msg);
 
     pcap_loop(handle, 0, packet_handler, NULL);
 
     sqlite3_close(db);
     pcap_close(handle);
 
     return 0;
 }
 