#include <stdio.h>
#include <stdlib.h>   
#include <string.h> 
#include <stdint.h>   
#include <errno.h>  
#include <fcntl.h>   
#include <mysql/mysql.h> 
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <time.h>
#include <pthread.h>
#include <map>
#include <vector>
#include <string>
#include <boost/crc.hpp>

// 常量定义
#define MAX_EVENTS 1024       // epoll最大事件数
#define MAX_CLIENTS 100       // 最大客户端连接数
#define BUFFER_SIZE 32768     // 缓冲区大小(32KB)
#define CHUNK_SIZE 32768      // 文件分片大小(32KB)
#define MY_PROTOCOL_VERSION 1 // 自定义协议版本号
#define ACK_TIMEOUT 5000      // ACK超时时间(5秒)

// 消息类型定义
#define MSG_TYPE_TEXT 1        // 文本消息
#define MSG_TYPE_FILE 2        // 文件消息
#define MSG_TYPE_ACK 3         // ACK确认
#define MSG_TYPE_CLIENT_LIST 4 // 客户端列表
#define MSG_TYPE_FILE_CHUNK 5  // 文件分片
#define MSG_TYPE_FILE_START 6  // 文件开始传输
#define MSG_TYPE_FILE_END 7    // 文件结束传输

// 增强版协议包头(使用packed属性避免内存对齐)
typedef struct {
    uint8_t  version;        // 协议版本
    uint8_t  msg_type;       // 消息类型
    uint32_t datalen;        // 数据长度
    uint32_t filename_len;   // 文件名长度
    uint64_t file_size;      // 文件总大小
    uint32_t msg_id;         // 消息唯一ID
    uint32_t chunk_index;    // 当前分片序号
    uint32_t chunk_count;    // 总分片数
    uint32_t sender_id;      // 发送者ID
    uint32_t crc32;          // CRC32校验（新增）
} __attribute__((packed)) PacketHeader;

// 客户端连接信息结构体
typedef struct {
    int socket;              // 客户端套接字
    int id;                  // 客户端唯一ID
    char ip[16];             // 客户端IP地址
    int port;                // 客户端端口
    char current_filename[BUFFER_SIZE]; // 当前传输的文件名
    int file_fd;             // 文件描述符
    uint64_t received_size;  // 已接收字节数
    uint32_t current_msg_id; // 当前消息ID
    time_t last_activity;    // 最后活动时间戳
    bool is_online;          // 在线状态
} Client;

// 文件传输状态结构体
typedef struct {
    uint32_t msg_id;                   // 消息ID
    uint32_t sender_id;                // 发送者ID
    char filename[BUFFER_SIZE];        // 文件名
    uint64_t file_size;                // 文件大小
    uint64_t received_size;            // 已接收大小
    uint32_t chunk_count;              // 总分片数
    std::map<uint32_t, bool> received_chunks; // 分片接收状态映射表
    time_t start_time;                 // 传输开始时间
    FILE* file_fd;                     // 文件指针
} FileTransfer;

// 全局变量
std::map<uint32_t, FileTransfer> file_transfers; // 文件传输状态映射表
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER; // 文件互斥锁
uint32_t next_msg_id = 1;               // 下一个消息ID(原子递增)

// 网络字节序转换(64位)
uint64_t htonll(uint64_t value) {
    return ((uint64_t)htonl((uint32_t)(value >> 32)) << 32) | htonl((uint32_t)value);
}

uint64_t ntohll(uint64_t value) {
    return ((uint64_t)ntohl((uint32_t)(value >> 32)) << 32) | ntohl((uint32_t)value);
}

// 错误处理函数(打印错误并退出)
void error_exit(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// 设置文件描述符为非阻塞模式
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) error_exit("fcntl(F_GETFL)");
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) error_exit("fcntl(F_SETFL)");
}

// 生成唯一消息ID(原子操作)
uint32_t generate_msg_id() {
    return __sync_fetch_and_add(&next_msg_id, 1);
}

// 向数据库插入新客户端并获取ID
bool insert_client_with_id(MYSQL* conn, const char* ip, int port, int* client_id) {
    char escaped_ip[BUFFER_SIZE] = { 0 };
    mysql_real_escape_string(conn, escaped_ip, ip, strlen(ip));

    // 使用事务保证操作的原子性
    if (mysql_query(conn, "START TRANSACTION") != 0) {
        fprintf(stderr, "开启事务失败: %s\n", mysql_error(conn));
        return false;
    }

    char query[BUFFER_SIZE] = { 0 };
    snprintf(query, sizeof(query), "INSERT INTO clients (ip, port) VALUES ('%s', %d)", escaped_ip, port);
    if (mysql_query(conn, query) != 0) {
        fprintf(stderr, "插入失败: %s\n", mysql_error(conn));
        if (mysql_query(conn, "ROLLBACK") != 0) {
            fprintf(stderr, "回滚失败: %s\n", mysql_error(conn));
        }
        return false;
    }

    // 获取自增ID
    *client_id = mysql_insert_id(conn);

    if (mysql_query(conn, "COMMIT") != 0) {
        fprintf(stderr, "提交事务失败: %s\n", mysql_error(conn));
        return false;
    }

    return true;
}

// CRC32计算函数
uint32_t calculateHeaderCRC32(const PacketHeader* header, const void* data, size_t data_len) {
    boost::crc_32_type crc;
    // 只对 header 的前 N 字节（不含 crc32 字段）+ data 做校验
    crc.process_bytes(header, offsetof(PacketHeader, crc32));
    if (data && data_len > 0) {
        crc.process_bytes(data, data_len);
    }
    return crc.checksum();
}

// CRC32校验日志辅助函数
void print_crc32_check(const char* type, uint32_t msg_id, uint32_t crc_recv, uint32_t crc_calc, int chunk_index, int chunk_count, int ok) {
    printf("[CRC32校验] type:%s msg_id:%u chunk:%d/%d 收到:%08x 计算:%08x 结果:%s\n",
        type, msg_id, chunk_index, chunk_count, crc_recv, crc_calc, ok ? "成功" : "失败");
}

// 发送ACK确认消息
void send_ack(int client_fd, uint32_t msg_id, uint32_t chunk_index) {
    PacketHeader ack_header = {
        .version = MY_PROTOCOL_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .datalen = 0,
        .filename_len = 0,
        .file_size = 0,
        .msg_id = htonl(msg_id),
        .chunk_index = htonl(chunk_index),
        .chunk_count = 0,
        .sender_id = 0,
        .crc32 = 0
    };
    // 计算CRC32
    ack_header.crc32 = htonl(calculateHeaderCRC32(&ack_header, NULL, 0));
    if (send(client_fd, &ack_header, sizeof(ack_header), MSG_NOSIGNAL) == -1) {
        fprintf(stderr, "发送ACK失败: %s\n", strerror(errno));
    }
}

// 获取在线客户端列表
std::vector<Client> get_online_clients(Client clients[]) {
    std::vector<Client> online_clients;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1 && clients[i].is_online) {
            online_clients.push_back(clients[i]);
        }
    }
    return online_clients;
}

// 广播客户端列表给所有在线客户端
void broadcast_client_list(Client clients[]) {
    std::vector<Client> online_clients = get_online_clients(clients);
    std::string client_list_data;
    for (const auto& client : online_clients) {
        client_list_data += std::to_string(client.id) + ":" + client.ip + ":" + std::to_string(client.port) + ";";
    }
    if (!client_list_data.empty()) {
        PacketHeader header = {
            .version = MY_PROTOCOL_VERSION,
            .msg_type = MSG_TYPE_CLIENT_LIST,
            .datalen = htonl(client_list_data.length()),
            .filename_len = 0,
            .file_size = 0,
            .msg_id = htonl(generate_msg_id()),
            .chunk_index = 0,
            .chunk_count = 0,
            .sender_id = 0,
            .crc32 = 0
        };
        // 计算CRC32
        header.crc32 = htonl(calculateHeaderCRC32(&header, client_list_data.c_str(), client_list_data.length()));
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != -1 && clients[i].is_online) {
                if (send(clients[i].socket, &header, sizeof(header), MSG_NOSIGNAL) == -1) {
                    fprintf(stderr, "发送客户端列表失败: %s\n", strerror(errno));
                    continue;
                }
                if (send(clients[i].socket, client_list_data.c_str(), client_list_data.length(), MSG_NOSIGNAL) == -1) {
                    fprintf(stderr, "发送客户端列表数据失败: %s\n", strerror(errno));
                    continue;
                }
            }
        }
    }
}

// 广播消息给所有客户端(核心转发函数)
void broadcast_message(Client clients[], int sender_fd, const void* data, size_t len,
    uint8_t msg_type, const char* filename, uint32_t filename_len, uint64_t file_size,
    uint32_t msg_id, uint32_t chunk_index, uint32_t chunk_count, uint32_t sender_id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1 && clients[i].is_online) {
            PacketHeader header = {
                .version = MY_PROTOCOL_VERSION,
                .msg_type = msg_type,
                .datalen = htonl(len),
                .filename_len = htonl(filename_len),
                .file_size = htonll(file_size),
                .msg_id = htonl(msg_id),
                .chunk_index = htonl(chunk_index),
                .chunk_count = htonl(chunk_count),
                .sender_id = htonl(sender_id),
                .crc32 = 0
            };
            // 计算CRC32
            if (filename_len > 0 && filename) {
                // 文件开始包：header+文件名
                header.crc32 = htonl(calculateHeaderCRC32(&header, filename, filename_len));
            }
            else if (len > 0 && data) {
                // 普通数据包：header+data
                header.crc32 = htonl(calculateHeaderCRC32(&header, data, len));
            }
            else {
                // 仅header
                header.crc32 = htonl(calculateHeaderCRC32(&header, NULL, 0));
            }
            if (send(clients[i].socket, &header, sizeof(header), MSG_NOSIGNAL) == -1) {
                fprintf(stderr, "发送头部失败: %s\n", strerror(errno));
                continue;
            }
            if (filename_len > 0 && filename) {
                if (send(clients[i].socket, filename, filename_len, MSG_NOSIGNAL) == -1) {
                    fprintf(stderr, "发送文件名失败: %s\n", strerror(errno));
                    continue;
                }
            }
            if (len > 0 && data) {
                if (send(clients[i].socket, data, len, MSG_NOSIGNAL) == -1) {
                    fprintf(stderr, "发送数据失败: %s\n", strerror(errno));
                    continue;
                }
            }
            printf("广播消息到客户端 %d: type=%u, msg_id=%u, chunk=%u/%u\n",
                clients[i].id, msg_type, msg_id, chunk_index, chunk_count);
        }
    }
}

// 处理文本消息
void handle_text_message(Client clients[], int client_fd, PacketHeader header) {
    char buffer[BUFFER_SIZE];
    if (ntohl(header.datalen) >= BUFFER_SIZE) {
        fprintf(stderr, "文本消息过长\n");
        return;
    }
    ssize_t bytes_read = recv(client_fd, buffer, ntohl(header.datalen), MSG_WAITALL);
    if (bytes_read != ntohl(header.datalen)) {
        fprintf(stderr, "文本消息接收不完整\n");
        return;
    }
    buffer[bytes_read] = '\0';
    // CRC32校验
    uint32_t crc_recv = ntohl(header.crc32);
    uint32_t crc_calc = calculateHeaderCRC32(&header, buffer, bytes_read);
    int ok = (crc_recv == crc_calc);
    print_crc32_check("TEXT", ntohl(header.msg_id), crc_recv, crc_calc, 0, 1, ok);
    if (!ok) {
        fprintf(stderr, "CRC32校验失败，丢弃消息\n");
        return;
    }
    printf("收到文本消息: %s\n", buffer);
    send_ack(client_fd, ntohl(header.msg_id), ntohl(header.chunk_index));
    broadcast_message(clients, client_fd, buffer, bytes_read, MSG_TYPE_TEXT,
        NULL, 0, 0, ntohl(header.msg_id), 0, 1, ntohl(header.sender_id));
}

// 处理文件开始传输消息
void handle_file_start(Client clients[], int client_fd, PacketHeader header) {
    char filename[BUFFER_SIZE];
    if (ntohl(header.filename_len) >= BUFFER_SIZE) {
        fprintf(stderr, "文件名过长\n");
        return;
    }
    ssize_t bytes_read = recv(client_fd, filename, ntohl(header.filename_len), MSG_WAITALL);
    if (bytes_read != ntohl(header.filename_len)) {
        fprintf(stderr, "文件名接收不完整\n");
        return;
    }
    filename[bytes_read] = '\0';
    // CRC32校验
    uint32_t crc_recv = ntohl(header.crc32);
    uint32_t crc_calc = calculateHeaderCRC32(&header, filename, bytes_read);
    int ok = (crc_recv == crc_calc);
    print_crc32_check("FILE_START", ntohl(header.msg_id), crc_recv, crc_calc, 0, ntohl(header.chunk_count), ok);
    if (!ok) {
        fprintf(stderr, "CRC32校验失败，丢弃文件开始包\n");
        return;
    }
    pthread_mutex_lock(&file_mutex);
    FileTransfer& transfer = file_transfers[ntohl(header.msg_id)];
    transfer.msg_id = ntohl(header.msg_id);
    transfer.sender_id = ntohl(header.sender_id);
    strcpy(transfer.filename, filename);
    transfer.file_size = ntohll(header.file_size);
    transfer.chunk_count = ntohl(header.chunk_count);
    transfer.start_time = time(NULL);
    transfer.file_fd = NULL;
    transfer.received_size = 0;
    transfer.received_chunks.clear();
    pthread_mutex_unlock(&file_mutex);
    printf("收到文件开始消息: %s (大小: %" PRIu64 " bytes, 分片数: %u)\n",
        filename, transfer.file_size, transfer.chunk_count);
    send_ack(client_fd, ntohl(header.msg_id), 0);
    broadcast_message(clients, client_fd, NULL, 0, MSG_TYPE_FILE_START,
        filename, ntohl(header.filename_len), ntohll(header.file_size),
        ntohl(header.msg_id), 0, ntohl(header.chunk_count), ntohl(header.sender_id));
}

// 处理文件分片消息
void handle_file_chunk(Client clients[], int client_fd, PacketHeader header) {
    uint32_t msg_id = ntohl(header.msg_id);
    uint32_t chunk_index = ntohl(header.chunk_index);
    uint32_t chunk_count = ntohl(header.chunk_count);
    uint32_t datalen = ntohl(header.datalen);
    pthread_mutex_lock(&file_mutex);
    auto it = file_transfers.find(msg_id);
    if (it == file_transfers.end()) {
        pthread_mutex_unlock(&file_mutex);
        fprintf(stderr, "未找到文件传输记录: msg_id=%u\n", msg_id);
        return;
    }
    FileTransfer& transfer = it->second;
    transfer.start_time = time(NULL);
    if (datalen > CHUNK_SIZE) {
        pthread_mutex_unlock(&file_mutex);
        fprintf(stderr, "分片数据过大: %u > %u\n", datalen, CHUNK_SIZE);
        return;
    }
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = 0;
    size_t total_read = 0;
    while (total_read < datalen) {
        bytes_read = recv(client_fd, buffer + total_read, datalen - total_read, 0);
        if (bytes_read <= 0) {
            if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                usleep(1000);
                continue;
            }
            pthread_mutex_unlock(&file_mutex);
            fprintf(stderr, "文件分片接收失败: %s\n", strerror(errno));
            return;
        }
        total_read += bytes_read;
    }
    if (total_read != datalen) {
        pthread_mutex_unlock(&file_mutex);
        fprintf(stderr, "文件分片接收不完整: 期望%d, 实际%zu\n", datalen, total_read);
        return;
    }
    // CRC32校验
    uint32_t crc_recv = ntohl(header.crc32);
    uint32_t crc_calc = calculateHeaderCRC32(&header, buffer, total_read);
    int ok = (crc_recv == crc_calc);
    print_crc32_check("FILE_CHUNK", msg_id, crc_recv, crc_calc, chunk_index, chunk_count, ok);
    if (!ok) {
        pthread_mutex_unlock(&file_mutex);
        fprintf(stderr, "CRC32校验失败，丢弃文件分片\n");
        return;
    }
    transfer.received_chunks[chunk_index] = true;
    transfer.received_size += total_read;
    pthread_mutex_unlock(&file_mutex);
    send_ack(client_fd, msg_id, chunk_index);
    broadcast_message(clients, client_fd, buffer, total_read, MSG_TYPE_FILE_CHUNK,
        NULL, 0, 0, msg_id, chunk_index, chunk_count, ntohl(header.sender_id));
    printf("转发文件分片: msg_id=%u, chunk=%u/%u, size=%zu\n",
        msg_id, chunk_index, chunk_count, total_read);
}

// 处理文件结束消息
void handle_file_end(Client clients[], int client_fd, PacketHeader header) {
    uint32_t msg_id = ntohl(header.msg_id);
    // CRC32校验
    uint32_t crc_recv = ntohl(header.crc32);
    uint32_t crc_calc = calculateHeaderCRC32(&header, NULL, 0);
    int ok = (crc_recv == crc_calc);
    print_crc32_check("FILE_END", msg_id, crc_recv, crc_calc, 0, 0, ok);
    if (!ok) {
        fprintf(stderr, "CRC32校验失败，丢弃文件结束包\n");
        return;
    }
    pthread_mutex_lock(&file_mutex);
    auto it = file_transfers.find(msg_id);
    if (it != file_transfers.end()) {
        FileTransfer& transfer = it->second;
        printf("文件传输完成: %s (msg_id=%u, 转发大小: %" PRIu64 ")\n",
            transfer.filename, msg_id, transfer.received_size);
        file_transfers.erase(it);
    }
    pthread_mutex_unlock(&file_mutex);
    send_ack(client_fd, msg_id, 0);
    broadcast_message(clients, client_fd, NULL, 0, MSG_TYPE_FILE_END,
        NULL, 0, 0, msg_id, 0, 0, ntohl(header.sender_id));
}

// 处理ACK消息
void handle_ack_message(int client_fd, PacketHeader header) {
    // CRC32校验
    uint32_t crc_recv = ntohl(header.crc32);
    uint32_t crc_calc = calculateHeaderCRC32(&header, NULL, 0);
    int ok = (crc_recv == crc_calc);
    print_crc32_check("ACK", ntohl(header.msg_id), crc_recv, crc_calc, ntohl(header.chunk_index), 0, ok);
    if (!ok) {
        fprintf(stderr, "CRC32校验失败，丢弃ACK包\n");
        return;
    }
    uint32_t msg_id = ntohl(header.msg_id);
    uint32_t chunk_index = ntohl(header.chunk_index);
    printf("收到ACK: msg_id=%u, chunk=%u\n", msg_id, chunk_index);
}

// 清理超时的文件传输
void cleanup_timeout_transfers() {
    time_t current_time = time(NULL);
    pthread_mutex_lock(&file_mutex);
    auto it = file_transfers.begin();
    while (it != file_transfers.end()) {
        // 检查是否超时(30分钟)
        if (current_time - it->second.start_time > 1800) {
            printf("清理超时文件传输: msg_id=%u\n", it->first);
            it = file_transfers.erase(it);
        }
        else {
            ++it;
        }
    }
    pthread_mutex_unlock(&file_mutex);
}

// 主函数
int main() {
    // 初始化MySQL连接
    MYSQL* conn = mysql_init(NULL);
    if (!conn || !mysql_real_connect(conn, "127.0.0.1", "root", "1228", "server", 0, NULL, 0)) {
        fprintf(stderr, "MySQL连接失败: %s\n", mysql_error(conn));
        exit(EXIT_FAILURE);
    }

    // 创建客户端表
    if (mysql_query(conn, "DROP TABLE IF EXISTS clients") != 0) {
        fprintf(stderr, "删除旧表失败: %s\n", mysql_error(conn));
    }

    if (mysql_query(conn,
        "CREATE TABLE clients ("
        "id INT AUTO_INCREMENT PRIMARY KEY, "
        "ip VARCHAR(15) NOT NULL, "
        "port INT NOT NULL)"
    ) != 0) {
        fprintf(stderr, "创建表失败: %s\n", mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }

    // 获取服务器端口号
    int port = 8888; // 默认端口
    char port_str[BUFFER_SIZE] = { 0 };
    printf("请输入服务器端口号（默认8888，直接回车使用默认值）: ");
    fflush(stdout);
    if (fgets(port_str, sizeof(port_str), stdin)) {
        char* newline = strchr(port_str, '\n');
        if (newline) *newline = '\0';

        if (port_str[0] != '\0') {
            int input_port = atoi(port_str);
            if (input_port >= 0 && input_port <= 65535) {
                port = input_port;
            }
            else {
                fprintf(stderr, "错误：端口号必须在0-65535之间，使用默认端口8888\n");
            }
        }
    }
    printf("服务器启动，监听端口 %d\n", port);
    printf("输入 'exit' 退出服务器\n");

    // 初始化客户端数组
    Client clients[MAX_CLIENTS] = { 0 };
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1; // 初始化为无效套接字
        clients[i].id = 0;
        clients[i].is_online = false;
    }

    // 创建监听套接字
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) error_exit("socket创建失败");

    // 设置端口复用选项
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        error_exit("setsockopt失败");

    // 绑定服务器地址
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error_exit("bind失败");

    // 开始监听
    if (listen(listen_fd, MAX_CLIENTS) < 0)
        error_exit("listen失败");

    // 设置非阻塞模式
    set_nonblocking(listen_fd);

    // 创建epoll实例
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) error_exit("epoll_create失败");

    struct epoll_event event, events[MAX_EVENTS];

    // 添加监听套接字到epoll
    event.events = EPOLLIN | EPOLLET; // 边缘触发模式
    event.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) < 0)
        error_exit("epoll_ctl添加监听socket失败");

    // 添加标准输入到epoll(用于接收退出命令)
    event.data.fd = STDIN_FILENO;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) < 0)
        error_exit("epoll_ctl添加标准输入失败");

    char exit_cmd[BUFFER_SIZE] = { 0 };
    int should_exit = 0;
    time_t last_cleanup = time(NULL); // 上次清理时间

    // 主事件循环
    while (!should_exit) {
        // 等待事件(1秒超时)
        int n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (n_events < 0) {
            if (errno == EINTR) continue; // 被信号中断
            error_exit("epoll_wait失败");
        }

        // 定期清理超时传输(每分钟一次)
        time_t current_time = time(NULL);
        if (current_time - last_cleanup > 60) {
            cleanup_timeout_transfers();
            last_cleanup = current_time;
        }

        // 处理所有事件
        for (int i = 0; i < n_events; i++) {
            int fd = events[i].data.fd;

            // 处理标准输入事件(退出命令)
            if (fd == STDIN_FILENO) {
                ssize_t read_size = read(STDIN_FILENO, exit_cmd, sizeof(exit_cmd));
                if (read_size > 0 && strstr(exit_cmd, "exit\n") != NULL) {
                    printf("接收到退出命令，关闭服务器\n");
                    should_exit = 1;
                    break;
                }
                memset(exit_cmd, 0, sizeof(exit_cmd));
            }

            // 处理新连接事件
            else if (fd == listen_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                // 接受新连接
                int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
                if (client_fd < 0) {
                    perror("accept失败");
                    continue;
                }

                // 查找可用客户端槽位
                int client_idx = -1;
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (clients[j].socket == -1) {
                        client_idx = j;
                        break;
                    }
                }

                // 客户端数量达到上限
                if (client_idx == -1) {
                    close(client_fd);
                    fprintf(stderr, "客户端连接数达到上限（%d）\n", MAX_CLIENTS);
                    continue;
                }

                // 设置非阻塞模式
                set_nonblocking(client_fd);
                char client_ip[INET_ADDRSTRLEN];
                // 获取客户端IP和端口
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                int client_port = ntohs(client_addr.sin_port);

                // 插入数据库并获取客户端ID
                int new_id = 0;
                if (insert_client_with_id(conn, client_ip, client_port, &new_id)) {
                    printf("新客户端连接: ID=%d IP=%s Port=%d\n", new_id, client_ip, client_port);
                    // 初始化客户端信息
                    clients[client_idx].id = new_id;
                    strcpy(clients[client_idx].ip, client_ip);
                    clients[client_idx].port = client_port;
                    clients[client_idx].is_online = true;
                    clients[client_idx].last_activity = time(NULL);
                }
                else {
                    printf("客户端ID生成失败，拒绝连接: IP=%s Port=%d\n", client_ip, client_port);
                    close(client_fd);
                    continue;
                }

                // 记录套接字并重置接收状态
                clients[client_idx].socket = client_fd;
                clients[client_idx].received_size = 0;

                // 添加到epoll监控
                event.data.fd = client_fd;
                event.events = EPOLLIN | EPOLLET;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
                    close(client_fd);
                    clients[client_idx].socket = -1;
                    error_exit("epoll_ctl添加客户端失败");
                }

                // 广播更新后的客户端列表
                broadcast_client_list(clients);
            }

            // 处理客户端数据事件
            else {
                int client_idx = -1;
                // 查找对应的客户端
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (clients[j].socket == fd) {
                        client_idx = j;
                        break;
                    }
                }

                // 客户端不存在(可能已断开)
                if (client_idx == -1) {
                    close(fd);
                    continue;
                }

                // 更新最后活动时间
                clients[client_idx].last_activity = time(NULL);

                // 接收协议头
                PacketHeader header = { 0 };
                ssize_t recv_size = recv(fd, &header, sizeof(header), 0);
                if (recv_size <= 0) {
                    // 客户端断开连接
                    printf("客户端%d断开连接（fd=%d）\n", clients[client_idx].id, fd);
                    close(fd);
                    clients[client_idx].socket = -1;
                    clients[client_idx].is_online = false;
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);

                    // 广播更新客户端列表
                    broadcast_client_list(clients);
                    continue;
                }

                // 检查头部完整性
                if (recv_size != sizeof(header)) {
                    fprintf(stderr, "接收头部不完整\n");
                    continue;
                }

                // 根据消息类型分发处理
                switch (header.msg_type) {
                case MSG_TYPE_TEXT:
                    handle_text_message(clients, fd, header);
                    break;
                case MSG_TYPE_FILE_START:
                    handle_file_start(clients, fd, header);
                    break;
                case MSG_TYPE_FILE_CHUNK:
                    handle_file_chunk(clients, fd, header);
                    break;
                case MSG_TYPE_FILE_END:
                    handle_file_end(clients, fd, header);
                    break;
                case MSG_TYPE_ACK:
                    handle_ack_message(fd, header);
                    break;
                default:
                    fprintf(stderr, "未知消息类型: %d\n", header.msg_type);
                    break;
                }
            }
        }
    }

    // 清理资源
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1) {
            close(clients[i].socket);
        }
    }

    // 清理文件传输状态
    pthread_mutex_lock(&file_mutex);
    file_transfers.clear();
    pthread_mutex_unlock(&file_mutex);

    // 销毁互斥锁
    pthread_mutex_destroy(&file_mutex);
    // 关闭数据库连接
    mysql_close(conn);
    // 关闭套接字
    close(listen_fd);
    close(epoll_fd);

    printf("服务器已关闭\n");
    return 0;
}