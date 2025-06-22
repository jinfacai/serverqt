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

// 常量定义
#define MAX_EVENTS 1024
#define MAX_CLIENTS 100
#define BUFFER_SIZE 32768  // 增大缓冲区支持大文件
#define CHUNK_SIZE 32768   // 文件分片大小
#define MY_PROTOCOL_VERSION 1
#define ACK_TIMEOUT 5000  // ACK超时时间(毫秒)

// 消息类型
#define MSG_TYPE_TEXT 1
#define MSG_TYPE_FILE 2
#define MSG_TYPE_ACK 3
#define MSG_TYPE_CLIENT_LIST 4
#define MSG_TYPE_FILE_CHUNK 5
#define MSG_TYPE_FILE_START 6
#define MSG_TYPE_FILE_END 7

// 增强版协议包头
typedef struct {
    uint8_t  version;
    uint8_t  msg_type;
    uint32_t datalen;
    uint32_t filename_len;
    uint64_t file_size;
    uint32_t msg_id;        // 消息唯一ID
    uint32_t chunk_index;   // 当前分片序号
    uint32_t chunk_count;   // 总分片数
    uint32_t sender_id;     // 发送者ID
} __attribute__((packed)) PacketHeader;

// 客户端连接信息
typedef struct {
    int socket;
    int id;
    char ip[16];
    int port;
    char current_filename[BUFFER_SIZE];
    int file_fd;
    uint64_t received_size;
    uint32_t current_msg_id;
    time_t last_activity;
    bool is_online;
} Client;

// 文件传输状态
typedef struct {
    uint32_t msg_id;
    uint32_t sender_id;
    char filename[BUFFER_SIZE];
    uint64_t file_size;
    uint64_t received_size;
    uint32_t chunk_count;
    std::map<uint32_t, bool> received_chunks;  // 记录已接收的分片
    time_t start_time;
    FILE* file_fd;
} FileTransfer;

// 全局变量
std::map<uint32_t, FileTransfer> file_transfers;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
uint32_t next_msg_id = 1;

// 网络字节序转换
uint64_t htonll(uint64_t value) {
    return ((uint64_t)htonl((uint32_t)(value >> 32)) << 32) | htonl((uint32_t)value);
}

uint64_t ntohll(uint64_t value) {
    return ((uint64_t)ntohl((uint32_t)(value >> 32)) << 32) | ntohl((uint32_t)value);
}

// 错误处理函数
void error_exit(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// 设置文件为非阻塞模式 
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) error_exit("fcntl(F_GETFL)");
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) error_exit("fcntl(F_SETFL)");
}

// 生成唯一消息ID
uint32_t generate_msg_id() {
    return __sync_fetch_and_add(&next_msg_id, 1);
}

// 生成唯一ID并插入客户端信息
bool insert_client_with_id(MYSQL* conn, const char* ip, int port, int* client_id) {
    char escaped_ip[BUFFER_SIZE] = { 0 };
    mysql_real_escape_string(conn, escaped_ip, ip, strlen(ip));

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

    *client_id = mysql_insert_id(conn);

    if (mysql_query(conn, "COMMIT") != 0) {
        fprintf(stderr, "提交事务失败: %s\n", mysql_error(conn));
        return false;
    }

    return true;
}

// 发送ACK确认
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
        .sender_id = 0
    };

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

// 广播客户端列表
void broadcast_client_list(Client clients[]) {
    std::vector<Client> online_clients = get_online_clients(clients);

    // 构建客户端列表数据
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
            .sender_id = 0
        };

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

// 广播消息给所有客户端
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
                .sender_id = htonl(sender_id)
            };

            if (send(clients[i].socket, &header, sizeof(header), MSG_NOSIGNAL) == -1) {
                fprintf(stderr, "发送头部失败: %s\n", strerror(errno));
                continue;
            }

            if (filename_len > 0) {
                if (send(clients[i].socket, filename, filename_len, MSG_NOSIGNAL) == -1) {
                    fprintf(stderr, "发送文件名失败: %s\n", strerror(errno));
                    continue;
                }
            }

            if (len > 0) {
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
    printf("收到文本消息: %s\n", buffer);

    // 发送ACK
    send_ack(client_fd, ntohl(header.msg_id), ntohl(header.chunk_index));

    // 广播消息
    broadcast_message(clients, client_fd, buffer, bytes_read, MSG_TYPE_TEXT,
        NULL, 0, 0, ntohl(header.msg_id), 0, 1, ntohl(header.sender_id));
}

// 处理文件开始消息
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

    // 服务器端不创建文件，只记录文件传输信息用于转发
    pthread_mutex_lock(&file_mutex);
    FileTransfer& transfer = file_transfers[ntohl(header.msg_id)];
    transfer.msg_id = ntohl(header.msg_id);
    transfer.sender_id = ntohl(header.sender_id);
    strcpy(transfer.filename, filename);
    transfer.file_size = ntohll(header.file_size);
    transfer.chunk_count = ntohl(header.chunk_count);
    transfer.start_time = time(NULL);
    transfer.file_fd = NULL; // 服务器端不创建文件
    transfer.received_size = 0;
    transfer.received_chunks.clear();
    pthread_mutex_unlock(&file_mutex);

    printf("收到文件开始消息: %s (大小: %" PRIu64 " bytes, 分片数: %u)\n",
        filename, transfer.file_size, transfer.chunk_count);

    // 发送ACK
    send_ack(client_fd, ntohl(header.msg_id), 0);

    // 广播文件开始消息
    broadcast_message(clients, client_fd, NULL, 0, MSG_TYPE_FILE_START,
        filename, ntohl(header.filename_len), ntohll(header.file_size),
        ntohl(header.msg_id), 0, ntohl(header.chunk_count), ntohl(header.sender_id));
}

// 处理文件分片
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

    // 刷新超时时间
    transfer.start_time = time(NULL);

    // 检查数据长度是否合理
    if (datalen > CHUNK_SIZE) {
        pthread_mutex_unlock(&file_mutex);
        fprintf(stderr, "分片数据过大: %u > %u\n", datalen, CHUNK_SIZE);
        return;
    }

    // 接收文件数据（仅用于转发，不写入文件）
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = 0;
    size_t total_read = 0;

    // 确保完整接收数据
    while (total_read < datalen) {
        bytes_read = recv(client_fd, buffer + total_read, datalen - total_read, 0);
        if (bytes_read <= 0) {
            if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // 非阻塞模式下暂时没有数据，等待一下
                usleep(1000); // 1ms
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

    // 服务器端不写入文件，只记录接收状态用于统计
    transfer.received_chunks[chunk_index] = true;
    transfer.received_size += total_read;

    pthread_mutex_unlock(&file_mutex);

    // 发送ACK
    send_ack(client_fd, msg_id, chunk_index);

    // 广播文件分片
    broadcast_message(clients, client_fd, buffer, total_read, MSG_TYPE_FILE_CHUNK,
        NULL, 0, 0, msg_id, chunk_index, chunk_count, ntohl(header.sender_id));

    printf("转发文件分片: msg_id=%u, chunk=%u/%u, size=%zu\n",
        msg_id, chunk_index, chunk_count, total_read);
}

// 处理文件结束消息
void handle_file_end(Client clients[], int client_fd, PacketHeader header) {
    uint32_t msg_id = ntohl(header.msg_id);

    pthread_mutex_lock(&file_mutex);
    auto it = file_transfers.find(msg_id);
    if (it != file_transfers.end()) {
        FileTransfer& transfer = it->second;

        printf("文件传输完成: %s (msg_id=%u, 转发大小: %" PRIu64 ")\n",
            transfer.filename, msg_id, transfer.received_size);

        file_transfers.erase(it);
    }
    pthread_mutex_unlock(&file_mutex);

    // 发送ACK
    send_ack(client_fd, msg_id, 0);

    // 广播文件结束消息
    broadcast_message(clients, client_fd, NULL, 0, MSG_TYPE_FILE_END,
        NULL, 0, 0, msg_id, 0, 0, ntohl(header.sender_id));
}

// 处理ACK消息
void handle_ack_message(int client_fd, PacketHeader header) {
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
        if (current_time - it->second.start_time > 1800) { // 30分钟超时
            printf("清理超时文件传输: msg_id=%u\n", it->first);
            it = file_transfers.erase(it);
        }
        else {
            ++it;
        }
    }
    pthread_mutex_unlock(&file_mutex);
}

int main() {
    // 初始化MySQL
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

    // 获取端口号
    int port = 8888;
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
        clients[i].socket = -1;
        clients[i].id = 0;
        clients[i].is_online = false;
    }

    // 创建监听Socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) error_exit("socket创建失败");

    // 设置端口复用
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        error_exit("setsockopt失败");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error_exit("bind失败");

    if (listen(listen_fd, MAX_CLIENTS) < 0)
        error_exit("listen失败");

    set_nonblocking(listen_fd);

    // 初始化epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) error_exit("epoll_create失败");

    struct epoll_event event, events[MAX_EVENTS];

    // 监听服务器socket
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) < 0)
        error_exit("epoll_ctl添加监听socket失败");

    // 添加标准输入到epoll监控
    event.data.fd = STDIN_FILENO;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) < 0)
        error_exit("epoll_ctl添加标准输入失败");

    char exit_cmd[BUFFER_SIZE] = { 0 };
    int should_exit = 0;
    time_t last_cleanup = time(NULL);

    while (!should_exit) {
        int n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000); // 1秒超时
        if (n_events < 0) {
            if (errno == EINTR) continue;
            error_exit("epoll_wait失败");
        }

        // 定期清理超时传输
        time_t current_time = time(NULL);
        if (current_time - last_cleanup > 60) { // 每分钟清理一次
            cleanup_timeout_transfers();
            last_cleanup = current_time;
        }

        for (int i = 0; i < n_events; i++) {
            int fd = events[i].data.fd;

            // 处理终端输入（退出命令）
            if (fd == STDIN_FILENO) {
                ssize_t read_size = read(STDIN_FILENO, exit_cmd, sizeof(exit_cmd));
                if (read_size > 0 && strstr(exit_cmd, "exit\n") != NULL) {
                    printf("接收到退出命令，关闭服务器\n");
                    should_exit = 1;
                    break;
                }
                memset(exit_cmd, 0, sizeof(exit_cmd));
            }

            // 处理新客户端连接
            else if (fd == listen_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
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

                if (client_idx == -1) {
                    close(client_fd);
                    fprintf(stderr, "客户端连接数达到上限（%d）\n", MAX_CLIENTS);
                    continue;
                }

                set_nonblocking(client_fd);
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                int client_port = ntohs(client_addr.sin_port);

                // 插入客户端信息并获取ID
                int new_id = 0;
                if (insert_client_with_id(conn, client_ip, client_port, &new_id)) {
                    printf("新客户端连接: ID=%d IP=%s Port=%d\n", new_id, client_ip, client_port);
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

                // 广播客户端列表更新
                broadcast_client_list(clients);
            }

            // 处理客户端数据
            else {
                int client_idx = -1;
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (clients[j].socket == fd) {
                        client_idx = j;
                        break;
                    }
                }

                if (client_idx == -1) {
                    close(fd);
                    continue;
                }

                // 更新最后活动时间
                clients[client_idx].last_activity = time(NULL);

                PacketHeader header = { 0 };
                ssize_t recv_size = recv(fd, &header, sizeof(header), 0);
                if (recv_size <= 0) {
                    // 客户端断开连接
                    printf("客户端%d断开连接（fd=%d）\n", clients[client_idx].id, fd);
                    close(fd);
                    clients[client_idx].socket = -1;
                    clients[client_idx].is_online = false;
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);

                    // 广播客户端列表更新
                    broadcast_client_list(clients);
                    continue;
                }

                if (recv_size != sizeof(header)) {
                    fprintf(stderr, "接收头部不完整\n");
                    continue;
                }

                // 处理不同类型的消息
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

    pthread_mutex_lock(&file_mutex);
    file_transfers.clear();
    pthread_mutex_unlock(&file_mutex);

    pthread_mutex_destroy(&file_mutex);
    mysql_close(conn);
    close(listen_fd);
    close(epoll_fd);
    printf("服务器已关闭\n");
    return 0;
}