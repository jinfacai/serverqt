#include <stdio.h>
#include <stdlib.h>   
#include <string.h> 
#include <stdint.h>   //uint8
#include <errno.h>  
#include <fcntl.h>   
#include <mysql/mysql.h> 
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <byteswap.h> // 用于 bswap_64

//常量定义
#define MAX_EVENTS 1024 //epoll一次最多处理的事件数
#define MAX_CLIENTS 100 //最大客户端连接数
#define BUFFER_SIZE 4096 //通用缓存区大小
#define MY_PROTOCOOL_VERSION 1 //当前协议版本
#define MAX_FILENAME_LEN 256  //最大文件名长度

//消息类型
#define MSG_TYPE_TEXT 1 //文本消息
#define MSG_TYPE_FILE 2 //文件消息
#pragma pack(push, 1)
//文件头
typedef struct {
    uint8_t  version;//1字节
    uint8_t  msg_type;//1字节
    uint32_t filename_len;//4字节 文件名长度
    uint64_t file_size;//8字节 整个文件大小
    uint64_t text_size;//8字节 文本消息大小
}FileHeader;//(14)

//协议包头
typedef struct {
    uint32_t data_len;//4字节 当前数据包长度
    uint64_t sSum;//8字节
} PacketHeader;//(12)
#pragma pack(pop)      // 恢复默认对齐方式
//客户端连接信息
typedef struct {
    int socket;
    int id;
    char current_filename[MAX_FILENAME_LEN];//当前文件名
    int file_fd;
} Client;

static char sendbuffer[BUFFER_SIZE];
static char recvbuffer[BUFFER_SIZE];

//网络字节序
// 主机字节序 -> 网络字节序 (64位)
#include <stdint.h>
#include <arpa/inet.h>

// 判断系统是否为小端字节序
static inline int is_little_endian() {
    static const uint16_t test = 0x0102;
    return (*(const uint8_t*)&test) == 0x02;
}

// 64位字节交换函数
static inline uint64_t bswap64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(x);
#else
    return ((x & 0x00000000000000FFULL) << 56) |
        ((x & 0x000000000000FF00ULL) << 40) |
        ((x & 0x0000000000FF0000ULL) << 24) |
        ((x & 0x00000000FF000000ULL) << 8) |
        ((x & 0x000000FF00000000ULL) >> 8) |
        ((x & 0x0000FF0000000000ULL) >> 24) |
        ((x & 0x00FF000000000000ULL) >> 40) |
        ((x & 0xFF00000000000000ULL) >> 56);
#endif
}

// 主机字节序 -> 网络字节序 (64位)
uint64_t htonll(uint64_t value) {
    if (is_little_endian()) {
        return bswap64(value);
    }
    return value;
}

// 网络字节序 -> 主机字节序 (64位)
uint64_t ntohll(uint64_t value) {
    return htonll(value); // 对称操作
}

//错误处理函数
void error_exit(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

//设置文件为非阻塞模式 
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL); //F_GETFL获取文件标识符
    if (flags == -1) error_exit("fcntl(F_GETFL)");
    flags |= O_NONBLOCK; //设置非阻塞 异步
    if (fcntl(fd, F_SETFL, flags) == -1) error_exit("fcntl(F_SETFL)");//F_SETFL 设置文件标识符
}

// 生成唯一ID并插入客户端信息（带事务保护）
bool insert_client_with_id(MYSQL* conn, const char* ip, int port, int* client_id) {
    char escaped_ip[BUFFER_SIZE] = { 0 };
    // 转义 IP 地址
    mysql_real_escape_string(conn, escaped_ip, ip, strlen(ip));

    // 开启事务
    if (mysql_query(conn, "START TRANSACTION") != 0) {
        fprintf(stderr, "开启事务失败: %s\n", mysql_error(conn));
        return false;
    }

    // 构建并执行插入语句
    char query[BUFFER_SIZE] = { 0 };
    snprintf(query, sizeof(query), "INSERT INTO clients (ip, port) VALUES ('%s', %d)", escaped_ip, port);
    if (mysql_query(conn, query) != 0) {
        fprintf(stderr, "插入失败: %s\n", mysql_error(conn));
        if (mysql_query(conn, "ROLLBACK") != 0) {
            fprintf(stderr, "回滚失败: %s\n", mysql_error(conn));
        }
        return false;
    }

    // 获取数据库自动生成的自增 ID
    *client_id = mysql_insert_id(conn);

    // 提交事务
    if (mysql_query(conn, "COMMIT") != 0) {
        fprintf(stderr, "提交事务失败: %s\n", mysql_error(conn));
        return false;
    }

    return true;
}

// 计算校验和
uint64_t calculate_checksum(const char* data, size_t len) {
    uint64_t sum = 0;

    for (size_t i = 0; i < len; i++) {
        sum += (uint8_t)data[i];  // 将每个字节转换为无符号8位整数并累加
    }

    return sum;
}
//文本广播发送
void broadcast_text_message(Client clients[], int sender_fd, uint8_t msgtype,
    uint64_t txsize, const char* txdata, uint32_t dtlen, uint64_t checksum)
{
    //计算数据包长度
    PacketHeader packetheader = {
     .data_len = htonl(dtlen),
     .sSum = 0 // 校验和
    };

    //封装数据包转发出去
    size_t totalsize = sizeof(packetheader) + dtlen;
    memcpy(sendbuffer, &packetheader, sizeof(packetheader));
    memcpy(sendbuffer + sizeof(packetheader), txdata, dtlen);
    //校验和
    uint64_t checksum_calculated = calculate_checksum(sendbuffer, totalsize);
    // 更新包头中的校验和字段（转换为大端序）
    packetheader.sSum = htonll(checksum_calculated);

    // 将更新后的包头（包含正确校验和）重新拷贝到发送缓冲区
    memcpy(sendbuffer, &packetheader, sizeof(packetheader));
    if (checksum_calculated != checksum) {
        fprintf(stderr, "校验和不匹配: 计算值=%" PRIu64 ", 接收值=%" PRIu64 "\n", checksum_calculated, checksum);
        return; // 处理错误
    }
    //广播消息到所有客户端
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) {//连接成功
            continue;//无效客户端    
        }
        else {
            if (send(clients[i].socket, sendbuffer, totalsize, 0) <= 0) {
                fprintf(stderr, "发送失败到客户端 %d (fd=%d): %s\n", i, clients[i].socket, strerror(errno));
            }
            else {
                //记录成功广播的消息信息
                printf("已广播消息到客户端 %d (fd=%d): type=%u, data_len=%zu", i, clients[i].socket, msgtype, dtlen);
                printf("\n");
            }
        }
    }

}

//文本处理
void handle_text_message(Client clients[], int client_fd, uint8_t type, uint64_t size) {
    //接收文本消息
    char buffer[BUFFER_SIZE];
    //定义数据包总大小
    uint64_t totalsize = sizeof(PacketHeader) + size;
    //如果数据包大小超过缓冲区大小，则分多次接收
    if (totalsize >= BUFFER_SIZE) {
        ssize_t currentsize = 0;
        ssize_t buffersize = BUFFER_SIZE;
        while (currentsize < totalsize) {
            ssize_t recvsize = recv(client_fd, buffer, buffersize, 0);
            if (recvsize < 0) {
                perror("recv failed");  // 会输出具体错误原因
                return;
            }
            if (recvsize != buffersize) {
                fprintf(stderr, "接收数据失败: %s\n", strerror(errno));
                return; // 处理错误
            }
            if (recvsize == 0) {
                fprintf(stderr, "连接已关闭: %s\n", strerror(errno));
                return; // 处理错误
            }
            //当前数据包数据总长度
            uint32_t datalen = *(uint32_t*)buffer;
            datalen = ntohl(datalen); // 转换为主机字节序
            //uint64_t textsum = *(uint64_t*)buffer + 4;
            //textsum = ntohll(textsum); // 转换为主机字节序
            uint64_t textsum = 0;
            memcpy(&textsum, buffer + 4, sizeof(uint64_t));  // 从 buffer 的偏移 4 开始取 8 字节
            textsum = ntohll(textsum);                       // 转换为主机字节序

            char data[BUFFER_SIZE];
            memcpy(data, buffer + 4 + 8, datalen);
            //广播文本消息
            broadcast_text_message(clients, client_fd, type, size, data, datalen, textsum);
            //计算剩余数据包大小 
            uint64_t resize = size - datalen;
            //如果剩余数据包大小超过缓冲区大小，则继续使用缓冲区大小
            // 否则使用剩余数据包大小加上包头大小
            if (resize > BUFFER_SIZE - sizeof(PacketHeader)) {
                buffersize = BUFFER_SIZE;
            }
            else {
                buffersize = resize + sizeof(PacketHeader);
            }
            currentsize += datalen;
        }
    }
    else {
        ssize_t buffersize = totalsize;
        ssize_t recvsize = recv(client_fd, buffer, buffersize, 0);
        //ssize_t recvsize = recv(client_fd, buffer, buffersize, 0);
        if (recvsize <= 0) {
            perror("recv failed or connection closed");
            //close(client_fd);  // 可选：关闭客户端连接
            return;  // 或直接退出该函数
        }
        if (recvsize < 12) {  // 至少需要 4字节长度 + 8字节校验和
            fprintf(stderr, "incomplete packet received\n");
            return;
        }
        //PacketHeader* header = (PacketHeader*)buffer;
        //uint32_t datalen = ntohl(header->data_len);  // 整个数据包长度
        //uint64_t textsum = ntohll(header->sSum);             // 校验和
        uint32_t datalen = *(uint32_t*)buffer;
        datalen = ntohl(datalen); // 转换为主机字节序
        uint64_t textsum = 0;
        memcpy(&textsum, buffer + 4, sizeof(uint64_t));  // 从 buffer 的偏移 4 开始取 8 字节
        textsum = ntohll(textsum);                    
        char data[buffersize];
        //uint64_t txtdata = *(uint64_t*)buffer + 4 + 8;
        //txtdata = ntohll(txtdata); // 转换为主机字节序
        memcpy(data, buffer + 4 + 8, datalen);
        broadcast_text_message(clients, client_fd, type, size, data, datalen, textsum);

    }
}

//文件广播发送
void broadcast_file_message(Client clients[], int sender_fd, uint8_t msgtype, const void* flname, uint32_t flen,
    uint64_t flsize, const char* fldata, uint32_t dtlen, uint64_t checksum) {

    PacketHeader packetheader = {
        .data_len = htonl(dtlen),
        .sSum = 0 // 校验和
    };
    //封装数据包转发出去
    size_t totalsize = sizeof(packetheader) + flen + dtlen;
    memcpy(sendbuffer, &packetheader, sizeof(packetheader));
    memcpy(sendbuffer + sizeof(packetheader), flname, flen);
    memcpy(sendbuffer + flen + sizeof(packetheader), fldata, dtlen);
    //校验和
    uint64_t checksum_calculated = calculate_checksum(sendbuffer, totalsize);
    packetheader.sSum = htonll(checksum_calculated);
    // 将更新后的包头（包含正确校验和）重新拷贝到发送缓冲区
    memcpy(sendbuffer, &packetheader, sizeof(packetheader));

    if (checksum_calculated != checksum) {
        fprintf(stderr, "校验和不匹配: 计算值=%" PRIu64 ", 接收值=%" PRIu64 "\n", checksum_calculated, packetheader.sSum);
        return; // 处理错误
    }
    //广播消息到所有客户端
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) {//连接成功
            continue;//无效客户端    
        }
        else {
            if (send(clients[i].socket, sendbuffer, totalsize, 0) <= 0) {
                fprintf(stderr, "发送失败到客户端 %d (fd=%d): %s\n", i, clients[i].socket, strerror(errno));
            }
            else {
                //记录成功广播的消息信息
                printf("已广播消息到客户端 %d (fd=%d): type=%u, data_len=%zu", i, clients[i].socket, msgtype, dtlen);
                printf("\n");
            }
        }

    }
}


//文件处理
void handle_file_message(Client clients[], int client_fd, uint8_t type, uint32_t len, uint64_t size) {
    char buffer[BUFFER_SIZE];
    uint64_t totalsize = sizeof(PacketHeader) + len + size;
    uint64_t packfilesize = sizeof(PacketHeader) + len;
    if (totalsize >= BUFFER_SIZE) {
        ssize_t currentsize = 0;
        ssize_t buffersize = BUFFER_SIZE;
        while (currentsize < totalsize) {
            ssize_t recvsize = recv(client_fd, buffer, buffersize, 0);
            if (recvsize != buffersize) {
                //报错
                fprintf(stderr, "接收数据失败: %s\n", strerror(errno));
            }
            if (recvsize == 0) {
                //报错
                fprintf(stderr, "连接已关闭: %s\n", strerror(errno));
            }
            PacketHeader* header = (PacketHeader*)buffer;

            uint32_t datalen = *(uint32_t*)buffer;
            datalen = ntohl(datalen); // 转换为主机字节序
            uint64_t filesum = 0;
            memcpy(&filesum, buffer + 4, sizeof(uint64_t));  // 从 buffer 的偏移 4 开始取 8 字节
            filesum = ntohll(filesum);
            //uint32_t datalen = ntohl(header->data_len);  // 整个数据包长度
            //uint64_t filesum = ntohll(header->sSum);             // 校验和exit
            char filename[MAX_FILENAME_LEN];
            memcpy(filename, buffer + 4 + 8, len);
            //filename[len] = '\0'; // 强制终止字符串
            char data[BUFFER_SIZE];
            memcpy(data, buffer + 4 + 8 + len, datalen);
            broadcast_file_message(clients, client_fd, type, filename, len, size, data, datalen, filesum);
            uint64_t resize = size - datalen;
            if (resize > BUFFER_SIZE - packfilesize) {
                buffersize = BUFFER_SIZE;
            }
            else {
                buffersize = resize + packfilesize;
            }
            currentsize += datalen;
        }
    }
    else {
        ssize_t buffersize = totalsize;
        ssize_t recvsize = recv(client_fd, buffer, buffersize, 0);
        if (recvsize < 0) {
            // 处理接收错误
            perror("recv failed");
            return;
        }
        else if (recvsize == 0) {
            // 连接关闭
            perror("socket closed");
            return;
        }
        uint32_t datalen = *(uint32_t*)buffer;
        datalen = ntohl(datalen); // 转换为主机字节序
        //uint64_t filesum = *(uint64_t*)buffer + 4;
        //filesum = ntohll(filesum); // 转换为主机字节序
        uint64_t filesum = 0;
        memcpy(&filesum, buffer + 4, sizeof(uint64_t));  // 从 buffer 的偏移 4 开始取 8 字节
        filesum = ntohll(filesum);
        char filename[MAX_FILENAME_LEN];
        memcpy(filename, buffer + 4 + 8, len);
        char data[BUFFER_SIZE];
        memcpy(data, buffer + 4 + 8 + len, datalen);
        broadcast_file_message(clients, client_fd, type, filename, len, size, data, datalen, filesum);

    }

}

//主函数
int main() {
    //创建mysql
    MYSQL* conn = mysql_init(NULL);

    if (!conn || !mysql_real_connect(conn, "127.0.0.1", "root", "1228", "server", 0, NULL, 0)) {
        fprintf(stderr, "MySQL init/connect failed: %s\n", mysql_error(conn));
        exit(EXIT_FAILURE);
    }
    //创建用于记录客户端 IP 和端口的表
    if (mysql_query(conn, "DROP TABLE IF EXISTS clients") != 0) {
        fprintf(stderr, "删除旧表失败: %s\n", mysql_error(conn));
    }

    // 创建新表（确保id字段自增）
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

    // 解析命令行参数获取端口号
    int port = 8888; // 默认端口
    char port_str[BUFFER_SIZE] = { 0 };
    printf("请输入服务器端口号（默认8888，直接回车使用默认值）: ");
    fflush(stdout);
    if (fgets(port_str, sizeof(port_str), stdin)) {
        char* newline = strchr(port_str, '\n');
        if (newline) *newline = '\0';  // 去掉换行符

        if (port_str[0] != '\0') {
            int input_port = atoi(port_str);
            if (input_port >= 0 && input_port <= 65535) {
                port = input_port;
            }
            else {
                fprintf(stderr, "错误：端口号必须在1024-65535之间，使用默认端口8888\n");
            }
        }
    }
    printf("服务器启动，监听端口 %d\n", port);
    printf("输入 'exit' 退出服务器\n");

    // 初始化客户端数组
    Client clients[MAX_CLIENTS] = { 0 };
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;//未连接
        clients[i].id = 0;
    }

    // 创建监听Socket TCP
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) error_exit("socket创建失败");

    // 设置端口复用
    // 防止服务无法重启或并发性能受限的问题
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)//SO_REUSEADDR允许重用本地地址（IP + 端口）
        error_exit("setsockopt失败");
    struct sockaddr_in server_addr;//存储服务端的地址信息（IP + 端口）
    memset(&server_addr, 0, sizeof(server_addr));//初始化为0
    server_addr.sin_family = AF_INET;//ipv4
    server_addr.sin_addr.s_addr = INADDR_ANY;//接受所有网卡上的ip地址
    server_addr.sin_port = htons(port);//网络字节序（大端）port
    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error_exit("bind失败");
    if (listen(listen_fd, MAX_CLIENTS) < 0)
        error_exit("listen失败");
    set_nonblocking(listen_fd);//非阻塞

    // 初始化epoll
    int epoll_fd = epoll_create1(0);//失败返回-1
    if (epoll_fd < 0) error_exit("epoll_create失败");
    //event：配置某个 fd 的监听事件
    //events：保存 epoll_wait 返回的多个就绪事件
    struct epoll_event event, events[MAX_EVENTS];
    //监听服务器的 监听套接字 listen_fd
    event.events = EPOLLIN | EPOLLET;//可读、边缘触发
    event.data.fd = listen_fd;//监听socket
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) < 0)
        error_exit("epoll_ctl添加监听socket失败");

    // 添加标准输入到epoll监控（用于处理exit命令）
    event.data.fd = STDIN_FILENO;//fd字段设置为标准输入的文件描述符
    event.events = EPOLLIN | EPOLLET;//可读、边缘触发
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) < 0)//监听event
        error_exit("epoll_ctl添加标准输入失败");

    char exit_cmd[BUFFER_SIZE] = { 0 };
    int should_exit = 0;

    while (!should_exit) {
        int n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        //用于等待 I/O 事件的发生,返回就绪事件的数量
        if (n_events < 0) {
            if (errno == EINTR) continue;
            error_exit("epoll_wait失败");
        }

        for (int i = 0; i < n_events; i++) {
            int fd = events[i].data.fd;

            // 处理终端输入（退出命令）
            if (fd == STDIN_FILENO) {
                ssize_t read_size = read(STDIN_FILENO, exit_cmd, sizeof(exit_cmd));
                if (read_size > 0 && strstr(exit_cmd, "exit\n") != NULL) {
                    printf("接收到退出命令，关闭服务器\n");
                    should_exit = 1; // 设置退出标志
                    break; // 跳出事件循环，准备退出
                }
                memset(exit_cmd, 0, sizeof(exit_cmd)); // 清空缓冲区
            }

            // 处理新客户端连接
            else if (fd == listen_fd) {
                struct sockaddr_in client_addr;//存储客户端
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_fd,
                    (struct sockaddr*)&client_addr, &client_len);//接受并返回客户端socket描述符
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

                set_nonblocking(client_fd);//非阻塞
                char client_ip[INET_ADDRSTRLEN];//存储 IPv4 地址
                //客户端的 IPv4地址（二进制形式） 转换为 字符串形式，并存入 client_ip 中
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                int client_port = ntohs(client_addr.sin_port);//转成主机字节序port

                // 使用事务保护的方式插入客户端信息并获取ID
                int new_id = 0;
                if (insert_client_with_id(conn, client_ip, client_port, &new_id)) {
                    printf("新客户端连接: ID=%d IP=%s Port=%d\n", new_id, client_ip, client_port);
                    clients[client_idx].id = new_id; // 使用数据库生成的ID
                }
                else {
                    printf("客户端ID生成失败，拒绝连接: IP=%s Port=%d\n", client_ip, client_port);
                    close(client_fd);
                    continue;
                }
                clients[client_idx].socket = client_fd;
                //clients[client_idx].received_size = 0;

                // 添加到epoll监控
                event.data.fd = client_fd;
                event.events = EPOLLIN | EPOLLET;//可读、边缘触发
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
                    close(client_fd);
                    clients[client_idx].socket = -1;
                    error_exit("epoll_ctl添加客户端失败");
                }
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
                if (client_idx == -1) { close(fd); continue; }

                //uint32_t total_size = sizeof(PacketHeader) + filename_len + len;
                //ssize_t recv_totalsize = recv(fd, recvbuffer,)

                //char fileheader[BUFFER_SIZE];
                //ssize_t recv_size = recv(fd, fileheader, sizeof(FileHeader), 0);
                // ssize_t recv_size = recv(fd, buffer, filename_len, 0);
                // ssize_t recv_size = recv(fd, buffer, data_len, 0);
                // 使用结构体指针解析
                FileHeader header;  // 确保与发送方结构体定义一致
                ssize_t recv_size = recv(fd, &header, sizeof(FileHeader), 0);
                if (recv_size != sizeof(FileHeader)) {
                    fprintf(stderr, "文件包头接收不完整\n");
                    exit(1);
                }
                //uint64_t headerchecksum = calculate_checksum((char*)&header, sizeof(header));
                if (recv_size <= 0) {
                    // 客户端断开连接
                    printf("客户端%d断开连接（fd=%d）\n", client_idx + 1, fd);
                    close(fd);
                    clients[client_idx].socket = -1;
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    continue;
                }
                // uint8_t vsion = *(uint8_t*)fileheader;
                 //if (vsion != MY_PROTOCOOL_VERSION) {
                ///     //报错
                 //	fprintf(stderr, "不支持的协议版本: %d\n", vsion);
               //  }
                // uint8_t msgtype = *((uint8_t*)fileheader + 1);
               //  msgtype = ntohl(msgtype);
               //  if (msgtype != MSG_TYPE_TEXT && msgtype != MSG_TYPE_FILE) {
              //       //报错
             //		fprintf(stderr, "未知消息类型: %d\n", msgtype);
                // }
               //  uint32_t filenamelen = *((uint32_t*)fileheader + 1 + 1);
               //  if (msgtype == MSG_TYPE_FILE && filenamelen == 0) {
               //      //报错
             //		fprintf(stderr, "文件名长度为0，无法处理文件消息\n");
               //  }
              //   uint64_t filesize = *((uint64_t*)fileheader + 1 + 1 + 4);
              //   if (msgtype == MSG_TYPE_FILE && filesize == 0) {
                     //报错
             //		fprintf(stderr, "文件大小为0，无法处理文件消息\n");
              //   }
               //  uint64_t textsize = *((uint64_t*)fileheader + 1 + 1 + 4 + 8);
              //   if (msgtype == MSG_TYPE_TEXT && textsize == 0) {
              //       //报错
             //		fprintf(stderr, "文本消息大小为0，无法处理文本消息\n");

             //    }
                 // 检查版本
                if (header.version != MY_PROTOCOOL_VERSION) {
                    fprintf(stderr, "不支持的协议版本: %d\n", header.version);
                    // 处理错误...
                }

                // 转换多字节字段的字节序
                header.msg_type = header.msg_type;  // 单字节无需转换
                header.filename_len = ntohl(header.filename_len);
                header.file_size = ntohll(header.file_size);  // 64位转换
                header.text_size = ntohll(header.text_size);
                uint8_t msgtype = header.msg_type;
                uint32_t filenamelen = header.filename_len;
                uint64_t filesize = header.file_size;
                uint64_t textsize = header.text_size;


                // 校验消息类型
                if (header.msg_type != MSG_TYPE_TEXT && header.msg_type != MSG_TYPE_FILE) {
                    fprintf(stderr, "未知消息类型: %d\n", header.msg_type);
                    // 处理错误...
                }

                // 校验文件消息
                if (header.msg_type == MSG_TYPE_FILE) {
                    if (header.filename_len == 0) {
                        fprintf(stderr, "文件名长度为0\n");
                    }
                    if (header.file_size == 0) {
                        fprintf(stderr, "文件大小为0\n");
                    }
                }
                // 校验文本消息
                else if (header.msg_type == MSG_TYPE_TEXT) {
                    if (header.text_size == 0) {
                        fprintf(stderr, "文本大小为0\n");
                    }
                }

                // 发送时转换字节序
                FileHeader response = {
                    .version = MY_PROTOCOOL_VERSION,
                    .msg_type = header.msg_type,  // 单字节不转换
                    .filename_len = htonl(header.filename_len),
                    .file_size = htonll(header.file_size),  // 64位转换
                    .text_size = htonll(header.text_size)
                };
                //发送文件头
                if ((send(clients[i].socket, sendbuffer, sizeof(FileHeader), 0) <= 0)) {
                    //报错
                    fprintf(stderr, "发送文件头失败到客户端 %d (fd=%d): %s\n", client_idx, fd, strerror(errno));

                }


                switch (msgtype) {
                case MSG_TYPE_TEXT:
                    handle_text_message(clients, fd, msgtype, textsize);
                    break;
                case MSG_TYPE_FILE:
                    handle_file_message(clients, fd, msgtype, filenamelen, filesize);
                    break;
                default:
                    fprintf(stderr, "未知消息类型: %d\n", msgtype);
                    break;
                }
            }
        }
    }

    // 清理资源
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1) {
            close(clients[i].socket);
            clients[i].socket = -1;
        }
    }
    mysql_close(conn);
    close(listen_fd);
    close(epoll_fd);
    printf("服务器已关闭\n");
    return 0;
}