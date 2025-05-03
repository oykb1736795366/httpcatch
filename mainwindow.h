#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QDateTime>
#include <QMainWindow>
#include <QStandardItemModel>
#include <QThread>
#include <pcap.h>

// 在MainWindow.h文件开头添加
#pragma pack(push, 1)
struct ip {
    u_char  ip_vhl;     // 版本 + 头部长度
    u_char  ip_tos;     // 服务类型
    u_short ip_len;     // 总长度
    u_short ip_id;      // 标识
    u_short ip_off;     // 分片偏移
    u_char  ip_ttl;     // 生存时间
    u_char  ip_p;       // 协议类型
    u_short ip_sum;     // 校验和
    struct  in_addr ip_src;
    struct  in_addr ip_dst;
};
#pragma pack(pop)

#pragma pack(push, 1)  // 确保1字节对齐
struct ether_header {
    u_char  ether_dhost[6];  // 目标MAC地址
    u_char  ether_shost[6];  // 源MAC地址
    u_short ether_type;      // 协议类型
};
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE
// 在结构体定义之后添加
#define ETHERTYPE_IP   0x0800  // IPv4
#define ETHERTYPE_ARP  0x0806  // ARP
#define ETHERTYPE_IPV6 0x86DD  // IPv6
class CaptureThread;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_saveButton_clicked();
    void on_clearButton_clicked();
    void addPacketToModel(const QString& time, const QString& src,
        const QString& dst, const QString& protocol, int length);

private:
    Ui::MainWindow* ui;
    QStandardItemModel* packetModel;
    pcap_t* handle;
    QStringList capturedPackets;
    CaptureThread* captureThread;

    void initPacketModel();
    void enumerateDevices();
    void startCapture();
    void stopCapture();
    QString getProtocolName(int protocol);
    QString formatMacAddress(const u_char* mac);
    QString formatIpAddress(const u_char* ip);
};

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    explicit CaptureThread(pcap_t* handle, QObject* parent = nullptr)
        : QThread(parent), handle(handle), stopped(false) {}

    void stop() { stopped = true; }

signals:
    void packetCaptured(const QString& time, const QString& src,
        const QString& dst, const QString& protocol, int length);

protected:
    void run() override {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res;

        while (!stopped && (res = pcap_next_ex(handle, &header, &packet)) >= 0) {
            if (res == 0) continue;

            QString src, dst, protocol;
            int length = header->len;
            QString time = QDateTime::fromMSecsSinceEpoch(
                (header->ts.tv_sec * 1000) + (header->ts.tv_usec / 1000))
                .toString("hh:mm:ss.zzz");

            // 解析以太网头
            const struct ether_header* eth = (struct ether_header*)packet;
            u_short eth_type = ntohs(eth->ether_type);

            // 处理IPv4数据包
            if (eth_type == 0x0800) {
                const struct ip* iph = (struct ip*)(packet + sizeof(ether_header));

                // 修改MainWindow.h中的IP地址解析部分
                char srcIp[INET_ADDRSTRLEN];
                char dstIp[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(iph->ip_src), srcIp, INET_ADDRSTRLEN);  // 添加AF_INET参数
                inet_ntop(AF_INET, &(iph->ip_dst), dstIp, INET_ADDRSTRLEN);

                src = srcIp;
                dst = dstIp;
                protocol = getIpProtocol(iph->ip_p);
            }
            // 处理ARP数据包
            else if (eth_type == 0x0806) {
                src = formatMacAddress(eth->ether_shost);
                dst = formatMacAddress(eth->ether_dhost);
                protocol = "ARP";
            }
            // 其他类型处理
            else {
                src = formatMacAddress(eth->ether_shost);
                dst = formatMacAddress(eth->ether_dhost);
                protocol = QString("0x%1").arg(eth_type, 4, 16, QLatin1Char('0'));
            }

            emit packetCaptured(time, src, dst, protocol, length);
        }

        if (res == -1) {
            qDebug() << "Error:" << pcap_geterr(handle);
        }
    }

private:
    QString getIpProtocol(u_char proto) {
        switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return QString::number(proto);
        }
    }

    QString formatMacAddress(const u_char* mac) {
        return QString("%1:%2:%3:%4:%5:%6")
            .arg(mac[0], 2, 16, QLatin1Char('0'))
            .arg(mac[1], 2, 16, QLatin1Char('0'))
            .arg(mac[2], 2, 16, QLatin1Char('0'))
            .arg(mac[3], 2, 16, QLatin1Char('0'))
            .arg(mac[4], 2, 16, QLatin1Char('0'))
            .arg(mac[5], 2, 16, QLatin1Char('0'));
    }

    pcap_t* handle;
    bool stopped;
};

#endif // MAINWINDOW_H