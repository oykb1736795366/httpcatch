#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QTextStream>
#include <ws2tcpip.h>
#include <pcap.h>
#include <QDebug>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")





MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , handle(nullptr)
    , captureThread(nullptr)
{
    ui->setupUi(this);

    // 初始化npcap
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::critical(this, "Error", "Npcap initialization failed: " + QString(errbuf));
        exit(1);
    }
    pcap_freealldevs(alldevs);

    packetModel = new QStandardItemModel(this);
    initPacketModel();
    enumerateDevices();
    ui->stopButton->setEnabled(false);
}

MainWindow::~MainWindow()
{
    stopCapture();
    delete ui;
}

void MainWindow::initPacketModel()
{
    packetModel->setColumnCount(6);
    packetModel->setHeaderData(0, Qt::Horizontal, tr("No."));
    packetModel->setHeaderData(1, Qt::Horizontal, tr("Time"));
    packetModel->setHeaderData(2, Qt::Horizontal, tr("Source"));
    packetModel->setHeaderData(3, Qt::Horizontal, tr("Destination"));
    packetModel->setHeaderData(4, Qt::Horizontal, tr("Protocol"));
    packetModel->setHeaderData(5, Qt::Horizontal, tr("Length"));
    ui->packetTableView->setModel(packetModel);
    ui->packetTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
}

void MainWindow::enumerateDevices()
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::warning(this, "Error", "Device enumeration failed: " + QString(errbuf));
        return;
    }

    ui->deviceComboBox->clear();
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        // 修改enumerateDevices()函数中的设备添加方式
        if (d->description) {
            // 将char*转换为QString
            ui->deviceComboBox->addItem(QString::fromLocal8Bit(d->description),
                QString::fromLocal8Bit(d->name));
        }
        else {
            ui->deviceComboBox->addItem(QString::fromLocal8Bit(d->name),
                QString::fromLocal8Bit(d->name));
        }
    }
    pcap_freealldevs(alldevs);
}

void MainWindow::startCapture()
{
    if (ui->deviceComboBox->currentIndex() == -1) {
        QMessageBox::warning(this, "Error", "Please select a network interface");
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    QString device = ui->deviceComboBox->currentData().toString();

    // 设置混杂模式
    handle = pcap_open_live(device.toUtf8().constData(), 65536, 1, 1000, errbuf);
    if (!handle) {
        QMessageBox::critical(this, "Error", "Open device failed: " + QString(errbuf));
        return;
    }

    // 检查数据链路类型
    if (pcap_datalink(handle) != DLT_EN10MB) {
        QMessageBox::warning(this, "Warning", "Non-Ethernet interface detected");
    }

    // 创建捕获线程
    captureThread = new CaptureThread(handle, this);
    connect(captureThread, &CaptureThread::packetCaptured,
        this, &MainWindow::addPacketToModel);
    captureThread->start();

    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
}

void MainWindow::stopCapture()
{
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
        captureThread = nullptr;
    }

    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }

    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}

void MainWindow::addPacketToModel(const QString& time, const QString& src,
    const QString& dst, const QString& protocol, int length)
{
    QList<QStandardItem*> items;
    items << new QStandardItem(QString::number(packetModel->rowCount() + 1))
        << new QStandardItem(time)
        << new QStandardItem(src)
        << new QStandardItem(dst)
        << new QStandardItem(protocol)
        << new QStandardItem(QString::number(length));

    packetModel->appendRow(items);

    // 保存原始数据包信息
    capturedPackets.append(QString("[%1] %2 > %3 %4 %5 bytes")
        .arg(time, src, dst, protocol).arg(length));
}

// ...其他按钮点击事件保持不变...

void MainWindow::on_startButton_clicked()
{
    startCapture();
}

void MainWindow::on_stopButton_clicked()
{
    stopCapture();
}

void MainWindow::on_saveButton_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Captured Packets"),
        "", tr("Text Files (*.txt);;All Files (*)"));
    if (fileName.isEmpty()) {
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Could not open file for writing"));
        return;
    }

    QTextStream out(&file);
    for (const QString& packet : capturedPackets) {
        out << packet << "\n";
    }

    file.close();
    QMessageBox::information(this, tr("Success"), tr("Packets saved successfully"));
}

void MainWindow::on_clearButton_clicked()
{
    packetModel->removeRows(0, packetModel->rowCount());
    capturedPackets.clear();
}

void MainWindow::startCapture()
{
    if (ui->deviceComboBox->currentIndex() == -1) {
        QMessageBox::warning(this, tr("Error"), tr("No network device selected"));
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::warning(this, tr("Error"), tr("Could not find any network devices: %1").arg(errbuf));
        return;
    }

    pcap_if_t* selectedDev = alldevs;
    for (int i = 0; i < ui->deviceComboBox->currentIndex(); i++) {
        selectedDev = selectedDev->next;
    }

    handle = pcap_open_live(selectedDev->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);

    if (handle == nullptr) {
        QMessageBox::warning(this, tr("Error"), tr("Could not open device: %1").arg(errbuf));
        return;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        QMessageBox::warning(this, tr("Error"), tr("This program only supports Ethernet networks"));
        pcap_close(handle);
        handle = nullptr;
        return;
    }

    // 创建并启动抓包线程
    captureThread = new CaptureThread(handle, this);
    connect(captureThread, &CaptureThread::packetCaptured,
        this, &MainWindow::addPacketToModel);
    captureThread->start();

    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
}

void MainWindow::stopCapture()
{
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
        captureThread = nullptr;
    }

    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }

    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}

void MainWindow::addPacketToModel(const QString& time, const QString& src,
    const QString& dst, const QString& protocol, int length)
{
    QList<QStandardItem*> rowItems;
    rowItems << new QStandardItem(QString::number(packetModel->rowCount() + 1));
    rowItems << new QStandardItem(time);
    rowItems << new QStandardItem(src);
    rowItems << new QStandardItem(dst);
    rowItems << new QStandardItem(protocol);
    rowItems << new QStandardItem(QString::number(length));

    packetModel->appendRow(rowItems);

    // 保存完整包信息
    QString packetInfo = QString("No: %1, Time: %2, Source: %3, Destination: %4, Protocol: %5, Length: %6")
        .arg(packetModel->rowCount())
        .arg(time)
        .arg(src)
        .arg(dst)
        .arg(protocol)
        .arg(length);
    capturedPackets.append(packetInfo);
}

QString MainWindow::getProtocolName(int protocol)
{
    switch (protocol) {
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_ICMP: return "ICMP";
    case ETHERTYPE_IP: return "IPv4";
    case ETHERTYPE_ARP: return "ARP";
    default: return QString::number(protocol);
    }
}

QString MainWindow::formatMacAddress(const u_char* mac)
{
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QLatin1Char('0'))
        .arg(mac[1], 2, 16, QLatin1Char('0'))
        .arg(mac[2], 2, 16, QLatin1Char('0'))
        .arg(mac[3], 2, 16, QLatin1Char('0'))
        .arg(mac[4], 2, 16, QLatin1Char('0'))
        .arg(mac[5], 2, 16, QLatin1Char('0'));
}

QString MainWindow::formatIpAddress(const u_char* ip)
{
    return QString("%1.%2.%3.%4")
        .arg(ip[0])
        .arg(ip[1])
        .arg(ip[2])
        .arg(ip[3]);
}