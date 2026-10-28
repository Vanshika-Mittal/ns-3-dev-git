/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Wenying Dai <dwy927@gmail.com>
 *          Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

// This program simulates Accurate ECN test cases over a 4-node bottleneck topology:
//
//           1000 Mbps           Bottleneck (10/1 Mbps)         1000 Mbps
//  Sender -------------- R1 -------------------------- R2 -------------- Receiver
//              2ms                       10ms                      2ms
//
// Supported Test Cases:
//   Case 1: AccECN Normal Negotiation (AccECN <-> AccECN, 10 Mbps, 300 KB)
//   Case 2: AccECN Congestion & CE Marking (AccECN <-> AccECN, 1 Mbps, Unlimited data, aggressive RED)
//   Case 3: AccECN Fallback to Classic ECN (AccECN <-> ClassicEcn, 10 Mbps, 200 KB)
//   Case 4: AccECN Fallback to Non-ECN (AccECN <-> NoEcn, 10 Mbps, 200 KB)

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

#include <filesystem>
#include <iomanip>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpAccEcnExample");

// All the pcaps will be collected in a folder named accecn in the ns-3 root directory.
std::string dir = "accecn/";

static void
CwndTracer(uint32_t oldval, uint32_t newval)
{
    NS_LOG_INFO("At " << Simulator::Now().GetSeconds() << "s, cwnd: " << oldval << " -> " << newval);
}

static void
TraceSocketAccEcn(Ptr<Node> node)
{
    Config::ConnectWithoutContext("/NodeList/" + std::to_string(node->GetId()) +
                                      "/$ns3::TcpL4Protocol/SocketList/*/$ns3::TcpSocketBase/CongestionWindow",
                                   MakeCallback(&CwndTracer));
}

void
RunCase(uint32_t caseId,
        const std::string& tcpTypeId,
        bool enablePcap,
        const std::string& baseDir,
        bool enableOptions)
{
    std::string caseTitle;
    std::string caseDir;
    std::string bottleneckBw = "10Mbps";
    uint64_t maxBytes = 0;
    double stopTime = 5.0;

    TcpSocketBase::EcnMode_t senderEcnMode = TcpSocketBase::AccEcn;
    TcpSocketState::UseEcn_t senderUseEcn = TcpSocketState::On;

    TcpSocketBase::EcnMode_t receiverEcnMode = TcpSocketBase::AccEcn;
    TcpSocketState::UseEcn_t receiverUseEcn = TcpSocketState::On;

    bool redUseHardDrop = true;
    double redMinTh = 5;
    double redMaxTh = 15;
    double redQw = 0.002;

    switch (caseId)
    {
    case 1:
        caseTitle = "Case 1: AccECN Normal Negotiation";
        caseDir = "case1_accecn_normal";
        bottleneckBw = "10Mbps";
        maxBytes = 300000; // 300 KB
        stopTime = 5.0;
        receiverEcnMode = TcpSocketBase::AccEcn;
        receiverUseEcn = TcpSocketState::On;
        redMinTh = 5;
        redMaxTh = 15;
        redQw = 0.002;
        break;

    case 2:
        caseTitle = "Case 2: AccECN Congestion (CE Marking)";
        caseDir = "case2_accecn_congestion";
        bottleneckBw = "1Mbps"; // Slow bottleneck to force queue buildup
        maxBytes = 0;          // Unlimited data
        stopTime = 10.0;
        receiverEcnMode = TcpSocketBase::AccEcn;
        receiverUseEcn = TcpSocketState::On;
        redUseHardDrop = false; // No packet drops above MaxTh; mark all
        redMinTh = 1;
        redMaxTh = 5;
        redQw = 0.1;
        break;

    case 3:
        caseTitle = "Case 3: AccECN Fallback to Classic ECN (RFC 3168)";
        caseDir = "case3_classic_ecn_fallback";
        bottleneckBw = "10Mbps";
        maxBytes = 200000; // 200 KB
        stopTime = 5.0;
        receiverEcnMode = TcpSocketBase::ClassicEcn;
        receiverUseEcn = TcpSocketState::On;
        redMinTh = 5;
        redMaxTh = 15;
        redQw = 0.002;
        break;

    case 4:
        caseTitle = "Case 4: AccECN Fallback to Non-ECN";
        caseDir = "case4_no_ecn_fallback";
        bottleneckBw = "10Mbps";
        maxBytes = 200000; // 200 KB
        stopTime = 5.0;
        receiverEcnMode = TcpSocketBase::NoEcn;
        receiverUseEcn = TcpSocketState::Off;
        redMinTh = 5;
        redMaxTh = 15;
        redQw = 0.002;
        break;

    default:
        std::cerr << "Unknown case ID: " << caseId << "\n";
        return;
    }

    std::string pcapDir = baseDir + caseDir + "/pcap/";

    std::cout << "\n======================================================================\n";
    std::cout << " Running " << caseTitle << " ...\n";
    std::cout << "======================================================================\n";

    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       TypeIdValue(TypeId::LookupByName("ns3::" + tcpTypeId)));

    if (!enableOptions)
    {
        // Disable standard TCP options for clean header inspection
        Config::SetDefault("ns3::TcpSocketBase::Timestamp", BooleanValue(false));
        Config::SetDefault("ns3::TcpSocketBase::Sack", BooleanValue(false));
        Config::SetDefault("ns3::TcpSocketBase::WindowScaling", BooleanValue(false));
    }

    // Force packets to queue in the RED QueueDisc
    Config::SetDefault("ns3::DropTailQueue<Packet>::MaxSize", QueueSizeValue(QueueSize("1p")));

    // Receiver ECN defaults for listening socket
    Config::SetDefault("ns3::TcpSocketBase::EcnMode", EnumValue(receiverEcnMode));
    Config::SetDefault("ns3::TcpSocketBase::UseEcn", EnumValue(receiverUseEcn));

    NodeContainer nodes;
    nodes.Create(4);
    Ptr<Node> sender = nodes.Get(0);
    Ptr<Node> r1 = nodes.Get(1);
    Ptr<Node> r2 = nodes.Get(2);
    Ptr<Node> receiver = nodes.Get(3);

    PointToPointHelper accessLink;
    accessLink.SetDeviceAttribute("DataRate", StringValue("1000Mbps"));
    accessLink.SetChannelAttribute("Delay", StringValue("2ms"));

    PointToPointHelper bottleneckLink;
    bottleneckLink.SetDeviceAttribute("DataRate", StringValue(bottleneckBw));
    bottleneckLink.SetChannelAttribute("Delay", StringValue("10ms"));

    NetDeviceContainer d0d1 = accessLink.Install(sender, r1);
    NetDeviceContainer d1d2 = bottleneckLink.Install(r1, r2);
    NetDeviceContainer d2d3 = accessLink.Install(r2, receiver);

    InternetStackHelper stack;
    stack.Install(nodes);

    // Install RED queue discipline with ECN on bottleneck
    TrafficControlHelper tchRed;
    tchRed.SetRootQueueDisc("ns3::RedQueueDisc",
                            "UseEcn",
                            BooleanValue(true),
                            "UseHardDrop",
                            BooleanValue(redUseHardDrop),
                            "LinkBandwidth",
                            DataRateValue(DataRate(bottleneckBw)),
                            "LinkDelay",
                            TimeValue(MilliSeconds(10)),
                            "MinTh",
                            DoubleValue(redMinTh),
                            "MaxTh",
                            DoubleValue(redMaxTh),
                            "QW",
                            DoubleValue(redQw),
                            "MaxSize",
                            StringValue("100p"));
    tchRed.Install(d1d2);

    if (enablePcap)
    {
        ns3::SystemPath::MakeDirectories(pcapDir);
        bottleneckLink.EnablePcapAll(pcapDir + "tcp-accecn");
    }

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = address.Assign(d0d1);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i2 = address.Assign(d1d2);

    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i3 = address.Assign(d2d3);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    uint16_t port = 50000;
    Address sinkAddress(InetSocketAddress(i2i3.GetAddress(1), port));
    PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory",
                                     InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApps = packetSinkHelper.Install(receiver);
    sinkApps.Start(Seconds(0.0));
    sinkApps.Stop(Seconds(stopTime));

    // Configure Sender ECN mode for the sending socket
    Config::SetDefault("ns3::TcpSocketBase::EcnMode", EnumValue(senderEcnMode));
    Config::SetDefault("ns3::TcpSocketBase::UseEcn", EnumValue(senderUseEcn));

    BulkSendHelper source("ns3::TcpSocketFactory", sinkAddress);
    source.SetAttribute("MaxBytes", UintegerValue(maxBytes));
    ApplicationContainer sourceApps = source.Install(sender);
    sourceApps.Start(Seconds(1.0));
    sourceApps.Stop(Seconds(stopTime));

    // Ensure sockets get the exact designated ECN mode
    Simulator::Schedule(Seconds(0.001), [sinkApps, receiverEcnMode, receiverUseEcn]() {
        Ptr<PacketSink> sink = DynamicCast<PacketSink>(sinkApps.Get(0));
        if (sink && sink->GetListeningSocket())
        {
            Ptr<TcpSocketBase> tcp = DynamicCast<TcpSocketBase>(sink->GetListeningSocket());
            if (tcp)
            {
                tcp->SetEcnMode(receiverEcnMode);
                tcp->SetUseEcn(receiverUseEcn);
            }
        }
    });

    Simulator::Schedule(Seconds(1.0001), [sourceApps, senderEcnMode, senderUseEcn]() {
        Ptr<BulkSendApplication> bulk = DynamicCast<BulkSendApplication>(sourceApps.Get(0));
        if (bulk && bulk->GetSocket())
        {
            Ptr<TcpSocketBase> tcp = DynamicCast<TcpSocketBase>(bulk->GetSocket());
            if (tcp)
            {
                tcp->SetEcnMode(senderEcnMode);
                tcp->SetUseEcn(senderUseEcn);
            }
        }
    });

    Simulator::Schedule(Seconds(1.0001), &TraceSocketAccEcn, sender);

    Simulator::Stop(Seconds(stopTime));
    Simulator::Run();

    Ptr<PacketSink> sink = DynamicCast<PacketSink>(sinkApps.Get(0));
    std::cout << " Simulation Complete:\n";
    std::cout << "  - Total Bytes Received: " << sink->GetTotalRx() << " bytes\n";
    std::cout << "  - Goodput:              "
              << (sink->GetTotalRx() * 8.0) / ((stopTime - 1.0) * 1e6) << " Mbps\n";
    if (enablePcap)
    {
        std::cout << "  - PCAP Files Saved in:  " << pcapDir << "\n";
    }

    Simulator::Destroy();
}

int
main(int argc, char* argv[])
{
    std::string tcpTypeId = "TcpCubic";
    uint32_t testCase = 0; // 0 means run ALL 4 cases, 1..4 runs a specific case
    bool enablePcap = true;
    bool enableOptions = false; // By default without standard options (Timestamp, SACK, WinScale)

    time_t rawtime;
    struct tm* timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y-%I-%M-%S", timeinfo);
    std::string currentTime(buffer);

    dir += (currentTime + "/");

    CommandLine cmd(__FILE__);
    cmd.AddValue("tcpTypeId", "TCP variant to use (e.g. TcpCubic, TcpLinuxReno)", tcpTypeId);
    cmd.AddValue("testCase", "Test case to run (1..4, or 0 for ALL cases)", testCase);
    cmd.AddValue("pcap", "Enable PCAP packet capture", enablePcap);
    cmd.AddValue("enableOptions",
                 "Enable standard TCP options (Timestamp, SACK, WinScale)",
                 enableOptions);
    cmd.AddValue("dir", "Base directory for PCAP traces", dir);
    cmd.Parse(argc, argv);

    if (testCase == 0)
    {
        std::cout << "\n======================================================================\n";
        std::cout << " RUNNING ALL 4 ACCECN TEST CASES\n";
        std::cout << "======================================================================\n";
        for (uint32_t c = 1; c <= 4; ++c)
        {
            RunCase(c, tcpTypeId, enablePcap, dir, enableOptions);
        }
    }
    else
    {
        RunCase(testCase, tcpTypeId, enablePcap, dir, enableOptions);
    }

    return 0;
}
