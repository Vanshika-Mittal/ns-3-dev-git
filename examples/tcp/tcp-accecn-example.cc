/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Wenying Dai <dwy927@gmail.com>
 *          Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

// This program simulates an Accurate ECN scenario over a bottleneck link:
//
//           1000 Mbps           10 Mbps          1000 Mbps
//  Sender -------------- R1 -------------- R2 -------------- Receiver
//              5ms               10ms               5ms
//
// The link between R1 and R2 is a bottleneck link with RED AQM configured to mark packets
// with ECN when the queue builds up.
//
// Accurate ECN (AccECN) provides byte-accurate, fine-grained congestion feedback
// by carrying a 3-bit ACE counter in the TCP header and tracing detailed byte counters
// (Cep, E0b, E1b, Ceb).

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpAccEcnExample");

static void
CwndTracer(uint32_t oldval, uint32_t newval)
{
    NS_LOG_INFO("At " << Simulator::Now().GetSeconds() << "s, cwnd changed: " << oldval << " -> "
                      << newval);
}

static void
TraceSocketAccEcn(Ptr<Node> node)
{
    Config::ConnectWithoutContext("/NodeList/" + std::to_string(node->GetId()) +
                                      "/$ns3::TcpL4Protocol/SocketList/*/$ns3::TcpSocketBase/CongestionWindow",
                                  MakeCallback(&CwndTracer));
}

int
main(int argc, char* argv[])
{
    std::string tcpTypeId = "TcpCubic";
    bool enableAccEcn = true;
    double stopTime = 10.0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("tcpTypeId", "TCP variant to use", tcpTypeId);
    cmd.AddValue("enableAccEcn", "Enable Accurate ECN on TCP sockets", enableAccEcn);
    cmd.AddValue("stopTime", "Stop time of the simulation (seconds)", stopTime);
    cmd.Parse(argc, argv);

    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       TypeIdValue(TypeId::LookupByName("ns3::" + tcpTypeId)));

    if (enableAccEcn)
    {
        Config::SetDefault("ns3::TcpSocketBase::EcnMode", EnumValue(TcpSocketBase::AccEcn));
        Config::SetDefault("ns3::TcpSocketBase::UseEcn", EnumValue(TcpSocketState::On));
    }

    NodeContainer nodes;
    nodes.Create(4);
    Ptr<Node> sender = nodes.Get(0);
    Ptr<Node> r1 = nodes.Get(1);
    Ptr<Node> r2 = nodes.Get(2);
    Ptr<Node> receiver = nodes.Get(3);

    PointToPointHelper accessLink;
    accessLink.SetDeviceAttribute("DataRate", StringValue("1000Mbps"));
    accessLink.SetChannelAttribute("Delay", StringValue("5ms"));

    PointToPointHelper bottleneckLink;
    bottleneckLink.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
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
                            "MinTh",
                            DoubleValue(5),
                            "MaxTh",
                            DoubleValue(15),
                            "MaxSize",
                            StringValue("100p"));
    tchRed.Install(d1d2);

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

    BulkSendHelper source("ns3::TcpSocketFactory", sinkAddress);
    source.SetAttribute("MaxBytes", UintegerValue(0));
    ApplicationContainer sourceApps = source.Install(sender);
    sourceApps.Start(Seconds(1.0));
    sourceApps.Stop(Seconds(stopTime));

    Simulator::Schedule(Seconds(1.0001), &TraceSocketAccEcn, sender);

    Simulator::Stop(Seconds(stopTime));
    Simulator::Run();

    Ptr<PacketSink> sink = DynamicCast<PacketSink>(sinkApps.Get(0));
    std::cout << "Accurate ECN Example Simulation Finished.\n";
    std::cout << "Total Bytes Received: " << sink->GetTotalRx() << " bytes\n";
    std::cout << "Goodput: " << (sink->GetTotalRx() * 8.0) / ((stopTime - 1.0) * 1e6) << " Mbps\n";

    Simulator::Destroy();
    return 0;
}
