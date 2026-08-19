/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Wenying Dai <dwy927@gmail.com>
 *          Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

// Network topology
//
//     500Mbps 2ms      1Mbps 20ms        500Mbps 2ms
// n0 -------------n1 -------------- n2-------------- n3
//
// The example providing to trace the counter of
// r.cep, r.e0b, r.ceb, r.e1b in AccEcn

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("AccEcnExample");

std::string dir = "AccEcnPlots/";

static void PrintE0bRCb (uint32_t oldval, uint32_t newval)
{
  std::ofstream fPlotQueue (dir + "Traces/e0bR.txt", std::ios::out | std::ios::app);
  fPlotQueue << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  fPlotQueue.close ();
}

static void PrintCebRCb (uint32_t oldval, uint32_t newval)
{
  std::ofstream fPlotQueue (dir + "Traces/cebR.txt", std::ios::out | std::ios::app);
  fPlotQueue << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  fPlotQueue.close ();
}

static void PrintCepRCb (uint32_t oldval, uint32_t newval)
{
  std::ofstream fPlotQueue (dir + "Traces/cepR.txt", std::ios::out | std::ios::app);
  fPlotQueue << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  fPlotQueue.close ();
}

static void PrintE0bSCb (uint32_t oldval, uint32_t newval)
{
  std::ofstream fPlotQueue (dir + "Traces/e0bS.txt", std::ios::out | std::ios::app);
  fPlotQueue << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  fPlotQueue.close ();
}

static void PrintCebSCb (uint32_t oldval, uint32_t newval)
{
  std::ofstream fPlotQueue (dir + "Traces/cebS.txt", std::ios::out | std::ios::app);
  fPlotQueue << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  fPlotQueue.close ();
}

static void PrintCepSCb (uint32_t oldval, uint32_t newval)
{
  std::ofstream fPlotQueue (dir + "Traces/cepS.txt", std::ios::out | std::ios::app);
  fPlotQueue << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  fPlotQueue.close ();
}

static void ConfigTracing ()
{
  Config::ConnectWithoutContext ("NodeList/0/$ns3::TcpL4Protocol/SocketList/0/AccEcnE0bS", MakeCallback (&PrintE0bSCb));
  Config::ConnectWithoutContext ("NodeList/0/$ns3::TcpL4Protocol/SocketList/0/AccEcnCebS", MakeCallback (&PrintCebSCb));
  Config::ConnectWithoutContext ("NodeList/0/$ns3::TcpL4Protocol/SocketList/0/AccEcnCepS", MakeCallback (&PrintCepSCb));

  Config::ConnectWithoutContext ("NodeList/3/$ns3::TcpL4Protocol/SocketList/0/AccEcnE0bR", MakeCallback (&PrintE0bRCb));
  Config::ConnectWithoutContext ("NodeList/3/$ns3::TcpL4Protocol/SocketList/0/AccEcnCebR", MakeCallback (&PrintCebRCb));
  Config::ConnectWithoutContext ("NodeList/3/$ns3::TcpL4Protocol/SocketList/0/AccEcnCepR", MakeCallback (&PrintCepRCb));
}

int main (int argc, char *argv[])
{
  char buffer[80];
  time_t rawtime;
  struct tm * timeinfo;
  time (&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(buffer,sizeof(buffer),"%d-%m-%Y-%I-%M-%S",timeinfo);
  std::string currentTime (buffer);
  CommandLine cmd;
  cmd.Parse (argc, argv);

  Time::SetResolution (Time::NS);

  std::string redLinkDataRate = "1Mbps";
  std::string redLinkDelay = "20ms";
  std::string EcnMode ="AccEcn";
  bool useEcn = true;
  uint32_t meanPktSize = 500;
  uint32_t maxBytes = 0;

  NS_LOG_INFO ("Create nodes.");
  NodeContainer c;
  c.Create(4);
  NodeContainer n0n1 = NodeContainer (c.Get (0), c.Get (1));
  NodeContainer n1n2 = NodeContainer (c.Get (1), c.Get (2));
  NodeContainer n2n3 = NodeContainer (c.Get (2), c.Get (3));

  NS_LOG_INFO ("Set default configurations.");
  Config::SetDefault ("ns3::RedQueueDisc::MaxSize", QueueSizeValue (QueueSize ("25p")));
  Config::SetDefault ("ns3::RedQueueDisc::MeanPktSize", UintegerValue (meanPktSize));
  Config::SetDefault ("ns3::RedQueueDisc::Wait", BooleanValue (true));
  Config::SetDefault ("ns3::RedQueueDisc::Gentle", BooleanValue (true));
  Config::SetDefault ("ns3::RedQueueDisc::QW", DoubleValue (0.002));
  Config::SetDefault ("ns3::RedQueueDisc::MinTh", DoubleValue (5));
  Config::SetDefault ("ns3::RedQueueDisc::MaxTh", DoubleValue (15));
  Config::SetDefault ("ns3::RedQueueDisc::UseEcn", BooleanValue (useEcn));
  Config::SetDefault ("ns3::TcpSocketBase::EcnMode", StringValue (EcnMode));


  NS_LOG_INFO ("Create channels.");
  PointToPointHelper p2p;

  p2p.SetDeviceAttribute ("DataRate", StringValue ("500Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));
  NetDeviceContainer devn0n1 = p2p.Install (n0n1);
  NetDeviceContainer devn2n3 = p2p.Install (n2n3);

  PointToPointHelper p2pRouter;
  p2pRouter.SetDeviceAttribute ("DataRate", StringValue (redLinkDataRate));
  p2pRouter.SetChannelAttribute ("Delay", StringValue (redLinkDelay));
  NetDeviceContainer devn1n2 = p2pRouter.Install (n1n2);

  NS_LOG_INFO ("Install internet stack.");
  InternetStackHelper internet;
  internet.Install (c);

  NS_LOG_INFO ("Install RED for bottle-neck path.");
  TrafficControlHelper tchRed;
  tchRed.SetRootQueueDisc ("ns3::RedQueueDisc", "LinkBandwidth", StringValue (redLinkDataRate),
                           "LinkDelay", StringValue (redLinkDelay));
  QueueDiscContainer queueDiscs;
  queueDiscs = tchRed.Install (devn1n2);

  NS_LOG_INFO("Assign IP Address.");
  Ipv4AddressHelper ipv4;

  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i1 = ipv4.Assign (devn0n1);

  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i2 = ipv4.Assign (devn1n2);

  ipv4.SetBase ("10.1.3.0", "255.255.255.0");
  Ipv4InterfaceContainer i2i3 = ipv4.Assign (devn2n3);

  NS_LOG_INFO("Set up routing.");
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  NS_LOG_INFO("Install Applications.");
  PacketSinkHelper sink ("ns3::TcpSocketFactory",InetSocketAddress(Ipv4Address::GetAny(),50000));
  ApplicationContainer sinkApp = sink.Install(c.Get(3));
  sinkApp.Start (Seconds (0.0));
  sinkApp.Stop (Seconds (100.0));


  BulkSendHelper clientHelper ("ns3::TcpSocketFactory", InetSocketAddress (i2i3.GetAddress (1), 50000));
  clientHelper.SetAttribute ("MaxBytes", UintegerValue (maxBytes));
  ApplicationContainer sourceApp = clientHelper.Install(c.Get(0));
  sourceApp.Start (Seconds (0.0));
  sourceApp.Stop (Seconds (100.0));

  dir += (currentTime + "/");
  std::string dirToSave = "mkdir -p " + dir;
  system (dirToSave.c_str ());
  system ((dirToSave + "/pcap/").c_str ());
  system ((dirToSave + "/Traces/").c_str ());
  p2p.EnablePcapAll (dir + "pcap/N", true);
  Simulator::Schedule (Seconds (0.01), &ConfigTracing);

  NS_LOG_INFO ("Run Simulation");
  Simulator::Stop (Seconds (100.0));
  Simulator::Run ();

  QueueDisc::Stats st = queueDiscs.Get (0)->GetStats ();
  std::cout << st << std::endl;

  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
  return 0;
}

