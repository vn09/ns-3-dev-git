//
// Created by Vuong Nguyen on 20/03/2017.
//
/*
 * This example program allows one to run ns-3 AODV under
 * a typical random waypoint mobility model.
 *
 * By default, the simulation runs for 200 simulated seconds, of which
 * the first 50 are used for start-up time.  The number of nodes is 50.
 * Nodes move according to RandomWaypointMobilityModel with a speed of
 * 20 m/s and no pause time within a 300x1500 m region.  The WiFi is
 * in ad hoc mode with a 2 Mb/s rate (802.11b) and a Friis loss model.
 * The transmit power is set to 7.5 dBm.
 *
 * It is possible to change the mobility and density of the network by
 * directly modifying the speed and the number of nodes.  It is also
 * possible to change the characteristics of the network by changing
 * the transmit power (as power increases, the impact of mobility
 * decreases and the effective density increases).
 *
 * By default, OLSR is used, but specifying a value of 2 for the protocol
 * will cause AODV to be used, and specifying a value of 3 will cause
 * DSDV to be used.
 *
 * By default, there are 10 source/sink data pairs sending UDP data
 * at an application rate of 2.048 Kb/s each. This is typically done
 * at a rate of 4 64-byte packets per second. Application data is
 * started at a random time between 50 and 51 seconds and continues
 * to the end of the simulation.
 *
 * The program outputs a few items:
 * - packet receptions are notified to stdout such as:
 *   <timestamp> <node-id> received one packet from <src-address>
 * - each second, the data reception statistics are tabulated and output
 *   to a comma-separated value (csv) file
 * - some tracing and flow monitor configuration that used to work is
 *   left commented inline in the program
 */

#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"

// RSA, Elgamal and ECC
#include "rsa.h"
#include "elgamal.h"
//#include "ecc.h"

using namespace ns3;
using namespace dsr;
using namespace std;

NS_LOG_COMPONENT_DEFINE ("aodv-experiment");

class RoutingExperiment {
public:
  RoutingExperiment();

  void Run(int nSinks, double txp, string CSVfileName);

  //static void SetMACParam (ns3::NetDeviceContainer & devices,
  //                                 int slotDistance);
  string CommandSetup(int argc, char **argv);

  // Input for testing
  string simplePlaintext = "The simple plaintext for MANETs";
  string mediumPlaintext = "7xSg7PNm7zTdGEGRhSzRg63KiUWtnUkXVGA8KadHTv3wnwh4Fbw3czCNwp3UDmq"
      "xEnfE9XuEQRBXbSLqjaPih5jYAzN9L47Qi5ZKSYpXwE8kMfkLn5yaBqxxgU4QCV"
      "wbib5PF5ULZQ7YHAc5h64BFuPZ4Sk2WcP4deUkaM8pvnvGEGBbuXtrcgfvQDc5hmhSgfDUrbxv";

  string longPlaintext = "8DY7uGGbiVLQSAWcPjUjVVmGELjZ2wGKWhjk597hTJM6uurQXKRayu4Nf38Rqaghm7HnEjhkZSkKS7d"
      "gdckSUBCwWYBKDBpugw5AMVzF83EQWfYwXc6HahUGyhXxpN5cKAhwFLF47JwBnJDpjuHydiXwJkHjSqA3E8ja4T"
      "CXZYPQi3HffHdHdNUpp3uWpcKYNHnLAWcN8h5kUxdrvbE9veaYkZvKUqEpRzeZda8XihiM5SwjLqYBRtd9WbXg8"
      "VVT9X22TkX5W5V4KLTBmx6PiMqPw8DrZ5zYjrvSipRc4wWa2c3gkMxjeKBvJ43LKmXc3q9w5NrPHD8ZhwNhWS8S"
      "EjXXVh7beA9EjtWPRVnQdhcWcgK3cn3dBvNGUdrTrN4hMhmFaTuwTYD3k4W756VcuLJg6MfGDw4YyeFgdGUZFKa"
      "BDUb9ivdpdxqrV89ncmyeMSZ2kg3SqCMt4q3aASL7nRpMMFjMMkYNBTxK9euM8VL59gup3BmL7TBeKaaXW39ggMW"
      "RvqGcyzA5nbdWqVqDv6brFWHzAFQvzjSATticktFz5YEueemwCfYNHSE9gLQft7HfmKN63xTrPNNmaPanT9Ni9qLa"
      "fGFiRWMzRXq3L3k685Y5h9JtACqkiiRvUgG9qUbzFKm3hBPRpK4LXEbPBEevcBw2UaUyk3g4Zq93QJi75P3Ve2QC8"
      "PHTrEUZtCguEBw8fnNaZCxx5Pw5HjzmPVNe6WmhhFexcdW83VRJhmrQLUj8JG479JAeE7VafCB9A3q3NK3znMYRwiT"
      "fPJyA4YghrWxx8GYWhx367WFPM7WqJCcvjbB9D3tknMgFkJ7h7PLE8Qt8FPGQaEpU9f62YpdfvWEbSXmwBiidChNd2"
      "i2uxSfBxJvJ3dAV6CKfJgn2yYGM9j3jt7fUWFiPqM4fYnzEbViZ3ipEgRqzGpMV49UEMLPztzvmdj9N62xm8vtNaeDP"
      "LFQYHZn7ftqYPEJcvNAq3VzWbBcfWAejhryR";

private:
  Ptr <Socket> SetupPacketReceive(Ipv4Address addr, Ptr <Node> node);

  void ReceivePacket(Ptr <Socket> socket);

  void CheckThroughput();

  uint32_t port;
  uint32_t bytesTotal;
  uint32_t packetsReceived;

  string m_CSVfileName;
  int m_nSinks;
  string m_protocolName;
  double m_txp;
  bool m_traceMobility;
  uint32_t m_protocol;
};

RoutingExperiment::RoutingExperiment()
    : port(9),
      bytesTotal(0),
      packetsReceived(0),
      m_CSVfileName("manet-routing.output.csv"),
      m_traceMobility(false),
      m_protocol(2) // AODV
{
}

static inline string
PrintReceivedPacket(Ptr <Socket> socket, Ptr <Packet> packet, Address senderAddress) {
  std::ostringstream oss;

  oss << Simulator::Now().GetSeconds() << " " << socket->GetNode()->GetId();

  if (InetSocketAddress::IsMatchingType(senderAddress)) {
    InetSocketAddress addr = InetSocketAddress::ConvertFrom(senderAddress);
    oss << " received one packet from " << addr.GetIpv4();
  } else {
    oss << " received one packet!";
  }
  return oss.str();
}

void
RoutingExperiment::ReceivePacket(Ptr <Socket> socket) {
  Ptr <Packet> packet;
  Address senderAddress;
  while ((packet = socket->RecvFrom(senderAddress))) {
    bytesTotal += packet->GetSize();
    packetsReceived += 1;
    NS_LOG_UNCOND(PrintReceivedPacket(socket, packet, senderAddress));
  }
}

void
RoutingExperiment::CheckThroughput() {
  double kbs = (bytesTotal * 8.0) / 1000;
  bytesTotal = 0;

  std::ofstream out(m_CSVfileName.c_str(), std::ios::app);

  out << (Simulator::Now()).GetSeconds() << ","
      << kbs << ","
      << packetsReceived << ","
      << m_nSinks << ","
      << m_protocolName << ","
      << m_txp << ""
      << std::endl;

  out.close();
  packetsReceived = 0;
  Simulator::Schedule(Seconds(1.0), &RoutingExperiment::CheckThroughput, this);
}

Ptr <Socket>
RoutingExperiment::SetupPacketReceive(Ipv4Address addr, Ptr <Node> node) {
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  Ptr <Socket> sink = Socket::CreateSocket(node, tid);
  InetSocketAddress local = InetSocketAddress(addr, port);
  sink->Bind(local);
  sink->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));

  return sink;
}

string
RoutingExperiment::CommandSetup(int argc, char **argv) {
  CommandLine cmd;
  cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
  cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
  cmd.AddValue("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol);
  cmd.Parse(argc, argv);
  return m_CSVfileName;
}

int
main(int argc, char *argv[]) {
  LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

  RoutingExperiment experiment;
  string CSVfileName = experiment.CommandSetup(argc, argv);

  RSA_AODV rsa_aodv(1024);
  string plainText = "Hello world";
  string cipherTextRSA = rsa_aodv.encrypt(plainText.data());
  string recoveredRSA = rsa_aodv.decrypt(cipherTextRSA.data());
  assert(recoveredRSA == plainText);
  cout << "Assert RSA successfully" << std::endl;

  ELGAMAL_AODV elgamal_aodv(1024);
  string cipherTextElgamal = elgamal_aodv.encrypt(plainText.data());
  string recoveredElgamal = elgamal_aodv.decrypt(cipherTextElgamal.data());
  assert(recoveredElgamal == plainText);
  cout << "Assert Elgamal successfully" << std::endl;

  //blank out the last output file and write the column headers
  std::ofstream out(CSVfileName.c_str());
  out << "SimulationSecond," <<
      "ReceiveRate," <<
      "PacketsReceived," <<
      "NumberOfSinks," <<
      "RoutingProtocol," <<
      "TransmissionPower" <<
      std::endl;
  out.close();

  int nSinks = 10;
  double txp = 7.5;

  experiment.Run(nSinks, txp, CSVfileName);
}

void
RoutingExperiment::Run(int nSinks, double txp, string CSVfileName) {
  Packet::EnablePrinting();
  m_nSinks = nSinks;
  m_txp = txp;
  m_CSVfileName = CSVfileName;

  int nWifis = 50;

  double TotalTime = 200.0;
  string rate("2048bps");
  string phyMode("DsssRate11Mbps");
  string tr_name("manet-routing-compare");
  int nodeSpeed = 20; //in m/s
  int nodePause = 0; //in s
  m_protocolName = "protocol";

  Config::SetDefault("ns3::OnOffApplication::PacketSize", StringValue("64"));
  Config::SetDefault("ns3::OnOffApplication::DataRate", StringValue(rate));

  //Set Non-unicastMode rate to unicast mode
  Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));

  // Create 50 nodes
  NodeContainer adhocNodes;
  adhocNodes.Create(nWifis);

  // setting up wifi phy and channel using helpers
  WifiHelper wifi;
  wifi.SetStandard(WIFI_PHY_STANDARD_80211b);

  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel");
  wifiPhy.SetChannel(wifiChannel.Create());

  // Add a mac and disable rate control
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue(phyMode),
                               "ControlMode", StringValue(phyMode));

  wifiPhy.Set("TxPowerStart", DoubleValue(txp));
  wifiPhy.Set("TxPowerEnd", DoubleValue(txp));

  wifiMac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, adhocNodes);

  MobilityHelper mobilityAdhoc;
  int64_t streamIndex = 0; // used to get consistent mobility across scenarios

  ObjectFactory pos;
  pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
  pos.Set("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
  pos.Set("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));

  Ptr <PositionAllocator> taPositionAlloc = pos.Create()->GetObject<PositionAllocator>();
  streamIndex += taPositionAlloc->AssignStreams(streamIndex);

  std::stringstream ssSpeed;
  ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
  std::stringstream ssPause;
  ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
  mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                 "Speed", StringValue(ssSpeed.str()),
                                 "Pause", StringValue(ssPause.str()),
                                 "PositionAllocator", PointerValue(taPositionAlloc));
  mobilityAdhoc.SetPositionAllocator(taPositionAlloc);
  mobilityAdhoc.Install(adhocNodes);
  streamIndex += mobilityAdhoc.AssignStreams(adhocNodes, streamIndex);
  NS_UNUSED(streamIndex); // From this point, streamIndex is unused

  AodvHelper aodv;
  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;

  switch (m_protocol) {
    case 2:
      list.Add(aodv, 100);
      m_protocolName = "AODV";
      break;
    default:
      NS_FATAL_ERROR("No such protocol:" << m_protocol);
  }

  // Install internet with 50 nodes and each node's type is adhoc
  internet.SetRoutingHelper(list);
  internet.Install(adhocNodes);

  NS_LOG_INFO("assigning ip address");

  // Using IPv4 with IP ranges from 10.1.1.0 --> 10.1.1.49
  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer adhocInterfaces;
  adhocInterfaces = addressAdhoc.Assign(adhocDevices);

  for (int i = 0; i < 1; i++) {
    UdpEchoServerHelper echoServer(port);

    ApplicationContainer serverApps = echoServer.Install(adhocNodes.Get(i + nSinks));
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(TotalTime));

    UdpEchoClientHelper echoClient(adhocInterfaces.GetAddress(i + nSinks), port);
    echoClient.SetAttribute("MaxPackets", UintegerValue(1));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));

    ApplicationContainer clientApps = echoClient.Install(adhocNodes.Get(i));
    Ptr <UniformRandomVariable> var = CreateObject<UniformRandomVariable>();
    clientApps.Start(Seconds(2));
    clientApps.Stop(Seconds(TotalTime));

    RSA_AODV rsa_aodv(1024);
    echoClient.SetFill(clientApps.Get(i), rsa_aodv.encrypt(RoutingExperiment::simplePlaintext.data()));
  }

  // For visualisation with NetAdmin purpose only
//  std::stringstream ss;
//  ss << nWifis;
//  string nodes = ss.str();
//
//  std::stringstream ss2;
//  ss2 << nodeSpeed;
//  string sNodeSpeed = ss2.str();
//
//  std::stringstream ss3;
//  ss3 << nodePause;
//  string sNodePause = ss3.str();
//
//  std::stringstream ss4;
//  ss4 << rate;
//  string sRate = ss4.str();
//
//  NS_LOG_INFO ("Configure Tracing.");
//  tr_name = tr_name + "_" + m_protocolName + "_" + nodes + "nodes_" + sNodeSpeed + "speed_" + sNodePause + "pause_" + sRate + "rate";
//
//  AsciiTraceHelper ascii;
//  Ptr <OutputStreamWrapper> osw = ascii.CreateFileStream((tr_name + ".tr").c_str());
//  wifiPhy.EnableAsciiAll(osw);
//  MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(tr_name + ".mob"));
//
//  Ptr <FlowMonitor> flowmon;
//  FlowMonitorHelper flowmonHelper;
//  flowmon = flowmonHelper.InstallAll();
//
  NS_LOG_INFO("Run Simulation.");
//
  CheckThroughput();
//
  Simulator::Stop(Seconds(TotalTime));
  Simulator::Run();
//
//  flowmon->SerializeToXmlFile((tr_name + ".flowmon").c_str(), false, false);

  Simulator::Destroy();
}


