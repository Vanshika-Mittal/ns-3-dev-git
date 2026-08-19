
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

#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "../model/ipv4-end-point.h"
#include "../model/ipv6-end-point.h"
#include "tcp-general-test.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "tcp-error-model.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/tcp-tx-buffer.h"
#include "ns3/tcp-rx-buffer.h"
#include "ns3/rtt-estimator.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpAccEcnTestSuite");

class TcpSocketTestAccEcn : public TcpSocketMsgBase
{
public:
    static TypeId GetTypeId (void);

    TcpSocketTestAccEcn () : TcpSocketMsgBase ()
    {
      m_dataPacketSent = 0;
    }

    TcpSocketTestAccEcn (const TcpSocketTestAccEcn &other)
            : TcpSocketMsgBase (other),
              m_testcase (other.m_testcase),
              m_who (other.m_who)
    {
    }

    enum SocketWho
    {
        SENDER,  //!< Sender node
        RECEIVER //!< Receiver node
    };

    void SetTestCase (uint32_t testCase, SocketWho who);

protected:
    virtual void SendEmptyPacket (uint16_t flags);
    virtual uint32_t SendDataPacket (SequenceNumber32 seq, uint32_t maxSize, bool withAck);
    virtual Ptr<TcpSocketBase> Fork (void);
    void SetCE (Ptr<Packet> p);
    void SetECT1 (Ptr<Packet> p);
    void SetNotECT (Ptr<Packet> p);

private:
    uint32_t m_dataPacketSent;
    uint32_t m_testcase;
    SocketWho m_who;
};

NS_OBJECT_ENSURE_REGISTERED (TcpSocketTestAccEcn);

TypeId
TcpSocketTestAccEcn::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpSocketTestAccEcn")
          .SetParent<TcpSocketMsgBase> ()
          .SetGroupName ("Internet")
          .AddConstructor<TcpSocketTestAccEcn> ()
  ;
  return tid;
}

void
TcpSocketTestAccEcn::SetTestCase (uint32_t testCase, SocketWho who)
{
  m_testcase = testCase;
  m_who = who;
}

void
TcpSocketTestAccEcn::SetCE(Ptr<Packet> p)
{
  uint8_t ipTos = MarkEcnCe(GetIpTos());

  SocketIpTosTag ipTosTag;
  ipTosTag.SetTos (ipTos);
  p->ReplacePacketTag (ipTosTag);

  SocketIpv6TclassTag ipTclassTag;
  ipTclassTag.SetTclass (ipTos);
  p->ReplacePacketTag (ipTclassTag);
}

void
TcpSocketTestAccEcn::SetECT1(Ptr<Packet> p)
{
  uint8_t ipTos = MarkEcnEct1(GetIpTos());

  SocketIpTosTag ipTosTag;
  ipTosTag.SetTos (ipTos);
  p->ReplacePacketTag (ipTosTag);

  SocketIpv6TclassTag ipTclassTag;
  ipTclassTag.SetTclass (ipTos);
  p->ReplacePacketTag (ipTclassTag);
}

void
TcpSocketTestAccEcn::SetNotECT(Ptr<Packet> p)
{
  uint8_t ipTos = ClearEcnBits(GetIpTos());

  SocketIpTosTag ipTosTag;
  ipTosTag.SetTos (ipTos);
  p->ReplacePacketTag (ipTosTag);

  SocketIpv6TclassTag ipTclassTag;
  ipTclassTag.SetTclass (ipTos);
  p->ReplacePacketTag (ipTclassTag);
}

Ptr<TcpSocketBase>
TcpSocketTestAccEcn::Fork (void)
{
  return CopyObject<TcpSocketTestAccEcn> (this);
}

void
TcpSocketTestAccEcn::SendEmptyPacket (uint16_t flags)
{
  NS_LOG_FUNCTION (this << static_cast<uint32_t> (flags));

  if (m_endPoint == nullptr && m_endPoint6 == nullptr)
  {
    NS_LOG_WARN ("Failed to send empty packet due to null endpoint");
    return;
  }

  Ptr<Packet> p = Create<Packet> ();
  TcpHeader header;
  SequenceNumber32 s = m_tcb->m_nextTxSequence;

  if (flags & TcpHeader::FIN)
  {
    flags |= TcpHeader::ACK;
  }
  else if (m_state == FIN_WAIT_1 || m_state == LAST_ACK || m_state == CLOSING)
  {
    ++s;
  }

  // Based on ECN++ draft Table 1 https://tools.ietf.org/html/draft-ietf-tcpm-generalized-ecn-02#section-3.2
  // if use ECN++ to reinforce classic ECN RFC 3618
  // should set ECT in SYN/ACK, pure ACK, FIN, RST
  // pure ACK do not clear so far, temporarily not set ECT in pure ACK for ECN++
  bool withEct = false;
  if ((m_ecnMode == EcnMode_t::EcnPp) && (((flags & TcpHeader::SYN) && (flags & TcpHeader::ACK)) ||
                                          flags & TcpHeader::FIN || flags & TcpHeader::RST))
  {
    withEct = true;
  }
  // AccEcn can set ECT in all control packet including SYN, SYN/ACK, pure ACK, FIN, RST
  if (m_ecnMode == EcnMode_t::AccEcn && (flags & TcpHeader::SYN || flags == TcpHeader::ACK || flags & TcpHeader::FIN || flags & TcpHeader::RST))
  {
    withEct = true;
  }
  AddSocketTags (p, withEct);

  if (m_ecnMode == EcnMode_t::AccEcn && m_connected)
  {
    NS_ASSERT_MSG (GetAceFlags(flags) == 0, "there are some unexpected bits in ACE field");
    uint16_t aceFlags = SetAceFlags (EncodeAceFlags (m_accEcnData->m_ecnCepR));
    header.SetFlags (flags | aceFlags);
  }
  else
  {
    header.SetFlags (flags);
  }

  header.SetSequenceNumber (s);
  header.SetAckNumber (m_rxBuffer->NextRxSequence ());
  if (m_endPoint != nullptr)
  {
    header.SetSourcePort (m_endPoint->GetLocalPort ());
    header.SetDestinationPort (m_endPoint->GetPeerPort ());
  }
  else
  {
    header.SetSourcePort (m_endPoint6->GetLocalPort ());
    header.SetDestinationPort (m_endPoint6->GetPeerPort ());
  }
  AddOptions (header);

  // RFC 6298, clause 2.4
  m_rto = Max (m_rtt->GetEstimate () + Max (m_clockGranularity, m_rtt->GetVariation () * 4), m_minRto);

  uint16_t windowSize = AdvertisedWindowSize ();
  bool hasSyn = flags & TcpHeader::SYN;
  bool hasAck = flags & TcpHeader::ACK;
  bool hasFin = flags & TcpHeader::FIN;
  bool isAck = flags == TcpHeader::ACK;

  if (hasSyn)
  {
    if (m_winScalingEnabled)
    { // The window scaling option is set only on SYN packets
      AddOptionWScale (header);
    }

    if (m_sackEnabled)
    {
      AddOptionSackPermitted (header);
    }

    if (m_synCount == 0)
    { // No more connection retries, give up
      NS_LOG_LOGIC ("Connection failed.");
      m_rtt->Reset (); //According to recommendation -> RFC 6298
      CloseAndNotify ();
      return;
    }
    else
    { // Exponential backoff of connection time out
      int backoffCount = 0x1 << (m_synRetries - m_synCount);
      m_rto = m_cnTimeout * backoffCount;
      m_synCount--;
    }

    if (m_synRetries - 1 == m_synCount)
    {
      UpdateRttHistory (s, 0, false);
    }
    else
    { // This is SYN retransmission
      UpdateRttHistory (s, 0, true);
    }

    windowSize = AdvertisedWindowSize (false);
  }
  header.SetWindowSize (windowSize);

  if (flags & TcpHeader::ACK)
  { // If sending an ACK, cancel the delay ACK as well
    m_delAckEvent.Cancel ();
    m_delAckCount = 0;
    if (m_highTxAck < header.GetAckNumber ())
    {
      m_highTxAck = header.GetAckNumber ();
    }
    if (m_sackEnabled && m_rxBuffer->GetSackListSize () > 0)
    {
      AddOptionSack (header);
    }
    NS_LOG_INFO ("Sending a pure ACK, acking seq " << m_rxBuffer->NextRxSequence ());
  }

  m_txTrace (p, header, this);

  if (hasSyn && !hasAck && m_who == SENDER) // SYN
  {
    if (m_testcase == 8 || m_testcase == 11)
    {
      SetCE(p);
    }
    else if (m_testcase == 9)
    {
      SetECT1(p);
    }
    else if (m_testcase == 10)
    {
      SetNotECT(p);
    }
  }

  if (hasSyn && hasAck && m_who == RECEIVER) // SYN + ACK
  {
    if (m_testcase == 8 || m_testcase == 11)
    {
      SetCE(p);
    }
    else if (m_testcase == 9)
    {
      SetECT1(p);
    }
    else if (m_testcase == 10)
    {
      SetNotECT(p);
    }
  }

  if (!hasSyn && hasAck && !m_connected && m_who == SENDER) // LastAck
  {
    if (m_testcase == 11)
    {
      SetCE(p);
    }
  }

  if (m_endPoint != nullptr)
  {
    m_tcp->SendPacket (p, header, m_endPoint->GetLocalAddress (),
                       m_endPoint->GetPeerAddress (), m_boundnetdevice);
  }
  else
  {
    m_tcp->SendPacket (p, header, m_endPoint6->GetLocalAddress (),
                       m_endPoint6->GetPeerAddress (), m_boundnetdevice);
  }


  if (m_retxEvent.IsExpired () && (hasSyn || hasFin) && !isAck )
  { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
    NS_LOG_LOGIC ("Schedule retransmission timeout at time "
                          << Simulator::Now ().GetSeconds () << " to expire at time "
                          << (Simulator::Now () + m_rto.Get ()).GetSeconds ());
    m_retxEvent = Simulator::Schedule (m_rto, &TcpSocketTestAccEcn::SendEmptyPacket, this, flags);
  }
}

uint32_t
TcpSocketTestAccEcn::SendDataPacket (SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  NS_LOG_FUNCTION (this << seq << maxSize << withAck);

  bool isRetransmission = false;
  if (seq != m_tcb->m_highTxMark)
  {
    isRetransmission = true;
  }

  Ptr<Packet> p = m_txBuffer->CopyFromSequence (maxSize, seq);
  uint32_t sz = p->GetSize (); // Size of packet
  uint16_t flags = withAck ? TcpHeader::ACK : 0;
  uint32_t remainingData = m_txBuffer->SizeFromSequence (seq + SequenceNumber32 (sz));

  if (m_tcb->m_pacing)
  {
    NS_LOG_INFO ("Pacing is enabled");
    if (m_pacingTimer.IsExpired ())
    {
      NS_LOG_DEBUG ("Current Pacing Rate " << m_tcb->m_currentPacingRate);
      NS_LOG_DEBUG ("Timer is in expired state, activate it " << m_tcb->m_currentPacingRate.CalculateBytesTxTime (sz));
      m_pacingTimer.Schedule (m_tcb->m_currentPacingRate.CalculateBytesTxTime (sz));
    }
    else
    {
      NS_LOG_INFO ("Timer is already in running state");
    }
  }

  if (withAck)
  {
    m_delAckEvent.Cancel ();
    m_delAckCount = 0;
  }

  // Classic ECN: Sender should reduce the Congestion Window as a response to receiver's ECN Echo notification only once per window
  // ECN++: Sender should reduce the Congestion Window even for the retransmission packet
  bool isRequiredCWR = (m_ecnMode == EcnMode_t::ClassicEcn && !isRetransmission) || m_ecnMode == EcnMode_t::EcnPp;
  if (m_tcb->m_ecnState == TcpSocketState::ECN_ECE_RCVD && m_ecnEchoSeq.Get() > m_ecnCWRSeq.Get () && isRequiredCWR)
  {
    NS_LOG_INFO ("Backoff mechanism by reducing CWND  by half because we've received ECN Echo");
    m_tcb->m_cWnd = std::max (m_tcb->m_cWnd.Get () / 2, m_tcb->m_segmentSize);
    m_tcb->m_ssThresh = m_tcb->m_cWnd;
    m_tcb->m_cWndInfl = m_tcb->m_cWnd;
    flags |= TcpHeader::CWR;
    m_ecnCWRSeq = seq;
    NS_LOG_DEBUG (TcpSocketState::EcnStateName[m_tcb->m_ecnState] << " -> ECN_CWR_SENT");
    m_tcb->m_ecnState = TcpSocketState::ECN_CWR_SENT;
    NS_LOG_INFO ("CWR flags set");
    NS_LOG_DEBUG (TcpSocketState::TcpCongStateName[m_tcb->m_congState] << " -> CA_CWR");
    if (m_tcb->m_congState == TcpSocketState::CA_OPEN)
    {
      m_congestionControl->CongestionStateSet (m_tcb, TcpSocketState::CA_CWR);
      m_tcb->m_congState = TcpSocketState::CA_CWR;
    }
  }

  // Based on ECN++ draft Table 1 https://tools.ietf.org/html/draft-ietf-tcpm-generalized-ecn-02#section-3.2
  // if use ECN++ to reinforce classic ECN RFC 3618
  // should set ECT in Re-XMT
  bool withEct = isRetransmission;
  AddSocketTags (p, withEct);

  if (m_closeOnEmpty && (remainingData == 0))
  {
    flags |= TcpHeader::FIN;
    if (m_state == ESTABLISHED)
    { // On active close: I am the first one to send FIN
      NS_LOG_DEBUG ("ESTABLISHED -> FIN_WAIT_1");
      m_state = FIN_WAIT_1;
    }
    else if (m_state == CLOSE_WAIT)
    { // On passive close: Peer sent me FIN already
      NS_LOG_DEBUG ("CLOSE_WAIT -> LAST_ACK");
      m_state = LAST_ACK;
    }
  }
  TcpHeader header;

  if (m_ecnMode == EcnMode_t::AccEcn && m_connected)
  {
    NS_ASSERT_MSG (GetAceFlags(flags) == 0, "there are some unexpected bits in ACE field");
    uint16_t aceFlags = SetAceFlags (EncodeAceFlags (m_accEcnData->m_ecnCepR));
    header.SetFlags (flags | aceFlags);
  }
  else
  {
    header.SetFlags (flags);
  }

  header.SetSequenceNumber (seq);
  header.SetAckNumber (m_rxBuffer->NextRxSequence ());
  if (m_endPoint)
  {
    header.SetSourcePort (m_endPoint->GetLocalPort ());
    header.SetDestinationPort (m_endPoint->GetPeerPort ());
  }
  else
  {
    header.SetSourcePort (m_endPoint6->GetLocalPort ());
    header.SetDestinationPort (m_endPoint6->GetPeerPort ());
  }
  header.SetWindowSize (AdvertisedWindowSize ());
  AddOptions (header);

  if (m_retxEvent.IsExpired ())
  {
    // Schedules retransmit timeout. m_rto should be already doubled.

    NS_LOG_LOGIC (this << " SendDataPacket Schedule ReTxTimeout at time " <<
                       Simulator::Now ().GetSeconds () << " to expire at time " <<
                       (Simulator::Now () + m_rto.Get ()).GetSeconds () );
    m_retxEvent = Simulator::Schedule (m_rto, &TcpSocketTestAccEcn::ReTxTimeout, this);
  }

  m_txTrace (p, header, this);

  m_dataPacketSent++;
  if (m_who == SENDER && m_dataPacketSent == 1) // first data segment
  {
    if (m_testcase == 11)
    {
      SetCE(p);
    }
  }

  if (m_endPoint)
  {
    m_tcp->SendPacket (p, header, m_endPoint->GetLocalAddress (),
                       m_endPoint->GetPeerAddress (), m_boundnetdevice);
    NS_LOG_DEBUG ("Send segment of size " << sz << " with remaining data " <<
                                          remainingData << " via TcpL4Protocol to " <<  m_endPoint->GetPeerAddress () <<
                                          ". Header " << header);
  }
  else
  {
    m_tcp->SendPacket (p, header, m_endPoint6->GetLocalAddress (),
                       m_endPoint6->GetPeerAddress (), m_boundnetdevice);
    NS_LOG_DEBUG ("Send segment of size " << sz << " with remaining data " <<
                                          remainingData << " via TcpL4Protocol to " <<  m_endPoint6->GetPeerAddress () <<
                                          ". Header " << header);
  }

  UpdateRttHistory (seq, sz, isRetransmission);

  // Update bytes sent during recovery phase
  if(m_tcb->m_congState == TcpSocketState::CA_RECOVERY)
  {
    m_recoveryOps->UpdateBytesSent (sz);
  }

  // Notify the application of the data being sent unless this is a retransmit
  if (seq + sz > m_tcb->m_highTxMark)
  {
    Simulator::ScheduleNow (&TcpSocketTestAccEcn::NotifyDataSent, this,
                            (seq + sz - m_tcb->m_highTxMark.Get ()));
  }
  // Update highTxMark
  m_tcb->m_highTxMark = std::max (seq + sz, m_tcb->m_highTxMark.Get ());
  return sz;
}

class TcpAccEcnTest : public TcpGeneralTest
{
public:
    /**
     * \brief Constructor
     *
     * \param testcase test case number
     * \param desc Description about the ECN capabilities of sender and reciever
     */
    TcpAccEcnTest (uint32_t testcase, const std::string &desc);

protected:
    virtual void Rx (const Ptr<const Packet> p, const TcpHeader&h, SocketWho who);
    virtual void Tx (const Ptr<const Packet> p, const TcpHeader&h, SocketWho who);
    virtual Ptr<TcpSocketMsgBase> CreateSenderSocket (Ptr<Node> node);
    virtual Ptr<TcpSocketMsgBase> CreateReceiverSocket (Ptr<Node> node);
    void ConfigureProperties ();
    void AccEcnE0BTrace (uint32_t oldValue, uint32_t newValue);
    void AccEcnE1BTrace (uint32_t oldValue, uint32_t newValue);
    void AccEcnCEBTrace (uint32_t oldValue, uint32_t newValue);
    void AccEcnCEPTrace (uint32_t oldValue, uint32_t newValue);

private:
    uint32_t m_testcase;
    uint32_t m_senderSent;
    uint32_t m_senderReceived;
    uint32_t m_receiverSent;
    uint32_t m_receiverReceived;
    uint32_t m_e0bChangeCount;
    uint32_t m_e1bChangeCount;
    uint32_t m_cebChangeCount;
    uint32_t m_cepChangeCount;
};

TcpAccEcnTest::TcpAccEcnTest (uint32_t testcase, const std::string &desc)
        : TcpGeneralTest (desc),
          m_testcase (testcase),
          m_senderSent (0),
          m_senderReceived (0),
          m_receiverSent (0),
          m_receiverReceived (0),
          m_e0bChangeCount (0),
          m_e1bChangeCount (0),
          m_cebChangeCount (0),
          m_cepChangeCount (0)
{
}

void TcpAccEcnTest::ConfigureProperties ()
{
  TcpGeneralTest::ConfigureProperties ();
  if (m_testcase == 1 || m_testcase == 2 || m_testcase == 3 || m_testcase >=7)
  {
    SetEcn (SENDER, TcpSocketBase::AccEcn);
  }
  else if ( m_testcase == 6)
  {
    SetEcn (SENDER, TcpSocketBase::EcnPp);
  }
  else if (m_testcase == 5)
  {
    SetEcn (SENDER, TcpSocketBase::ClassicEcn);
  }

  if (m_testcase >= 4)
  {
    SetEcn (RECEIVER, TcpSocketBase::AccEcn);
  }
  else if (m_testcase == 3)
  {
    SetEcn (RECEIVER, TcpSocketBase::EcnPp);
  }
  else if (m_testcase == 2)
  {
    SetEcn (RECEIVER, TcpSocketBase::ClassicEcn);
  }
}

Ptr<TcpSocketMsgBase> TcpAccEcnTest::CreateSenderSocket (Ptr<Node> node)
{
  Ptr<TcpSocketTestAccEcn> socket = DynamicCast<TcpSocketTestAccEcn> (
          CreateSocket (node, TcpSocketTestAccEcn::GetTypeId (), m_congControlTypeId));
  socket->SetTestCase (m_testcase, TcpSocketTestAccEcn::SENDER);
  socket->TraceConnectWithoutContext ("AccEcnE0bS",
                                              MakeCallback (&TcpAccEcnTest::AccEcnE0BTrace, this));
  socket->TraceConnectWithoutContext ("AccEcnE1bS",
                                              MakeCallback (&TcpAccEcnTest::AccEcnE1BTrace, this));
  socket->TraceConnectWithoutContext ("AccEcnCebS",
                                              MakeCallback (&TcpAccEcnTest::AccEcnCEBTrace, this));
  socket->TraceConnectWithoutContext ("AccEcnCepS",
                                              MakeCallback (&TcpAccEcnTest::AccEcnCEPTrace, this));

  return socket;
}

Ptr<TcpSocketMsgBase> TcpAccEcnTest::CreateReceiverSocket (Ptr<Node> node)
{
  Ptr<TcpSocketTestAccEcn> socket = DynamicCast<TcpSocketTestAccEcn> (
          CreateSocket (node, TcpSocketTestAccEcn::GetTypeId (), m_congControlTypeId));
  socket->SetTestCase (m_testcase, TcpSocketTestAccEcn::RECEIVER);
  return socket;
}

void
TcpAccEcnTest::AccEcnE0BTrace (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_DEBUG("AccEcnE0BTrace: " << oldValue << " " << newValue);
}

void
TcpAccEcnTest::AccEcnE1BTrace (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_DEBUG("AccEcnE1BTrace: " << oldValue << " " << newValue);
}

void
TcpAccEcnTest::AccEcnCEBTrace (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_DEBUG("AccEcnCEBTrace: " << oldValue << " " << newValue);
}

void
TcpAccEcnTest::AccEcnCEPTrace (uint32_t oldValue, uint32_t newValue)
{
  NS_LOG_DEBUG("AccEcnCEPTrace: " << oldValue << " " << newValue);
  m_cepChangeCount++;
  if (m_testcase == 11)
  {
    if (m_cepChangeCount == 1)
    {
      NS_TEST_ASSERT_MSG_EQ (newValue, 5, "AccEcn ACE decode test: initial s.cep should be 5");
    }
    if (m_cepChangeCount == 2)
    {
      NS_TEST_ASSERT_MSG_EQ (newValue, 6, "AccEcn ACE decode test: s.cep should be 6");

    }
    if (m_cepChangeCount == 3)
    {
      NS_TEST_ASSERT_MSG_EQ (newValue, 8, "AccEcn ACE decode test: s.cep should be 8");

    }
  }

}




void
TcpAccEcnTest::Rx (const Ptr<const Packet> p, const TcpHeader &h, SocketWho who)
{
  NS_LOG_FUNCTION(this << m_testcase << who);

  if (who == RECEIVER)
  {
    m_receiverReceived++;
    NS_LOG_DEBUG("RECEIVER received: " << m_receiverReceived << " Flags: " << h.GetFlags());
    if (m_receiverReceived == 1) // SYN
    {
      NS_TEST_ASSERT_MSG_NE (((h.GetFlags ()) & TcpHeader::SYN), 0, "SYN should be received as first message at the receiver");
      if (m_testcase == 1 || m_testcase == 2 || m_testcase == 3 ||m_testcase >= 7)
      {
        NS_TEST_ASSERT_MSG_NE ((h.GetFlags () & TcpHeader::ECE) && (h.GetFlags () & TcpHeader::CWR) && (h.GetFlags () & TcpHeader::AE),
                               0, "The flags ECE + CWR + AE should be set in the TCP header of SYN at receiver when sender is AccEcn Capable");
      }
      else if (m_testcase == 5 || m_testcase == 6)
      {
        NS_TEST_ASSERT_MSG_NE ((h.GetFlags () & TcpHeader::ECE) && (h.GetFlags () & TcpHeader::CWR) && !(h.GetFlags () & TcpHeader::AE),
                               0, "The flags ECE + CWR should be set in the TCP header of SYN at receiver when sender is ClassicEcn or EcnPp Capable");
      }
      else if (m_testcase == 4)
      {
        NS_TEST_ASSERT_MSG_EQ (((h.GetFlags () & TcpHeader::ECE) || (h.GetFlags () & TcpHeader::CWR) || (h.GetFlags () & TcpHeader::AE)),
                               0, "The flags ECE + CWR + AE should not be set in the TCP header of SYN at receiver when sender is not ECN Capable");
      }
    } // End SYN test in tcp header

    if (m_receiverReceived == 2) // Last ACK in three-way handshake
    {
      NS_TEST_ASSERT_MSG_NE (((h.GetFlags ()) & TcpHeader::ACK), 0, "ACK should be received as second message at receiver");
      if (m_testcase >= 7)
      {
        // negotiation test
        uint8_t ace = (h.GetFlags() >> 6) & 0x7;
        if (m_testcase == 7)
        {
          NS_TEST_ASSERT_MSG_EQ (ace - 0b100, 0, "AccEcn last ack test fail for test case 7");
        }
        else if (m_testcase == 8)
        {
          NS_TEST_ASSERT_MSG_EQ (ace - 0b110, 0, "AccEcn last ack test fail for test case 8");
        }
        else if (m_testcase == 9)
        {
          NS_TEST_ASSERT_MSG_EQ (ace - 0b011, 0, "AccEcn last ack test fail for test case 9");
        }
        else if (m_testcase == 10)
        {
          NS_TEST_ASSERT_MSG_EQ (ace - 0b010, 0, "AccEcn last ack test fail for test case 10");
        }

       }
    } // End Last Ack test in tcp header

  }// End test for who == RECEIVER

  if (who == SENDER)
  {
    m_senderReceived++;
    NS_LOG_DEBUG("SENDER received: " << m_receiverReceived << " Flags: " << h.GetFlags());
    if (m_senderReceived == 1) // SYN+ACK
    {
      NS_TEST_ASSERT_MSG_NE (((h.GetFlags ()) & TcpHeader::SYN) && ((h.GetFlags ()) & TcpHeader::ACK), 0, "SYN+ACK received as first message at sender");
      // negotiation test
      if (m_testcase == 1 || m_testcase == 4)
      {
        NS_TEST_ASSERT_MSG_EQ (((h.GetFlags () & TcpHeader::ECE) || (h.GetFlags () & TcpHeader::CWR) || (h.GetFlags () & TcpHeader::AE)),
                               0, "The flags ECE + CWR + AE should not be set in the TCP header of SYN+ACK in test case 1 or 4");
      }
      else if (m_testcase == 2 || m_testcase == 3 || m_testcase == 5 || m_testcase == 6)
      {
        NS_TEST_ASSERT_MSG_NE ((h.GetFlags () & TcpHeader::ECE) && !(h.GetFlags () & TcpHeader::CWR) && !(h.GetFlags () & TcpHeader::AE),
                               0, "The flags ECE should be set in the TCP header of SYN+ACK in test case 1 3 5 6");
      }
      else if (m_testcase == 7) // AE should be set
      {
        NS_TEST_ASSERT_MSG_NE (!(h.GetFlags () & TcpHeader::ECE) && !(h.GetFlags () & TcpHeader::CWR) && (h.GetFlags () & TcpHeader::AE),
                               0, "AccEcn SYN+ACK test fail for test case 7");
      }
      else if (m_testcase == 8) // AE + CWR should be set
      {
        NS_TEST_ASSERT_MSG_NE (!(h.GetFlags () & TcpHeader::ECE) && (h.GetFlags () & TcpHeader::CWR) && (h.GetFlags () & TcpHeader::AE),
                               0, "AccEcn SYN+ACK test fail for test case 8");
      }
      else if (m_testcase == 9) // CWR + ECE should be set
      {
        NS_TEST_ASSERT_MSG_NE ((h.GetFlags () & TcpHeader::ECE) && (h.GetFlags () & TcpHeader::CWR) && !(h.GetFlags () & TcpHeader::AE),
                               0, "AccEcn SYN+ACK test fail for test case 9");
      }
      else if (m_testcase == 10) // CWR should be set
      {
        NS_TEST_ASSERT_MSG_NE (!(h.GetFlags () & TcpHeader::ECE) && (h.GetFlags () & TcpHeader::CWR) && !(h.GetFlags () & TcpHeader::AE),
                               0, "AccEcn SYN+ACK test fail for test case 10");
      }

    } // End SYN+ACK test in tcp header

  }// End test for who == SENDER
}

void TcpAccEcnTest::Tx (const Ptr<const Packet> p, const TcpHeader &h, SocketWho who)
{
  NS_LOG_FUNCTION(this << m_testcase << who);
  if (who == SENDER)
  {
    m_senderSent++;
    NS_LOG_DEBUG("SENDER sent: " << m_senderSent << " Flags: " << h.GetFlags());
    if (m_testcase == 11)
    {
      // ACE Encoding test
      if (m_senderSent == 3 || m_senderSent == 4 || m_senderSent == 5) // the packet after connection established
      {
        uint8_t ace = (h.GetFlags() >> 6) & 0x7;
        NS_TEST_ASSERT_MSG_EQ (ace - 0b110, 0, "ACE encoding test: should be 0b110");
      }
    }
  }

  if (who == RECEIVER)
  {
    m_receiverSent++;
    NS_LOG_DEBUG("RECEIVER sent: " << m_receiverSent << " Flags: " << h.GetFlags());
    if (m_testcase == 11)
    {
      // ACE Encoding test
      if (m_receiverSent == 2)
      {
        NS_TEST_ASSERT_MSG_NE (((h.GetFlags ()) & TcpHeader::ACK), 0, "ACK for the data segments");
        uint8_t ace = (h.GetFlags() >> 6) & 0x7;
        NS_TEST_ASSERT_MSG_EQ (ace , 0, "ACE encoding test: should be 0 because 8 % 8 = 0");
      }

    }
  }
}

/**
 * \ingroup internet-test
 * \ingroup tests
 *
 * \brief TCP ECN++ TestSuite
 */
static class TcpAccEcnTestSuite : public TestSuite
{
public:
    TcpAccEcnTestSuite () : TestSuite ("tcp-accecn-test", UNIT)
    {
      AddTestCase (new TcpAccEcnTest (1, "AccEcn Negotiation Test : Sender AccEcn, Receiver NoEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (2, "AccEcn Negotiation Test : Sender AccEcn, Receiver ClassicEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (3, "AccEcn Negotiation Test : Sender AccEcn, Receiver EcnPp"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (4, "AccEcn Negotiation Test : Sender NoEcn, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (5, "AccEcn Negotiation Test : Sender ClassicEcn, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (6, "AccEcn Negotiation Test : Sender EcnPp, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (7, "AccEcn Negotiation Test : Sender AccEcn, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (8, "AccEcn Negotiation Test : Sender AccEcn, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (9, "AccEcn Negotiation Test : Sender AccEcn, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (10, "AccEcn Negotiation Test : Sender AccEcn, Receiver AccEcn"), TestCase::QUICK);
      AddTestCase (new TcpAccEcnTest (11, "AccEcn Feedback Test : Sender AccEcn, Receiver AccEcn"), TestCase::QUICK);
    }
} g_tcpAccEcnTestSuite;

}// namespace ns3
