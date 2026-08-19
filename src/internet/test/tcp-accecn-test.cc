/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Accurate ECN (AccECN) Test Suite.
 */

#include "tcp-general-test.h"

#include "ns3/ipv4-end-point.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv6-end-point.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/rtt-estimator.h"
#include "ns3/simple-channel.h"
#include "ns3/tcp-accecn-data.h"
#include "ns3/tcp-header.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/tcp-rx-buffer.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/tcp-socket-state.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("TcpAccEcnTestSuite");

/**
 * \ingroup internet-test
 * \brief Socket that allows injecting custom IP TOS / ECN marks on packets.
 */
class TcpSocketAccEcnCustom : public TcpSocketMsgBase
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::TcpSocketAccEcnCustom")
                                .SetParent<TcpSocketMsgBase>()
                                .SetGroupName("Internet")
                                .AddConstructor<TcpSocketAccEcnCustom>();
        return tid;
    }

    TcpSocketAccEcnCustom()
        : TcpSocketMsgBase()
    {
    }

    TcpSocketAccEcnCustom(const TcpSocketAccEcnCustom& other)
        : TcpSocketMsgBase(other),
          m_markSynCe(other.m_markSynCe),
          m_markSynAckCe(other.m_markSynAckCe),
          m_markDataCePkt(other.m_markDataCePkt),
          m_pktCount(other.m_pktCount)
    {
    }

    void SetMarkSynCe(bool v)
    {
        m_markSynCe = v;
    }

    void SetMarkSynAckCe(bool v)
    {
        m_markSynAckCe = v;
    }

    void SetMarkDataCePacket(uint32_t pktIndex)
    {
        m_markDataCePkt = pktIndex;
    }

  protected:
    void SendEmptyPacket(uint16_t flags) override
    {
        Ptr<Packet> p = Create<Packet>();
        TcpHeader header;
        SequenceNumber32 s = m_tcb->m_nextTxSequence;
        TcpPacketType_t packetType = INVALID;

        if (flags & TcpHeader::FIN)
        {
            packetType = TcpPacketType_t::FIN;
            flags |= TcpHeader::ACK;
        }
        else if (m_state == FIN_WAIT_1 || m_state == LAST_ACK || m_state == CLOSING)
        {
            ++s;
        }

        if (flags & TcpHeader::SYN)
        {
            packetType = TcpPacketType_t::SYN;
            if (flags & TcpHeader::ACK)
            {
                packetType = TcpPacketType_t::SYN_ACK;
            }
        }
        else if (flags & TcpHeader::ACK)
        {
            packetType = TcpPacketType_t::PURE_ACK;
        }

        if (flags & TcpHeader::RST)
        {
            packetType = TcpPacketType_t::RST;
        }

        AddSocketTags(p, IsEct(packetType));

        if (m_markSynCe && (flags & TcpHeader::SYN) && !(flags & TcpHeader::ACK))
        {
            SocketIpTosTag ipTosTag;
            ipTosTag.SetTos(0x3); // CE mark
            p->ReplacePacketTag(ipTosTag);
        }
        else if (m_markSynAckCe && (flags & TcpHeader::SYN) && (flags & TcpHeader::ACK))
        {
            SocketIpTosTag ipTosTag;
            ipTosTag.SetTos(0x3); // CE mark
            p->ReplacePacketTag(ipTosTag);
        }

        if (m_ecnMode == EcnMode_t::AccEcn && m_connected)
        {
            if (GetAceFlags(flags) == 0)
            {
                uint16_t aceFlags = SetAceFlags(EncodeAceFlags(m_accEcnData->m_ecnCepR));
                header.SetFlags(flags | aceFlags);
            }
            else
            {
                header.SetFlags(flags);
            }
        }
        else
        {
            header.SetFlags(flags);
        }
        header.SetSequenceNumber(s);
        header.SetAckNumber(m_tcb->m_rxBuffer->NextRxSequence());
        if (m_endPoint != nullptr)
        {
            header.SetSourcePort(m_endPoint->GetLocalPort());
            header.SetDestinationPort(m_endPoint->GetPeerPort());
        }
        else
        {
            header.SetSourcePort(m_endPoint6->GetLocalPort());
            header.SetDestinationPort(m_endPoint6->GetPeerPort());
        }
        AddOptions(header);

        m_rto = Max(m_rtt->GetEstimate() + Max(m_clockGranularity, m_rtt->GetVariation() * 4),
                    m_minRto);

        uint16_t windowSize = AdvertisedWindowSize();
        header.SetWindowSize(windowSize >> m_rcvWindShift);

        if (m_endPoint != nullptr)
        {
            m_tcp->SendPacket(p,
                              header,
                              m_endPoint->GetLocalAddress(),
                              m_endPoint->GetPeerAddress(),
                              m_boundnetdevice);
        }
        else
        {
            m_tcp->SendPacket(p,
                              header,
                              m_endPoint6->GetLocalAddress(),
                              m_endPoint6->GetPeerAddress(),
                              m_boundnetdevice);
        }
    }

    uint32_t SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck) override
    {
        m_pktCount++;
        uint32_t sz = TcpSocketBase::SendDataPacket(seq, maxSize, withAck);
        return sz;
    }

    Ptr<TcpSocketBase> Fork() override
    {
        return CopyObject<TcpSocketAccEcnCustom>(this);
    }

  private:
    bool m_markSynCe{false};
    bool m_markSynAckCe{false};
    uint32_t m_markDataCePkt{0};
    uint32_t m_pktCount{0};
};

NS_OBJECT_ENSURE_REGISTERED(TcpSocketAccEcnCustom);

/**
 * \ingroup internet-test
 * \brief Test 1-3: Accurate ECN 3WHS negotiation and fallback.
 */
class TcpAccEcnNegotiationTest : public TcpGeneralTest
{
  public:
    TcpAccEcnNegotiationTest(TcpSocketBase::EcnMode_t senderMode,
                             TcpSocketBase::EcnMode_t receiverMode,
                             const std::string& desc)
        : TcpGeneralTest(desc),
          m_senderMode(senderMode),
          m_receiverMode(receiverMode)
    {
    }

  protected:
    void ConfigureProperties() override
    {
        TcpGeneralTest::ConfigureProperties();
        SetEcnMode(SENDER, m_senderMode);
        SetEcnMode(RECEIVER, m_receiverMode);
    }

    void ConfigureEnvironment() override
    {
        TcpGeneralTest::ConfigureEnvironment();
        SetAppPktCount(2);
        SetAppPktSize(500);
    }

    void Tx(const Ptr<const Packet> p, const TcpHeader& h, SocketWho who) override
    {
        if (who == SENDER)
        {
            m_senderTxCount++;
            if (h.GetFlags() & TcpHeader::SYN && !(h.GetFlags() & TcpHeader::ACK))
            {
                if (m_senderMode == TcpSocketBase::AccEcn)
                {
                    uint16_t expectedFlags =
                        TcpHeader::SYN | TcpHeader::ECE | TcpHeader::CWR | TcpHeader::AE;
                    NS_TEST_ASSERT_MSG_EQ((h.GetFlags() & expectedFlags),
                                          expectedFlags,
                                          "Sender AccECN SYN must have SYN|ECE|CWR|AE");
                }
            }
        }
        else if (who == RECEIVER)
        {
            m_receiverTxCount++;
            if (h.GetFlags() & TcpHeader::SYN && (h.GetFlags() & TcpHeader::ACK))
            {
                if (m_senderMode == TcpSocketBase::AccEcn && m_receiverMode == TcpSocketBase::AccEcn)
                {
                    // AccECN SYN-ACK
                    uint16_t ecnFlags =
                        h.GetFlags() & (TcpHeader::CWR | TcpHeader::ECE | TcpHeader::AE);
                    NS_TEST_ASSERT_MSG_NE(ecnFlags,
                                          0,
                                          "Receiver AccECN SYN-ACK must carry AccECN feedback");
                }
            }
        }
    }

  private:
    TcpSocketBase::EcnMode_t m_senderMode;
    TcpSocketBase::EcnMode_t m_receiverMode;
    uint32_t m_senderTxCount{0};
    uint32_t m_receiverTxCount{0};
};

/**
 * \ingroup internet-test
 * \brief Test 4-6: Accurate ECN Handshake with CE markings on SYN / SYN-ACK.
 */
class TcpAccEcnHandshakeCeTest : public TcpGeneralTest
{
  public:
    enum HandshakeCeCase
    {
        CE_ON_SYN,
        CE_ON_SYN_ACK
    };

    TcpAccEcnHandshakeCeTest(HandshakeCeCase testCase, const std::string& desc)
        : TcpGeneralTest(desc),
          m_testCase(testCase)
    {
    }

  protected:
    Ptr<TcpSocketMsgBase> CreateSenderSocket(Ptr<Node> node) override
    {
        Ptr<TcpSocketAccEcnCustom> s = DynamicCast<TcpSocketAccEcnCustom>(
            CreateSocket(node, TcpSocketAccEcnCustom::GetTypeId(), m_congControlTypeId));
        if (m_testCase == CE_ON_SYN)
        {
            s->SetMarkSynCe(true);
        }
        return s;
    }

    Ptr<TcpSocketMsgBase> CreateReceiverSocket(Ptr<Node> node) override
    {
        Ptr<TcpSocketAccEcnCustom> s = DynamicCast<TcpSocketAccEcnCustom>(
            CreateSocket(node, TcpSocketAccEcnCustom::GetTypeId(), m_congControlTypeId));
        if (m_testCase == CE_ON_SYN_ACK)
        {
            s->SetMarkSynAckCe(true);
        }
        return s;
    }

    void ConfigureProperties() override
    {
        TcpGeneralTest::ConfigureProperties();
        SetEcnMode(SENDER, TcpSocketBase::AccEcn);
        SetEcnMode(RECEIVER, TcpSocketBase::AccEcn);
        SetSegmentSize(SENDER, 1000);
        SetSegmentSize(RECEIVER, 1000);
        SetInitialCwnd(SENDER, 10);
    }

    void ConfigureEnvironment() override
    {
        TcpGeneralTest::ConfigureEnvironment();
        SetAppPktCount(3);
        SetAppPktSize(1000);
    }

    void Rx(const Ptr<const Packet> p, const TcpHeader& h, SocketWho who) override
    {
        if (who == SENDER && (h.GetFlags() & TcpHeader::SYN) && (h.GetFlags() & TcpHeader::ACK))
        {
            if (m_testCase == CE_ON_SYN)
            {
                // Receiver received CE on SYN, sent SYN|ACK|CWR|AE
                uint16_t expectedFlags = TcpHeader::CWR | TcpHeader::AE;
                NS_TEST_ASSERT_MSG_EQ((h.GetFlags() & expectedFlags),
                                      expectedFlags,
                                      "Receiver must echo CE on SYN using CWR|AE");
            }
        }
    }

  private:
    HandshakeCeCase m_testCase;
};

/**
 * \ingroup internet-test
 * \brief Test 7-9: Unit test for Accurate ECN ACE encoding, decoding, and data counters.
 */
class TcpAccEcnDecodingTest : public TestCase
{
  public:
    TcpAccEcnDecodingTest()
        : TestCase("Accurate ECN ACE encoding and decoding and counter verification")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<Node> node = CreateObject<Node>();
        Ptr<TcpSocketBase> socket = CreateObject<TcpSocketBase>();
        socket->SetNode(node);
        socket->SetEcnMode(TcpSocketBase::AccEcn);

        // Test ACE helpers
        uint8_t aceValue = 0b101;
        uint16_t flagWithAce = socket->SetAceFlags(aceValue);
        NS_TEST_ASSERT_MSG_EQ(socket->GetAceFlags(flagWithAce),
                              aceValue,
                              "SetAceFlags and GetAceFlags mismatch");

        // Test EncodeAceFlags modulo 8
        NS_TEST_ASSERT_MSG_EQ(socket->EncodeAceFlags(0), 0, "0 mod 8 == 0");
        NS_TEST_ASSERT_MSG_EQ(socket->EncodeAceFlags(5), 5, "5 mod 8 == 5");
        NS_TEST_ASSERT_MSG_EQ(socket->EncodeAceFlags(8), 0, "8 mod 8 == 0");
        NS_TEST_ASSERT_MSG_EQ(socket->EncodeAceFlags(13), 5, "13 mod 8 == 5");

        // Test AccECN counter initialization
        Ptr<TcpAccEcnData> accData = CreateObject<TcpAccEcnData>();
        accData->IniSenderCounters();
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnCepS.Get(), 5, "Sender initial cep must be 5");
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnE0bS.Get(), 1, "Sender initial e0b must be 1");
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnCebS.Get(), 0, "Sender initial ceb must be 0");
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnE1bS.Get(), 0, "Sender initial e1b must be 0");

        accData->IniReceiverCounters();
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnCepR.Get(), 5, "Receiver initial cep must be 5");
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnE0bR.Get(), 1, "Receiver initial e0b must be 1");
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnCebR.Get(), 0, "Receiver initial ceb must be 0");
        NS_TEST_ASSERT_MSG_EQ(accData->m_ecnE1bR.Get(), 0, "Receiver initial e1b must be 0");

        // Test ACE delta calculations across modulo-8 wrap-around
        uint8_t DIVACE = 8;
        uint32_t sCep = 5;
        // Step 1: ace = 6 (1 CE mark)
        uint8_t ace1 = 6;
        uint32_t delta1 = (ace1 + DIVACE - (sCep % DIVACE)) % DIVACE;
        NS_TEST_ASSERT_MSG_EQ(delta1, 1, "Delta from ace 5 to 6 should be 1");
        sCep += delta1; // sCep = 6

        // Step 2: ace = 0 (2 CE marks, wrapping around 7 -> 0)
        uint8_t ace2 = 0;
        uint32_t delta2 = (ace2 + DIVACE - (sCep % DIVACE)) % DIVACE;
        NS_TEST_ASSERT_MSG_EQ(delta2, 2, "Delta from ace 6 to 0 (wrap-around) should be 2");
        sCep += delta2; // sCep = 8

        // Step 3: ace = 3 (3 CE marks)
        uint8_t ace3 = 3;
        uint32_t delta3 = (ace3 + DIVACE - (sCep % DIVACE)) % DIVACE;
        NS_TEST_ASSERT_MSG_EQ(delta3, 3, "Delta from ace 0 (8) to 3 should be 3");
        sCep += delta3; // sCep = 11
        NS_TEST_ASSERT_MSG_EQ(sCep, 11, "Accumulated cepS must be 11");
    }
};

/**
 * \ingroup internet-test
 * \brief Test: Full AccECN Data Transfer Test.
 */
class TcpAccEcnTransferTest : public TcpGeneralTest
{
  public:
    TcpAccEcnTransferTest(const std::string& desc)
        : TcpGeneralTest(desc)
    {
    }

  protected:
    void ConfigureProperties() override
    {
        TcpGeneralTest::ConfigureProperties();
        SetEcnMode(SENDER, TcpSocketBase::AccEcn);
        SetEcnMode(RECEIVER, TcpSocketBase::AccEcn);
    }

    void ConfigureEnvironment() override
    {
        TcpGeneralTest::ConfigureEnvironment();
        SetAppPktCount(10);
        SetAppPktSize(1000);
    }

    void FinalChecks() override
    {
        NS_TEST_ASSERT_MSG_GT(m_pktsAcked, 0, "AccECN connection must transfer and ack data");
    }

    void ProcessedAck(const Ptr<const TcpSocketState> tcb, const TcpHeader& h, SocketWho who) override
    {
        if (who == SENDER)
        {
            m_pktsAcked++;
        }
    }

  private:
    uint32_t m_pktsAcked{0};
};

/**
 * \ingroup internet-test
 * \brief TestSuite for Accurate ECN (AccECN).
 */
class TcpAccEcnTestSuite : public TestSuite
{
  public:
    TcpAccEcnTestSuite()
        : TestSuite("tcp-accecn", Type::UNIT)
    {
        // 1. Sender AccECN, Receiver AccECN
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::AccEcn,
                                                TcpSocketBase::AccEcn,
                                                "AccECN 3WHS: AccECN Sender and AccECN Receiver"),
                    TestCase::Duration::QUICK);

        // 2. Sender AccECN, Receiver Classic ECN (Fallback to EcnPp)
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::AccEcn,
                                                TcpSocketBase::ClassicEcn,
                                                "AccECN Fallback: AccECN Sender to Classic ECN"),
                    TestCase::Duration::QUICK);

        // 3. Sender AccECN, Receiver No ECN (Fallback to NoEcn)
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::AccEcn,
                                                TcpSocketBase::NoEcn,
                                                "AccECN Fallback: AccECN Sender to No ECN"),
                    TestCase::Duration::QUICK);

        // 4. Sender Classic ECN, Receiver AccECN (Fallback to EcnPp)
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::ClassicEcn,
                                                TcpSocketBase::AccEcn,
                                                "AccECN Fallback: Classic ECN Sender to AccECN"),
                    TestCase::Duration::QUICK);

        // 5. Sender No ECN, Receiver AccECN (Fallback to NoEcn)
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::NoEcn,
                                                TcpSocketBase::AccEcn,
                                                "AccECN Fallback: No ECN Sender to AccECN"),
                    TestCase::Duration::QUICK);

        // 6. CE on SYN
        AddTestCase(new TcpAccEcnHandshakeCeTest(TcpAccEcnHandshakeCeTest::CE_ON_SYN,
                                                "AccECN Handshake: CE on SYN packet"),
                    TestCase::Duration::QUICK);

        // 7. CE on SYN-ACK
        AddTestCase(new TcpAccEcnHandshakeCeTest(TcpAccEcnHandshakeCeTest::CE_ON_SYN_ACK,
                                                "AccECN Handshake: CE on SYN-ACK packet"),
                    TestCase::Duration::QUICK);

        // 8. Decoding, modulo-8 wrap-around & Counter unit tests
        AddTestCase(new TcpAccEcnDecodingTest(), TestCase::Duration::QUICK);

        // 9. Full data transfer test
        AddTestCase(new TcpAccEcnTransferTest("AccECN Full Data Transfer"),
                    TestCase::Duration::QUICK);
    }
};

static TcpAccEcnTestSuite g_tcpAccEcnTestSuite;

} // namespace ns3
