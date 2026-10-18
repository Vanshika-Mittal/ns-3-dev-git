/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Wenying Dai <dwy927@gmail.com>
 *          Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
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
#include "ns3/tcp-option-accecn.h"
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
          m_sendBrokenSynAck(other.m_sendBrokenSynAck),
          m_sendForwardCompatSynAck(other.m_sendForwardCompatSynAck),
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

    /**
     * @brief Set whether to send broken SYN-ACK reflecting SYN ECN flags (AE, CWR, ECE = 1, 1, 1).
     * @param v True to enable broken SYN-ACK reflection.
     */
    void SetSendBrokenSynAck(bool v)
    {
        m_sendBrokenSynAck = v;
    }

    /**
     * @brief Set whether to send forward compatibility SYN-ACK (AE, CWR, ECE = 1, 0, 1).
     * @param v True to enable forward compatibility SYN-ACK.
     */
    void SetSendForwardCompatSynAck(bool v)
    {
        m_sendForwardCompatSynAck = v;
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

        if (m_sendBrokenSynAck && (flags & TcpHeader::SYN) && (flags & TcpHeader::ACK))
        {
            flags = (flags & ~(TcpHeader::CWR | TcpHeader::ECE | TcpHeader::AE)) |
                    (TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE);
        }
        else if (m_sendForwardCompatSynAck && (flags & TcpHeader::SYN) && (flags & TcpHeader::ACK))
        {
            flags = (flags & ~(TcpHeader::CWR | TcpHeader::ECE | TcpHeader::AE)) |
                    (TcpHeader::AE | TcpHeader::ECE);
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

        bool hasSyn = flags & TcpHeader::SYN;
        bool hasAck = flags & TcpHeader::ACK;
        bool addAccEcnOption =
            (hasSyn && hasAck) || (!hasSyn && hasAck && !m_connected) ||
            !m_accEcnData->m_useDelAckAccEcn;
        if (m_ecnMode == EcnMode_t::AccEcn && addAccEcnOption)
        {
            AddOptionAccEcn(header);
            m_accEcnData->m_useDelAckAccEcn = true;
        }

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
    bool m_markSynCe{false};               ///< Mark SYN with CE.
    bool m_markSynAckCe{false};            ///< Mark SYN-ACK with CE.
    bool m_sendBrokenSynAck{false};        ///< Send broken server reflection (1, 1, 1) on SYN-ACK.
    bool m_sendForwardCompatSynAck{false}; ///< Send forward compatibility (1, 0, 1) on SYN-ACK.
    uint32_t m_markDataCePkt{0};           ///< Index of data packet to mark CE.
    uint32_t m_pktCount{0};                ///< Number of sent packets.
};

NS_OBJECT_ENSURE_REGISTERED(TcpSocketAccEcnCustom);

/**
 * @ingroup internet-test
 * @ingroup tests
 * @brief Socket helper that exposes protected handshake methods and intercepts packets for unit testing.
 */
class TcpSocketAccEcnTester : public TcpSocketBase
{
  public:
    /**
     * @brief Get the type ID.
     * @return The object TypeId.
     */
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::TcpSocketAccEcnTester")
                                .SetParent<TcpSocketBase>()
                                .SetGroupName("Internet")
                                .AddConstructor<TcpSocketAccEcnTester>();
        return tid;
    }

    TcpSocketAccEcnTester()
        : TcpSocketBase()
    {
    }

    TcpSocketAccEcnTester(const TcpSocketAccEcnTester& other)
        : TcpSocketBase(other)
    {
    }

    Ptr<TcpSocketBase> Fork() override
    {
        return CopyObject<TcpSocketAccEcnTester>(this);
    }

    using TcpSocketBase::CheckEcnRvdSyn;
    using TcpSocketBase::CheckEcnRvdSynAck;
    using TcpSocketBase::CheckEcnRvdLastAck;
    using TcpSocketBase::IsEct;
    using TcpSocketBase::m_tcb;
    using TcpSocketBase::m_accEcnData;
    using TcpSocketBase::m_state;
    using TcpSocketBase::m_synCount;
    using TcpSocketBase::m_synRetries;
    using TcpSocketBase::ReTxTimeout;

    /**
     * @brief Set the TCP state machine state.
     * @param state The state to set.
     */
    void SetState(TcpStates_t state)
    {
        m_state = state;
    }

    /**
     * @brief Get the TCP state machine state.
     * @return The current state.
     */
    TcpStates_t GetState() const
    {
        return m_state;
    }

    /**
     * @brief Get the TCP transmission control block (TCB).
     * @return Pointer to TcpSocketState.
     */
    Ptr<TcpSocketState> GetTcb() const
    {
        return m_tcb;
    }

    /**
     * @brief Get the AccECN data state.
     * @return Pointer to TcpAccEcnData.
     */
    Ptr<TcpAccEcnData> GetAccEcnData() const
    {
        return m_accEcnData;
    }

    std::vector<uint16_t> m_sentEmptyFlags; ///< Recorded flags from SendEmptyPacket calls.

  protected:
    void SendEmptyPacket(uint16_t flags) override
    {
        m_sentEmptyFlags.push_back(flags);
        if (m_synCount > 0)
        {
            m_synCount--;
        }
    }
};

NS_OBJECT_ENSURE_REGISTERED(TcpSocketAccEcnTester);

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
 * @ingroup internet-test
 * @ingroup tests
 * @brief Test: Broken Server Handshake Fallback (RFC 9768 Table 2).
 */
class TcpAccEcnBrokenServerTest : public TcpGeneralTest
{
  public:
    /**
     * @brief Constructor.
     * @param desc Test description.
     */
    TcpAccEcnBrokenServerTest(const std::string& desc)
        : TcpGeneralTest(desc)
    {
    }

  protected:
    Ptr<TcpSocketMsgBase> CreateReceiverSocket(Ptr<Node> node) override
    {
        Ptr<TcpSocketAccEcnCustom> s = DynamicCast<TcpSocketAccEcnCustom>(
            CreateSocket(node, TcpSocketAccEcnCustom::GetTypeId(), m_congControlTypeId));
        s->SetSendBrokenSynAck(true);
        return s;
    }

    void ConfigureProperties() override
    {
        TcpGeneralTest::ConfigureProperties();
        SetEcnMode(SENDER, TcpSocketBase::AccEcn);
        SetEcnMode(RECEIVER, TcpSocketBase::AccEcn);
        SetSegmentSize(SENDER, 1000);
        SetSegmentSize(RECEIVER, 1000);
    }

    void ConfigureEnvironment() override
    {
        TcpGeneralTest::ConfigureEnvironment();
        SetAppPktCount(4);
        SetAppPktSize(1000);
    }

    void Tx(const Ptr<const Packet> p, const TcpHeader& h, SocketWho who) override
    {
        if (who == RECEIVER && (h.GetFlags() & TcpHeader::SYN) && (h.GetFlags() & TcpHeader::ACK))
        {
            uint16_t expectedFlags =
                TcpHeader::SYN | TcpHeader::ACK | TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE;
            NS_TEST_ASSERT_MSG_EQ((h.GetFlags() & expectedFlags),
                                  expectedFlags,
                                  "Broken server must reflect AE|CWR|ECE on SYN-ACK");
        }
        else if (who == SENDER && !(h.GetFlags() & TcpHeader::SYN) &&
                 (h.GetFlags() & TcpHeader::ACK) && !m_sawFirstAck)
        {
            m_sawFirstAck = true;
            uint16_t ecnFlags = h.GetFlags() & (TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE);
            NS_TEST_ASSERT_MSG_EQ(ecnFlags,
                                  0,
                                  "Client falling back to NoEcn must not send ACE in 3rd ACK");
        }
    }

    void FinalChecks() override
    {
        NS_TEST_ASSERT_MSG_GT(m_pktsAcked, 0, "Data must transfer successfully after fallback");
        Ptr<TcpSocketBase> senderSock = DynamicCast<TcpSocketBase>(GetSenderSocket());
        NS_TEST_ASSERT_MSG_EQ(senderSock->GetEcnMode(),
                              TcpSocketBase::NoEcn,
                              "Client must fall back to NoEcn with broken server");
    }

    void ProcessedAck(const Ptr<const TcpSocketState> tcb, const TcpHeader& h, SocketWho who) override
    {
        if (who == SENDER)
        {
            m_pktsAcked++;
        }
    }

  private:
    uint32_t m_pktsAcked{0};   ///< Number of packets acknowledged.
    bool m_sawFirstAck{false}; ///< Whether the first ACK was received.
};

/**
 * @ingroup internet-test
 * @ingroup tests
 * @brief Test: Forward Compatibility SYN-ACK Negotiation (RFC 9768 Section 3.1.3).
 */
class TcpAccEcnForwardCompatTest : public TcpGeneralTest
{
  public:
    /**
     * @brief Constructor.
     * @param desc Test description.
     */
    TcpAccEcnForwardCompatTest(const std::string& desc)
        : TcpGeneralTest(desc)
    {
    }

  protected:
    Ptr<TcpSocketMsgBase> CreateReceiverSocket(Ptr<Node> node) override
    {
        Ptr<TcpSocketAccEcnCustom> s = DynamicCast<TcpSocketAccEcnCustom>(
            CreateSocket(node, TcpSocketAccEcnCustom::GetTypeId(), m_congControlTypeId));
        s->SetSendForwardCompatSynAck(true);
        return s;
    }

    void ConfigureProperties() override
    {
        TcpGeneralTest::ConfigureProperties();
        SetEcnMode(SENDER, TcpSocketBase::AccEcn);
        SetEcnMode(RECEIVER, TcpSocketBase::AccEcn);
        SetSegmentSize(SENDER, 1000);
        SetSegmentSize(RECEIVER, 1000);
    }

    void ConfigureEnvironment() override
    {
        TcpGeneralTest::ConfigureEnvironment();
        SetAppPktCount(4);
        SetAppPktSize(1000);
    }

    void Tx(const Ptr<const Packet> p, const TcpHeader& h, SocketWho who) override
    {
        if (who == RECEIVER && (h.GetFlags() & TcpHeader::SYN) && (h.GetFlags() & TcpHeader::ACK))
        {
            uint16_t expectedFlags = TcpHeader::SYN | TcpHeader::ACK | TcpHeader::AE | TcpHeader::ECE;
            NS_TEST_ASSERT_MSG_EQ((h.GetFlags() & expectedFlags),
                                  expectedFlags,
                                  "Forward compat server must send AE|ECE on SYN-ACK");
        }
        else if (who == SENDER && !(h.GetFlags() & TcpHeader::SYN) &&
                 (h.GetFlags() & TcpHeader::ACK) && !m_sawFirstAck)
        {
            m_sawFirstAck = true;
            uint16_t ace = (h.GetFlags() >> 6) & 0x7;
            NS_TEST_ASSERT_MSG_EQ(ace,
                                  0b010,
                                  "Client in AccEcn mode must send ACE = 0b010 in 3rd ACK reflecting Not-ECT SYN-ACK");
        }
    }

    void FinalChecks() override
    {
        NS_TEST_ASSERT_MSG_GT(m_pktsAcked, 0, "Data must transfer successfully in AccECN mode");
        Ptr<TcpSocketBase> senderSock = DynamicCast<TcpSocketBase>(GetSenderSocket());
        NS_TEST_ASSERT_MSG_EQ(senderSock->GetEcnMode(),
                              TcpSocketBase::AccEcn,
                              "Client must enter AccEcn mode with forward-compatible server");
    }

    void ProcessedAck(const Ptr<const TcpSocketState> tcb, const TcpHeader& h, SocketWho who) override
    {
        if (who == SENDER)
        {
            m_pktsAcked++;
        }
    }

  private:
    uint32_t m_pktsAcked{0};   ///< Number of packets acknowledged.
    bool m_sawFirstAck{false}; ///< Whether the first ACK was received.
};

/**
 * @ingroup internet-test
 * @ingroup tests
 * @brief Test: SYN Retransmission Sequence (RFC 9768 Section 3.1.4.1).
 */
class TcpAccEcnSynRetransmissionTest : public TestCase
{
  public:
    /**
     * @brief Constructor.
     */
    TcpAccEcnSynRetransmissionTest()
        : TestCase("Accurate ECN SYN retransmission fallback sequence per RFC 9768 Section 3.1.4.1")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<Node> node = CreateObject<Node>();
        Ptr<TcpSocketAccEcnTester> socket = CreateObject<TcpSocketAccEcnTester>();
        socket->SetNode(node);
        socket->SetEcnMode(TcpSocketBase::AccEcn);
        socket->SetState(TcpSocketBase::SYN_SENT);
        socket->m_synRetries = 4;
        socket->m_synCount = 3;

        // 1st retransmission: must be AccECN retry (1, 1, 1)
        socket->ReTxTimeout();
        NS_TEST_ASSERT_MSG_EQ(socket->m_sentEmptyFlags.empty(), false, "A SYN must be sent on 1st timeout");
        uint16_t flags1 = socket->m_sentEmptyFlags.back();
        uint16_t expectedFlags1 = TcpHeader::SYN | TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE;
        NS_TEST_ASSERT_MSG_EQ(flags1 & expectedFlags1, expectedFlags1, "1st SYN retransmission must retain AccECN flags");

        // 2nd retransmission: must fall back to non-ECN (0, 0, 0)
        socket->ReTxTimeout();
        uint16_t flags2 = socket->m_sentEmptyFlags.back();
        uint16_t ecnFlags2 = flags2 & (TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE);
        NS_TEST_ASSERT_MSG_EQ(ecnFlags2, 0, "2nd SYN retransmission must clear ECN flags (fallback to non-ECN)");
        NS_TEST_ASSERT_MSG_EQ((flags2 & TcpHeader::SYN), TcpHeader::SYN, "2nd retransmission must be a SYN");

        // 3rd retransmission: must continue non-ECN (0, 0, 0)
        socket->ReTxTimeout();
        uint16_t flags3 = socket->m_sentEmptyFlags.back();
        uint16_t ecnFlags3 = flags3 & (TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE);
        NS_TEST_ASSERT_MSG_EQ(ecnFlags3, 0, "3rd SYN retransmission must clear ECN flags (non-ECN)");
    }
};

/**
 * @ingroup internet-test
 * @ingroup tests
 * @brief Test: Detailed Handshake and Counter Validation (RFC 9768 Section 3.1 and Tables 2/3/4).
 */
class TcpAccEcnHandshakeValidationTest : public TestCase
{
  public:
    /**
     * @brief Constructor.
     */
    TcpAccEcnHandshakeValidationTest()
        : TestCase("Accurate ECN Handshake Negotiation and Table 2-3-4 Validation per RFC 9768")
    {
    }

  private:
    void DoRun() override
    {
        Ptr<Node> node = CreateObject<Node>();

        // 1. Client SYN/ACK processing (Table 2 & Section 3.1.3)
        // 1a. Broken server reflection (1, 1, 1) -> NoEcn
        {
            Ptr<TcpSocketAccEcnTester> client = CreateObject<TcpSocketAccEcnTester>();
            client->SetNode(node);
            client->SetEcnMode(TcpSocketBase::AccEcn);
            TcpHeader h;
            h.SetFlags(TcpHeader::SYN | TcpHeader::ACK | TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE);
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetEcnMode(),
                                  TcpSocketBase::NoEcn,
                                  "Broken server reflection (1,1,1) must cause client fallback to NoEcn");
        }

        // 1b. Forward compatibility (1, 0, 1) -> AccEcn
        {
            Ptr<TcpSocketAccEcnTester> client = CreateObject<TcpSocketAccEcnTester>();
            client->SetNode(node);
            client->SetEcnMode(TcpSocketBase::AccEcn);
            TcpHeader h;
            h.SetFlags(TcpHeader::SYN | TcpHeader::ACK | TcpHeader::AE | TcpHeader::ECE);
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetEcnMode(),
                                  TcpSocketBase::AccEcn,
                                  "Forward compat (1,0,1) must cause client to enter AccEcn");
        }

        // 1c. Classic ECN fallback (0, 0, 1) -> ClassicEcn
        {
            Ptr<TcpSocketAccEcnTester> client = CreateObject<TcpSocketAccEcnTester>();
            client->SetNode(node);
            client->SetEcnMode(TcpSocketBase::AccEcn);
            TcpHeader h;
            h.SetFlags(TcpHeader::SYN | TcpHeader::ACK | TcpHeader::ECE);
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetEcnMode(),
                                  TcpSocketBase::ClassicEcn,
                                  "SYN/ACK with (0,0,1) must fall back to ClassicEcn");
        }

        // 1d. Non-ECN fallback (0, 0, 0) -> NoEcn
        {
            Ptr<TcpSocketAccEcnTester> client = CreateObject<TcpSocketAccEcnTester>();
            client->SetNode(node);
            client->SetEcnMode(TcpSocketBase::AccEcn);
            TcpHeader h;
            h.SetFlags(TcpHeader::SYN | TcpHeader::ACK);
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetEcnMode(),
                                  TcpSocketBase::NoEcn,
                                  "SYN/ACK with (0,0,0) must fall back to NoEcn");
        }

        // 1e. CE on SYN echo (1, 1, 0) -> cWnd = 1 SMSS, s.cep stays 5 (RFC 9768 Section 3.2.2.2 bullet 2)
        {
            Ptr<TcpSocketAccEcnTester> client = CreateObject<TcpSocketAccEcnTester>();
            client->SetNode(node);
            client->SetEcnMode(TcpSocketBase::AccEcn);
            TcpHeader h;
            h.SetFlags(TcpHeader::SYN | TcpHeader::ACK | TcpHeader::AE | TcpHeader::CWR);
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetTcb()->m_cWnd,
                                  client->GetTcb()->m_segmentSize,
                                  "CE on SYN echo must reduce initial cWnd to 1 SMSS");
            NS_TEST_ASSERT_MSG_EQ(client->GetAccEcnData()->m_ecnCepS.Get(),
                                  5,
                                  "Client s.cep must remain 5 on CE on SYN feedback");
        }

        // 1f. CE in IP-ECN field of SYN/ACK -> r.cep becomes 6 (RFC 9768 Section 3.2.2.2 bullet 3)
        {
            Ptr<TcpSocketAccEcnTester> client = CreateObject<TcpSocketAccEcnTester>();
            client->SetNode(node);
            client->SetEcnMode(TcpSocketBase::AccEcn);
            client->GetTcb()->m_ecnState = TcpSocketState::ECN_CE_RCVD;
            TcpHeader h;
            h.SetFlags(TcpHeader::SYN | TcpHeader::ACK | TcpHeader::CWR);
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetAccEcnData()->m_ecnCepR.Get(),
                                  6,
                                  "Client r.cep must increment from 5 to 6 on CE-marked SYN/ACK");
            // Duplicate CE SYN/ACK must not increment beyond 6
            client->CheckEcnRvdSynAck(h);
            NS_TEST_ASSERT_MSG_EQ(client->GetAccEcnData()->m_ecnCepR.Get(),
                                  6,
                                  "Duplicate CE-marked SYN/ACK must not increment r.cep beyond 6");
        }

        // 2. Server SYN processing
        // 2a. Forward compatibility on SYN (any flags other than (0,0,0) or (0,1,1)) -> AccECN
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::LISTEN);
            TcpHeader synH;
            synH.SetFlags(TcpHeader::SYN | TcpHeader::AE | TcpHeader::ECE); // (1, 0, 1)
            server->CheckEcnRvdSyn(synH, false);
            NS_TEST_ASSERT_MSG_EQ(server->GetEcnMode(),
                                  TcpSocketBase::AccEcn,
                                  "Server must negotiate AccECN for forward compat SYN flags");
        }

        // 2b. CE in IP-ECN field of SYN -> server r.cep must remain 5 (RFC 9768 Section 3.2.2.2 bullet 1)
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::LISTEN);
            server->GetTcb()->m_ecnState = TcpSocketState::ECN_CE_RCVD;
            TcpHeader synH;
            synH.SetFlags(TcpHeader::SYN | TcpHeader::AE | TcpHeader::CWR | TcpHeader::ECE);
            server->CheckEcnRvdSyn(synH, false);
            NS_TEST_ASSERT_MSG_EQ(server->GetAccEcnData()->m_ecnCepR.Get(),
                                  5,
                                  "Server r.cep must remain 5 when receiving CE on SYN");
        }

        // 2c. Fallback SYN in SYN_RCVD -> server remains in AccECN but disables outgoing ECT
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::SYN_RCVD);
            TcpHeader synH;
            synH.SetFlags(TcpHeader::SYN); // (0, 0, 0)
            server->CheckEcnRvdSyn(synH, true);
            NS_TEST_ASSERT_MSG_EQ(server->GetEcnMode(),
                                  TcpSocketBase::AccEcn,
                                  "Server remains in AccECN mode on fallback SYN");
            NS_TEST_ASSERT_MSG_EQ(server->GetTcb()->m_isEcnBitFlipped,
                                  true,
                                  "Server must disable outgoing ECT after receiving fallback SYN");
        }

        // 2d. Conflicting SYN in SYN_RCVD -> server sends RST and closes
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::SYN_RCVD);
            TcpHeader synH;
            synH.SetFlags(TcpHeader::SYN | TcpHeader::CWR | TcpHeader::ECE); // Classic ECN (0, 1, 1)
            server->CheckEcnRvdSyn(synH, true);
            NS_TEST_ASSERT_MSG_EQ(server->GetState(),
                                  TcpSocketBase::CLOSED,
                                  "Server must close and reset connection on conflicting Classic ECN SYN");
        }

        // 3. Server final ACK (3WHS) processing (Table 4)
        // 3a. Table 4 Note 1: ACE = 0b000 disables outgoing ECT
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::SYN_RCVD);
            TcpHeader ackH;
            ackH.SetFlags(TcpHeader::ACK); // ACE = 0b000
            server->CheckEcnRvdLastAck(ackH);
            NS_TEST_ASSERT_MSG_EQ(server->GetTcb()->m_isEcnBitFlipped,
                                  true,
                                  "ACE=0 on 3WHS final ACK must disable outgoing ECT per Table 4 Note 1");
        }

        // 3b. CE on SYN/ACK feedback: ACE = 0b110 -> s.cep becomes 6, cWnd = 1 SMSS
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::SYN_RCVD);
            TcpHeader ackH;
            ackH.SetFlags(TcpHeader::ACK | server->SetAceFlags(0b110));
            server->CheckEcnRvdLastAck(ackH);
            NS_TEST_ASSERT_MSG_EQ(server->GetAccEcnData()->m_ecnCepS.Get(),
                                  6,
                                  "Server s.cep must increment from 5 to 6 on CE feedback per Table 4");
            NS_TEST_ASSERT_MSG_EQ(server->GetTcb()->m_cWnd,
                                  server->GetTcb()->m_segmentSize,
                                  "Server cWnd must be set to 1 SMSS on CE feedback");
        }

        // 3c. Normal ACK (Not-ECT): ACE = 0b010 when Not-ECT sent on SYN/ACK -> no mangling
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::SYN_RCVD);
            TcpHeader ackH;
            ackH.SetFlags(TcpHeader::ACK | server->SetAceFlags(0b010));
            server->CheckEcnRvdLastAck(ackH);
            NS_TEST_ASSERT_MSG_EQ(server->GetTcb()->m_isEcnBitFlipped,
                                  false,
                                  "Normal Not-ECT reflection must not trigger mangling detection");
        }

        // 3d. Mangling detection: Server sent Not-ECT on SYN/ACK, but received ACE = 0b100 (ECT0)
        {
            Ptr<TcpSocketAccEcnTester> server = CreateObject<TcpSocketAccEcnTester>();
            server->SetNode(node);
            server->SetEcnMode(TcpSocketBase::AccEcn);
            server->SetState(TcpSocketBase::SYN_RCVD);
            TcpHeader ackH;
            ackH.SetFlags(TcpHeader::ACK | server->SetAceFlags(0b100));
            server->CheckEcnRvdLastAck(ackH);
            NS_TEST_ASSERT_MSG_EQ(server->GetTcb()->m_isEcnBitFlipped,
                                  true,
                                  "Server must detect mangling when Not-ECT changes to ECT(0)");
        }
    }
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

        // 2. Sender AccECN, Receiver Classic ECN (Fallback to Classic ECN)
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::AccEcn,
                                                TcpSocketBase::ClassicEcn,
                                                "AccECN Fallback: AccECN Sender to Classic ECN"),
                    TestCase::Duration::QUICK);

        // 3. Sender AccECN, Receiver No ECN (Fallback to NoEcn)
        AddTestCase(new TcpAccEcnNegotiationTest(TcpSocketBase::AccEcn,
                                                TcpSocketBase::NoEcn,
                                                "AccECN Fallback: AccECN Sender to No ECN"),
                    TestCase::Duration::QUICK);

        // 4. Sender Classic ECN, Receiver AccECN (Fallback to Classic ECN)
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

        // 10. Broken Server Handshake Fallback (RFC 9768 Table 2)
        AddTestCase(new TcpAccEcnBrokenServerTest("AccECN Fallback: Broken Server SYN-ACK reflection"),
                    TestCase::Duration::QUICK);

        // 11. Forward Compatibility SYN/ACK Negotiation (RFC 9768 Section 3.1.3)
        AddTestCase(new TcpAccEcnForwardCompatTest("AccECN Forward Compatibility: Reserved (1,0,1) SYN-ACK"),
                    TestCase::Duration::QUICK);

        // 12. SYN Retransmission Sequence (RFC 9768 Section 3.1.4.1)
        AddTestCase(new TcpAccEcnSynRetransmissionTest(), TestCase::Duration::QUICK);

        // 13. Detailed Handshake and Counter Validation (RFC 9768 Section 3.1 and Tables 2/3/4)
        AddTestCase(new TcpAccEcnHandshakeValidationTest(), TestCase::Duration::QUICK);
    }
};

static TcpAccEcnTestSuite g_tcpAccEcnTestSuite;

} // namespace ns3
