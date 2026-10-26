/*
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 *
 *
 * Authors: Shikha Bakshi <shikhabakshi912@gmail.com>
 *          Mohit P. Tahiliani <tahiliani@nitk.edu.in>
 */

/**
 * @file
 * @brief Unit test for the TCP D-SACK (Duplicate Selective Acknowledgment) implementation.
 *
 * This unit test exercises the TCP receive buffer by injecting duplicate,
 * out-of-order, and retransmitted segments, and verifies that D-SACK blocks
 * are correctly generated and reported under various loss and reordering
 * scenarios, in accordance with RFC 2883.
 */

#include "tcp-error-model.h"
#include "tcp-general-test.h"

#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/simple-channel.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpDsackTest");

/**
 * @ingroup internet-test
 * @brief Test case for validating TCP D-SACK behavior.
 *
 * TcpDsackSackTest is a unit test that validates the correct behavior of TCP D-SACK (Duplicate
 * Selective Acknowledgment) support in ns-3. The test constructs a sender-receiver TCP setup and
 * verifies that the TCP receive buffer correctly generates D-SACK blocks under various duplicate,
 * reordered, and retransmission scenarios, in accordance with RFC 2883.
 */

class TcpDsackSackTest : public TcpGeneralTest
{
  public:
    /**
     * @brief Constructor for the D-SACK test case.
     * @param sack Whether SACK option is enabled.
     * @param dsack Boolean variable to enable or disable D-SACK.
     * @param msg Test message.
     */
    TcpDsackSackTest(bool sack, bool dsack, const std::string& msg);

    Ptr<TcpSocketMsgBase> CreateSenderSocket(Ptr<Node> node) override;

  private:
    void DoRun() override;

    /**
     * @brief D-SACK tests.
     */
    void TestDsack();

    /**
     * @brief D-SACK test for reporting a duplicate segment.
     */
    void TestDuplicateSegment();

    /**
     * @brief D-SACK test for reporting an out-of-order segment and a duplicate segment.
     */
    void TestOutOfOrderSegment();

    /**
     * @brief D-SACK test for reporting a duplicate of an out-of-order segment.
     */
    void TestDuplicateOutOfOrderSegment();

    /**
     * @brief D-SACK test for reporting Partial Duplicate Segments.
     */
    void TestSingleDuplicateSegment();

    /**
     * @brief D-SACK test for two non-contiguous duplicate subsegments covered by
     * the cumulative acknowledgement .
     */
    void TestSegmentsCoveredByAck();

    /**
     * @brief D-SACK test for two non-contiguous duplicate subsegments not covered
     * by the cumulative acknowledgement .
     */
    void TestSegmentsNotCoveredByAck();

    /**
     * @brief D-SACK test for a packet is replicated in the network.
     */
    void TestDuplicateByNetwork();

    /**
     * @brief D-SACK test for false retransmit due to reordering .
     */
    void TestFalseRetransmit();

    /**
     * @brief D-SACK test for retransmit timeout due to ACK loss .
     */
    void TestRetransmitTimeout();

    /**
     * @brief D-SACK test for early retransmit timeout.
     */
    void TestEarlyRetransmitTimeout();

  protected:
    void Tx(const Ptr<const Packet> p, const TcpHeader& h, SocketWho who) override;

    /** @brief Indicates whether SACK is enabled. */
    bool m_sackState;
    /** @brief Indicates whether D-SACK is enabled. */
    bool m_dsackState;
};

TcpDsackSackTest::TcpDsackSackTest(bool sack, bool dsack, const std::string& msg)
    : TcpGeneralTest(msg),
      m_sackState(sack),
      m_dsackState(dsack)
{
}

Ptr<TcpSocketMsgBase>
TcpDsackSackTest::CreateSenderSocket(Ptr<Node> node)
{
    Ptr<TcpSocketMsgBase> socket = TcpGeneralTest::CreateSenderSocket(node);
    socket->SetAttribute("DSack", BooleanValue(m_dsackState));
    socket->SetAttribute("Sack", BooleanValue(m_sackState));
    return socket;
}

void
TcpDsackSackTest::Tx(const Ptr<const Packet> p, const TcpHeader& h, SocketWho who)
{
    if ((h.GetFlags() & TcpHeader::SYN))
    {
        if (!m_sackState)
        {
            NS_TEST_ASSERT_MSG_EQ(h.HasOption(TcpOption::SACKPERMITTED),
                                  false,
                                  "SackPermitted disabled if sack is disabled");
        }
        else
        {
            NS_TEST_ASSERT_MSG_EQ(h.HasOption(TcpOption::SACKPERMITTED),
                                  true,
                                  "SackPermitted disabled but option enabled");
        }
    }
}

void
TcpDsackSackTest::TestDuplicateSegment()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;

    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(1), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(101), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestOutOfOrderSegment()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(301));
    rxBuf.Add(p, h);

    NS_TEST_ASSERT_MSG_EQ(rxBuf.NextRxSequence(),
                          SequenceNumber32(201),
                          "Sequence number differs from expected");

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;
    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(1), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(101), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestDuplicateOutOfOrderSegment()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    TcpOptionSack::SackList sackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(201));
    rxBuf.Add(p, h);

    NS_TEST_ASSERT_MSG_EQ(rxBuf.NextRxSequence(),
                          SequenceNumber32(101),
                          "Sequence number differs from expected");

    h.SetSequenceNumber(SequenceNumber32(301));
    rxBuf.Add(p, h);

    rxBuf.Add(p, h);

    sackList = rxBuf.GetSackList();
    NS_TEST_ASSERT_MSG_EQ(sackList.size(), 1, "SACK list should contain one element");
    auto it = sackList.begin();
    NS_TEST_ASSERT_MSG_EQ(it->first, SequenceNumber32(201), "SACK block different than expected");
    NS_TEST_ASSERT_MSG_EQ(it->second, SequenceNumber32(401), "SACK block different than expected");

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;
    NS_TEST_ASSERT_MSG_EQ(dsackList.size(), 1, "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(301), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(401), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestSingleDuplicateSegment()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    TcpOptionSack::SackList sackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(301));
    rxBuf.Add(p, h);

    NS_TEST_ASSERT_MSG_EQ(rxBuf.NextRxSequence(),
                          SequenceNumber32(101),
                          "Sequence number differs from expected");

    sackList = rxBuf.GetSackList();
    NS_TEST_ASSERT_MSG_EQ(sackList.size(), 1, "SACK list should contain one element");
    auto it = sackList.begin();
    NS_TEST_ASSERT_MSG_EQ(it->first, SequenceNumber32(301), "SACK block different than expected");
    NS_TEST_ASSERT_MSG_EQ(it->second, SequenceNumber32(401), "SACK block different than expected");

    Ptr<Packet> p2 = Create<Packet>(100);
    p = Create<Packet>(200);
    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p2, h);
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;
    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(101), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(201), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestSegmentsCoveredByAck()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    TcpOptionSack::SackList sackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(501));
    rxBuf.Add(p, h);

    NS_TEST_ASSERT_MSG_EQ(rxBuf.NextRxSequence(),
                          SequenceNumber32(101),
                          "Sequence number differs from expected");

    sackList = rxBuf.GetSackList();
    NS_TEST_ASSERT_MSG_EQ(sackList.size(), 1, "SACK list should contain one element");
    auto it = sackList.begin();
    NS_TEST_ASSERT_MSG_EQ(it->first, SequenceNumber32(501), "SACK block different than expected");
    NS_TEST_ASSERT_MSG_EQ(it->second, SequenceNumber32(601), "SACK block different than expected");

    Ptr<Packet> p2 = Create<Packet>(100);
    p = Create<Packet>(300);
    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p2, h);
    h.SetSequenceNumber(SequenceNumber32(301));
    rxBuf.Add(p2, h);
    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;
    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(101), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(201), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestSegmentsNotCoveredByAck()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    TcpOptionSack::SackList sackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(601));
    rxBuf.Add(p, h);

    NS_TEST_ASSERT_MSG_EQ(rxBuf.NextRxSequence(),
                          SequenceNumber32(101),
                          "Sequence number differs from expected");

    sackList = rxBuf.GetSackList();
    NS_TEST_ASSERT_MSG_EQ(sackList.size(), 1, "SACK list should contain one element");
    auto it = sackList.begin();
    NS_TEST_ASSERT_MSG_EQ(it->first, SequenceNumber32(601), "SACK block different than expected");
    NS_TEST_ASSERT_MSG_EQ(it->second, SequenceNumber32(701), "SACK block different than expected");

    Ptr<Packet> p2 = Create<Packet>(100);
    p = Create<Packet>(300);
    h.SetSequenceNumber(SequenceNumber32(201));
    rxBuf.Add(p2, h);
    h.SetSequenceNumber(SequenceNumber32(401));
    rxBuf.Add(p2, h);
    sackList = rxBuf.GetSackList();
    NS_TEST_ASSERT_MSG_EQ(sackList.size(), 3, "SACK list should contain one element");
    it = sackList.begin();
    NS_TEST_ASSERT_MSG_EQ(it->first, SequenceNumber32(401), "SACK block different than expected");
    NS_TEST_ASSERT_MSG_EQ(it->second, SequenceNumber32(501), "SACK block different than expected");
    h.SetSequenceNumber(SequenceNumber32(201));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;
    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(201), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(301), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestDuplicateByNetwork()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;

    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(101), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(201), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestFalseRetransmit()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(201));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(301));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(401));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;

    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(101), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(201), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestRetransmitTimeout()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(201));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(301));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;

    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(1), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(101), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestEarlyRetransmitTimeout()
{
    TcpRxBuffer rxBuf;
    TcpOptionSack::SackList dsackList;
    Ptr<Packet> p = Create<Packet>(100);
    TcpHeader h;

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.SetNextRxSequence(SequenceNumber32(1));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    h.SetSequenceNumber(SequenceNumber32(1));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    SequenceNumber32 head = dsackList.front().first;
    SequenceNumber32 tail = dsackList.front().second;

    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(1), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(101), "DSack Block differs from expected");

    h.SetSequenceNumber(SequenceNumber32(101));
    rxBuf.Add(p, h);

    dsackList = rxBuf.GetDsackList();
    head = dsackList.front().first;
    tail = dsackList.front().second;

    NS_TEST_ASSERT_MSG_EQ(head, SequenceNumber32(101), "DSack Block differs from expected");
    NS_TEST_ASSERT_MSG_EQ(tail, SequenceNumber32(201), "DSack Block differs from expected");
}

void
TcpDsackSackTest::TestDsack()
{
    TestDuplicateSegment();
    TestOutOfOrderSegment();
    TestDuplicateOutOfOrderSegment();
    TestSingleDuplicateSegment();
    TestSegmentsCoveredByAck();
    TestSegmentsNotCoveredByAck();
    TestDuplicateByNetwork();
    TestFalseRetransmit();
    TestRetransmitTimeout();
    TestEarlyRetransmitTimeout();
}

void
TcpDsackSackTest::DoRun()
{
    TestDsack();
}

/**
 * @ingroup internet-test
 *
 * @brief Test suite for verifying TCP D-SACK behavior under duplicate,
 *        out-of-order, and retransmission scenarios.
 *
 * Verifies:
 *  - Correct negotiation of SACK and D-SACK options
 *  - Accurate generation of D-SACK blocks for duplicate segments
 */
class TcpDsackTestSuite : public TestSuite
{
  public:
    TcpDsackTestSuite()
        : TestSuite("tcp-dsack-test", Type::UNIT)
    {
        AddTestCase(new TcpDsackSackTest(true, true, "Sack enable"), TestCase::Duration::QUICK);
        AddTestCase(new TcpDsackSackTest(false, true, "Sack disable"), TestCase::Duration::QUICK);
        AddTestCase(new TcpDsackSackTest(true, false, "Sack enable and D-SACK disable"),
                    TestCase::Duration::QUICK);
    }
};

/**
 * @brief Static variable for test initialization
 */
static TcpDsackTestSuite g_TcpDsackTestSuite;
