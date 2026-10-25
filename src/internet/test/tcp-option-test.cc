/*
 * Copyright (c) 2014 Natale Patriciello <natale.patriciello@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ns3/random-variable-stream.h"
#include "ns3/tcp-option-ts.h"
#include "ns3/tcp-option-winscale.h"
#include "ns3/tcp-option-accecn.h"
#include "ns3/tcp-option.h"
#include "ns3/test.h"

#include <string.h>

using namespace ns3;

/**
 * @ingroup internet-test
 *
 * @brief TCP Window Scaling option Test
 */
class TcpOptionWSTestCase : public TestCase
{
  public:
    /**
     * @brief Constructor.
     * @param name Test description.
     * @param scale Window scaling.
     */
    TcpOptionWSTestCase(std::string name, uint8_t scale);

    /**
     * @brief Serialization test.
     */
    void TestSerialize();
    /**
     * @brief Deserialization test.
     */
    void TestDeserialize();

  private:
    void DoRun() override;
    void DoTeardown() override;

    uint8_t m_scale; //!< Window scaling.
    Buffer m_buffer; //!< Buffer.
};

TcpOptionWSTestCase::TcpOptionWSTestCase(std::string name, uint8_t scale)
    : TestCase(name)
{
    m_scale = scale;
}

void
TcpOptionWSTestCase::DoRun()
{
    TestSerialize();
    TestDeserialize();
}

void
TcpOptionWSTestCase::TestSerialize()
{
    TcpOptionWinScale opt;

    opt.SetScale(m_scale);
    NS_TEST_EXPECT_MSG_EQ(m_scale, opt.GetScale(), "Scale isn't saved correctly");

    m_buffer.AddAtStart(opt.GetSerializedSize());

    opt.Serialize(m_buffer.Begin());
}

void
TcpOptionWSTestCase::TestDeserialize()
{
    TcpOptionWinScale opt;

    Buffer::Iterator start = m_buffer.Begin();
    uint8_t kind = start.PeekU8();

    NS_TEST_EXPECT_MSG_EQ(kind, TcpOption::WINSCALE, "Different kind found");

    opt.Deserialize(start);

    NS_TEST_EXPECT_MSG_EQ(m_scale, opt.GetScale(), "Different scale found");
}

void
TcpOptionWSTestCase::DoTeardown()
{
}

/**
 * @ingroup internet-test
 *
 * @brief TCP TimeStamp option Test
 */
class TcpOptionTSTestCase : public TestCase
{
  public:
    /**
     * @brief Constructor.
     * @param name Test description.
     */
    TcpOptionTSTestCase(std::string name);

    /**
     * @brief Serialization test.
     */
    void TestSerialize();
    /**
     * @brief Deserialization test.
     */
    void TestDeserialize();

  private:
    void DoRun() override;
    void DoTeardown() override;

    uint32_t m_timestamp; //!< TimeStamp.
    uint32_t m_echo;      //!< Echoed TimeStamp.
    Buffer m_buffer;      //!< Buffer.
};

TcpOptionTSTestCase::TcpOptionTSTestCase(std::string name)
    : TestCase(name)
{
    m_timestamp = 0;
    m_echo = 0;
}

void
TcpOptionTSTestCase::DoRun()
{
    Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable>();

    for (uint32_t i = 0; i < 1000; ++i)
    {
        m_timestamp = x->GetInteger();
        m_echo = x->GetInteger();
        TestSerialize();
        TestDeserialize();
    }
}

void
TcpOptionTSTestCase::TestSerialize()
{
    TcpOptionTS opt;

    opt.SetTimestamp(m_timestamp);
    opt.SetEcho(m_echo);

    NS_TEST_EXPECT_MSG_EQ(m_timestamp, opt.GetTimestamp(), "TS isn't saved correctly");
    NS_TEST_EXPECT_MSG_EQ(m_echo, opt.GetEcho(), "echo isn't saved correctly");

    m_buffer.AddAtStart(opt.GetSerializedSize());

    opt.Serialize(m_buffer.Begin());
}

void
TcpOptionTSTestCase::TestDeserialize()
{
    TcpOptionTS opt;

    Buffer::Iterator start = m_buffer.Begin();
    uint8_t kind = start.PeekU8();

    NS_TEST_EXPECT_MSG_EQ(kind, TcpOption::TS, "Different kind found");

    opt.Deserialize(start);

    NS_TEST_EXPECT_MSG_EQ(m_timestamp, opt.GetTimestamp(), "Different TS found");
    NS_TEST_EXPECT_MSG_EQ(m_echo, opt.GetEcho(), "Different echo found");
}

void
TcpOptionTSTestCase::DoTeardown()
{
}

/**
 * @ingroup internet-test
 *
 * @brief TCP AccEcn option Test
 */
class TcpOptionAccEcnTestCase : public TestCase
{
  public:
    /**
     * @brief Constructor.
     * @param name Test description.
     */
    TcpOptionAccEcnTestCase(std::string name);

  private:
    void DoRun() override;

    uint32_t m_e0b;  ///< the number of TCP payload bytes marked with ECT(0)
    uint32_t m_ceb;  ///< the number of TCP payload bytes marked with CE
    uint32_t m_e1b;  ///< the number of TCP payload bytes marked with ECT(1)
};

TcpOptionAccEcnTestCase::TcpOptionAccEcnTestCase(std::string name)
    : TestCase(name),
      m_e0b(0),
      m_ceb(0),
      m_e1b(0)
{
}

void
TcpOptionAccEcnTestCase::DoRun()
{
    Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable>();
    std::vector<uint8_t> lengths = {11, 8, 5, 2};

    for (uint8_t len : lengths)
    {
        for (uint32_t i = 0; i < 100; ++i)
        {
            m_e0b = (x->GetInteger() & 0xFFFFFF);
            m_ceb = (x->GetInteger() & 0xFFFFFF);
            m_e1b = (x->GetInteger() & 0xFFFFFF);

            // Test AccECN0 (Order 0, Kind 172)
            {
                TcpOptionAccEcn0 opt0;
                opt0.SetLength(len);
                opt0.SetE0B(m_e0b);
                opt0.SetCEB(m_ceb);
                opt0.SetE1B(m_e1b);

                Buffer buf;
                buf.AddAtStart(opt0.GetSerializedSize());
                opt0.Serialize(buf.Begin());

                Buffer::Iterator start = buf.Begin();
                uint8_t kind = start.PeekU8();
                NS_TEST_EXPECT_MSG_EQ(kind, TcpOption::ACCECN0, "AccECN0: Different kind found");

                TcpOptionAccEcn0 opt0Rx;
                uint32_t bytesRead = opt0Rx.Deserialize(start);
                NS_TEST_EXPECT_MSG_EQ(bytesRead, len, "AccECN0: Incorrect bytes read");
                NS_TEST_EXPECT_MSG_EQ(opt0Rx.GetLength(), len, "AccECN0: Incorrect length");

                if (opt0Rx.HasE0B())
                {
                    NS_TEST_EXPECT_MSG_EQ(opt0Rx.GetE0B(), m_e0b, "AccECN0: E0B mismatch");
                }
                if (opt0Rx.HasCEB())
                {
                    NS_TEST_EXPECT_MSG_EQ(opt0Rx.GetCEB(), m_ceb, "AccECN0: CEB mismatch");
                }
                if (opt0Rx.HasE1B())
                {
                    NS_TEST_EXPECT_MSG_EQ(opt0Rx.GetE1B(), m_e1b, "AccECN0: E1B mismatch");
                }
            }

            // Test AccECN1 (Order 1, Kind 174)
            {
                TcpOptionAccEcn1 opt1;
                opt1.SetLength(len);
                opt1.SetE0B(m_e0b);
                opt1.SetCEB(m_ceb);
                opt1.SetE1B(m_e1b);

                Buffer buf;
                buf.AddAtStart(opt1.GetSerializedSize());
                opt1.Serialize(buf.Begin());

                Buffer::Iterator start = buf.Begin();
                uint8_t kind = start.PeekU8();
                NS_TEST_EXPECT_MSG_EQ(kind, TcpOption::ACCECN1, "AccECN1: Different kind found");

                TcpOptionAccEcn1 opt1Rx;
                uint32_t bytesRead = opt1Rx.Deserialize(start);
                NS_TEST_EXPECT_MSG_EQ(bytesRead, len, "AccECN1: Incorrect bytes read");
                NS_TEST_EXPECT_MSG_EQ(opt1Rx.GetLength(), len, "AccECN1: Incorrect length");

                if (opt1Rx.HasE0B())
                {
                    NS_TEST_EXPECT_MSG_EQ(opt1Rx.GetE0B(), m_e0b, "AccECN1: E0B mismatch");
                }
                if (opt1Rx.HasCEB())
                {
                    NS_TEST_EXPECT_MSG_EQ(opt1Rx.GetCEB(), m_ceb, "AccECN1: CEB mismatch");
                }
                if (opt1Rx.HasE1B())
                {
                    NS_TEST_EXPECT_MSG_EQ(opt1Rx.GetE1B(), m_e1b, "AccECN1: E1B mismatch");
                }
            }
        }
    }
}

/**
 * @ingroup internet-test
 *
 * @brief TCP options TestSuite
 */
class TcpOptionTestSuite : public TestSuite
{
  public:
    TcpOptionTestSuite()
        : TestSuite("tcp-option", Type::UNIT)
    {
        for (uint8_t i = 0; i < 15; ++i)
        {
            AddTestCase(new TcpOptionWSTestCase("Testing window scale value", i),
                        TestCase::Duration::QUICK);
        }
        AddTestCase(new TcpOptionTSTestCase("Testing serialization of random values for timestamp"),
                    TestCase::Duration::QUICK);
        AddTestCase(new TcpOptionAccEcnTestCase("Testing e0b,ceb,e1b for AccEcn option"),
                    TestCase::Duration::QUICK);
    }
};

static TcpOptionTestSuite g_TcpOptionTestSuite; //!< Static variable for test initialization
