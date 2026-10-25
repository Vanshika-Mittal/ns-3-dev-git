/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Wenying Dai <dwy927@gmail.com>
 *          Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

#include "tcp-option-accecn.h"

#include "ns3/log.h"

#include <algorithm>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("TcpOptionAccEcn");

NS_OBJECT_ENSURE_REGISTERED(TcpOptionAccEcn);
NS_OBJECT_ENSURE_REGISTERED(TcpOptionAccEcn0);
NS_OBJECT_ENSURE_REGISTERED(TcpOptionAccEcn1);

namespace
{

/**
 * Helper to write a 24-bit integer in big-endian network byte order.
 *
 * @param i the Buffer::Iterator to write to
 * @param val the 24-bit value to write
 */
void
Write24(Buffer::Iterator& i, uint32_t val)
{
    i.WriteU8(static_cast<uint8_t>((val >> 16) & 0xFF));
    i.WriteU8(static_cast<uint8_t>((val >> 8) & 0xFF));
    i.WriteU8(static_cast<uint8_t>(val & 0xFF));
}

/**
 * Helper to read a 24-bit integer in big-endian network byte order.
 *
 * @param i the Buffer::Iterator to read from
 * @return the 24-bit value read
 */
uint32_t
Read24(Buffer::Iterator& i)
{
    uint32_t b0 = i.ReadU8();
    uint32_t b1 = i.ReadU8();
    uint32_t b2 = i.ReadU8();
    return (b0 << 16) | (b1 << 8) | b2;
}

} // namespace

TcpOptionAccEcn::TcpOptionAccEcn()
    : TcpOption(),
      m_e0b(0),
      m_ceb(0),
      m_e1b(0),
      m_length(11)
{
}

TcpOptionAccEcn::~TcpOptionAccEcn()
{
}

TypeId
TcpOptionAccEcn::GetTypeId()
{
    static TypeId tid = TypeId("ns3::TcpOptionAccEcn")
                            .SetParent<TcpOption>()
                            .SetGroupName("Internet")
                            .AddConstructor<TcpOptionAccEcn>();
    return tid;
}

uint8_t
TcpOptionAccEcn::GetKind() const
{
    return TcpOption::ACCECN0;
}

uint8_t
TcpOptionAccEcn::GetFieldOrder() const
{
    return 0;
}

void
TcpOptionAccEcn::Print(std::ostream& os) const
{
    os << "Kind: " << static_cast<int>(GetKind()) << " Length: " << static_cast<int>(m_length);
    if (HasE0B())
    {
        os << " e0b: " << m_e0b;
    }
    if (HasCEB())
    {
        os << " ceb: " << m_ceb;
    }
    if (HasE1B())
    {
        os << " e1b: " << m_e1b;
    }
}

uint32_t
TcpOptionAccEcn::GetSerializedSize() const
{
    NS_LOG_FUNCTION(this);
    return m_length;
}

void
TcpOptionAccEcn::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this);
    Buffer::Iterator i = start;
    i.WriteU8(GetKind());
    auto length = static_cast<uint8_t>(GetSerializedSize());
    i.WriteU8(length);

    if (length < 2)
    {
        return;
    }

    uint8_t numFields = (length - 2) / 3;
    uint32_t field1 = (GetFieldOrder() == 0) ? m_e0b : m_e1b;
    uint32_t field2 = m_ceb;
    uint32_t field3 = (GetFieldOrder() == 0) ? m_e1b : m_e0b;

    if (numFields >= 1)
    {
        Write24(i, field1);
    }
    if (numFields >= 2)
    {
        Write24(i, field2);
    }
    if (numFields >= 3)
    {
        Write24(i, field3);
    }

    // Write trailing padding bytes (if any) as zeros
    uint8_t written = 2 + std::min(static_cast<uint8_t>(3), numFields) * 3;
    while (written < length)
    {
        i.WriteU8(0);
        ++written;
    }
}

uint32_t
TcpOptionAccEcn::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this);
    Buffer::Iterator i = start;
    uint8_t readKind = i.ReadU8();
    uint8_t size = i.ReadU8();

    if (readKind != GetKind())
    {
        NS_LOG_WARN("Malformed AccECN option, wrong kind: " << static_cast<int>(readKind));
        return 0;
    }
    if (size < 2 || size > 40)
    {
        NS_LOG_WARN("Malformed AccECN option, invalid size: " << static_cast<int>(size));
        return 0;
    }

    m_length = size;
    uint8_t numFields = (size - 2) / 3;

    if (numFields >= 1)
    {
        uint32_t val = Read24(i);
        if (GetFieldOrder() == 0)
        {
            m_e0b = val;
        }
        else
        {
            m_e1b = val;
        }
    }
    if (numFields >= 2)
    {
        m_ceb = Read24(i);
    }
    if (numFields >= 3)
    {
        uint32_t val = Read24(i);
        if (GetFieldOrder() == 0)
        {
            m_e1b = val;
        }
        else
        {
            m_e0b = val;
        }
    }

    // Skip extra fields or trailing padding bytes per RFC 9768 Section 3.2.3
    uint8_t bytesParsed = 2 + std::min(static_cast<uint8_t>(3), numFields) * 3;
    if (size > bytesParsed)
    {
        i.Next(size - bytesParsed);
    }

    return GetSerializedSize();
}

uint32_t
TcpOptionAccEcn::GetE0B() const
{
    return m_e0b;
}

uint32_t
TcpOptionAccEcn::GetCEB() const
{
    return m_ceb;
}

uint32_t
TcpOptionAccEcn::GetE1B() const
{
    return m_e1b;
}

void
TcpOptionAccEcn::SetE0B(uint32_t e0b)
{
    m_e0b = e0b & 0xFFFFFF;
}

void
TcpOptionAccEcn::SetCEB(uint32_t ceb)
{
    m_ceb = ceb & 0xFFFFFF;
}

void
TcpOptionAccEcn::SetE1B(uint32_t e1b)
{
    m_e1b = e1b & 0xFFFFFF;
}

bool
TcpOptionAccEcn::HasE0B() const
{
    uint8_t numFields = (m_length >= 2) ? (m_length - 2) / 3 : 0;
    if (GetFieldOrder() == 0)
    {
        return numFields >= 1;
    }
    else
    {
        return numFields >= 3;
    }
}

bool
TcpOptionAccEcn::HasCEB() const
{
    uint8_t numFields = (m_length >= 2) ? (m_length - 2) / 3 : 0;
    return numFields >= 2;
}

bool
TcpOptionAccEcn::HasE1B() const
{
    uint8_t numFields = (m_length >= 2) ? (m_length - 2) / 3 : 0;
    if (GetFieldOrder() == 0)
    {
        return numFields >= 3;
    }
    else
    {
        return numFields >= 1;
    }
}

void
TcpOptionAccEcn::SetLength(uint8_t length)
{
    m_length = length;
}

uint8_t
TcpOptionAccEcn::GetLength() const
{
    return m_length;
}

// ----------------------------------------------------------------------------
// TcpOptionAccEcn0 (Kind 172, Order 0)
// ----------------------------------------------------------------------------

TcpOptionAccEcn0::TcpOptionAccEcn0()
    : TcpOptionAccEcn()
{
}

TcpOptionAccEcn0::~TcpOptionAccEcn0()
{
}

TypeId
TcpOptionAccEcn0::GetTypeId()
{
    static TypeId tid = TypeId("ns3::TcpOptionAccEcn0")
                            .SetParent<TcpOptionAccEcn>()
                            .SetGroupName("Internet")
                            .AddConstructor<TcpOptionAccEcn0>();
    return tid;
}

uint8_t
TcpOptionAccEcn0::GetKind() const
{
    return TcpOption::ACCECN0;
}

uint8_t
TcpOptionAccEcn0::GetFieldOrder() const
{
    return 0;
}

// ----------------------------------------------------------------------------
// TcpOptionAccEcn1 (Kind 174, Order 1)
// ----------------------------------------------------------------------------

TcpOptionAccEcn1::TcpOptionAccEcn1()
    : TcpOptionAccEcn()
{
}

TcpOptionAccEcn1::~TcpOptionAccEcn1()
{
}

TypeId
TcpOptionAccEcn1::GetTypeId()
{
    static TypeId tid = TypeId("ns3::TcpOptionAccEcn1")
                            .SetParent<TcpOptionAccEcn>()
                            .SetGroupName("Internet")
                            .AddConstructor<TcpOptionAccEcn1>();
    return tid;
}

uint8_t
TcpOptionAccEcn1::GetKind() const
{
    return TcpOption::ACCECN1;
}

uint8_t
TcpOptionAccEcn1::GetFieldOrder() const
{
    return 1;
}

} // namespace ns3
