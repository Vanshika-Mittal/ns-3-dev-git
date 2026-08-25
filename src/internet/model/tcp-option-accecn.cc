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

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("TcpOptionAccEcn");

NS_OBJECT_ENSURE_REGISTERED(TcpOptionAccEcn);

TcpOptionAccEcn::TcpOptionAccEcn()
    : TcpOptionExperimental(),
      m_e0b(0),
      m_ceb(0),
      m_e1b(0)
{
}

TcpOptionAccEcn::~TcpOptionAccEcn()
{
}

TypeId
TcpOptionAccEcn::GetTypeId()
{
    static TypeId tid = TypeId("ns3::TcpOptionAccEcn")
                            .SetParent<TcpOptionExperimental>()
                            .SetGroupName("Internet")
                            .AddConstructor<TcpOptionAccEcn>();
    return tid;
}

void
TcpOptionAccEcn::Print(std::ostream& os) const
{
    os << "e0b: " << m_e0b << " ceb: " << m_ceb << " e1b: " << m_e1b;
}

uint32_t
TcpOptionAccEcn::GetSerializedSize() const
{
    NS_LOG_FUNCTION(this);
    // 2: Kind(1 byte) + Length(1 byte)
    // 2: ExID for magic number(2 bytes)
    // 3*3: option content field with 3 counters * 3 bytes for each counter
    return 13;
}

void
TcpOptionAccEcn::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this);
    Buffer::Iterator i = start;
    i.WriteU8(GetKind());
    auto length = static_cast<uint8_t>(GetSerializedSize());
    i.WriteU8(length);
    i.WriteHtonU16(GetExID());

    // Write e0b (3 bytes, big-endian)
    auto high16 = static_cast<uint16_t>((m_e0b & 0xFFFF00) >> 8);
    auto low8 = static_cast<uint8_t>(m_e0b & 0xFF);
    i.WriteHtonU16(high16);
    i.WriteU8(low8);

    // Write ceb (3 bytes, big-endian)
    high16 = static_cast<uint16_t>((m_ceb & 0xFFFF00) >> 8);
    low8 = static_cast<uint8_t>(m_ceb & 0xFF);
    i.WriteHtonU16(high16);
    i.WriteU8(low8);

    // Write e1b (3 bytes, big-endian)
    high16 = static_cast<uint16_t>((m_e1b & 0xFFFF00) >> 8);
    low8 = static_cast<uint8_t>(m_e1b & 0xFF);
    i.WriteHtonU16(high16);
    i.WriteU8(low8);
}

uint32_t
TcpOptionAccEcn::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this);
    Buffer::Iterator i = start;
    uint8_t readKind = i.ReadU8();
    uint8_t size = i.ReadU8();
    uint16_t exID = i.ReadNtohU16();
    if (readKind != GetKind() || exID != GetExID())
    {
        NS_LOG_WARN("Malformed AccEcn option, wrong type");
        return 0;
    }
    NS_LOG_LOGIC("Size: " << static_cast<uint32_t>(size));

    // Read e0b (3 bytes, big-endian)
    auto high16 = static_cast<uint32_t>(i.ReadNtohU16());
    auto low8 = static_cast<uint32_t>(i.ReadU8());
    m_e0b = (high16 << 8) + low8;

    // Read ceb (3 bytes, big-endian)
    high16 = static_cast<uint32_t>(i.ReadNtohU16());
    low8 = static_cast<uint32_t>(i.ReadU8());
    m_ceb = (high16 << 8) + low8;

    // Read e1b (3 bytes, big-endian)
    high16 = static_cast<uint32_t>(i.ReadNtohU16());
    low8 = static_cast<uint32_t>(i.ReadU8());
    m_e1b = (high16 << 8) + low8;

    return GetSerializedSize();
}

uint16_t
TcpOptionAccEcn::GetExID() const
{
    return TcpOptionExperimental::ACCECN;
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
    m_e0b = e0b;
}

void
TcpOptionAccEcn::SetCEB(uint32_t ceb)
{
    m_ceb = ceb;
}

void
TcpOptionAccEcn::SetE1B(uint32_t e1b)
{
    m_e1b = e1b;
}

} // namespace ns3