/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Wenying Dai <dwy927@gmail.com>
 *         Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

#include "tcp-accecn-data.h"

#include "ns3/log.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("TcpAccEcnData");
NS_OBJECT_ENSURE_REGISTERED(TcpAccEcnData);

TypeId
TcpAccEcnData::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::TcpAccEcnData")
            .SetParent<Object>()
            .SetGroupName("Internet")
            .AddConstructor<TcpAccEcnData>()
            .AddTraceSource("AccEcnCepS",
                            "Sender CE packet count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnCepS),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnCebS",
                            "Sender CE byte count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnCebS),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnE0bS",
                            "Sender ECT0 byte count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnE0bS),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnE1bS",
                            "Sender ECT1 byte count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnE1bS),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnCepR",
                            "Receiver CE packet count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnCepR),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnCebR",
                            "Receiver CE byte count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnCebR),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnE0bR",
                            "Receiver ECT0 byte count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnE0bR),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("AccEcnE1bR",
                            "Receiver ECT1 byte count",
                            MakeTraceSourceAccessor(&TcpAccEcnData::m_ecnE1bR),
                            "ns3::TracedValueCallback::Uint32");
    return tid;
}

TcpAccEcnData::TcpAccEcnData()
    : Object()
{
    NS_LOG_FUNCTION(this);
}

void
TcpAccEcnData::IniSenderCounters()
{
    NS_LOG_FUNCTION(this);
    if (!m_isIniS)
    {
        m_isIniS = true;
        m_ecnCepS = 5; // Initialized to 5 per draft-ietf-tcpm-accurate-ecn Section 3.2.3.1
        m_ecnE0bS = 1;
        m_ecnCebS = 0;
        m_ecnE1bS = 0;
    }
}

void
TcpAccEcnData::IniReceiverCounters()
{
    NS_LOG_FUNCTION(this);
    if (!m_isIniR)
    {
        m_isIniR = true;
        m_ecnCepR = 5; // Initialized to 5 per draft-ietf-tcpm-accurate-ecn Section 3.2.3.1
        m_ecnE0bR = 1;
        m_ecnCebR = 0;
        m_ecnE1bR = 0;
    }
}

} // namespace ns3
