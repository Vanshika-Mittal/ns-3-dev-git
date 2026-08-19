/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Wenying Dai <dwy927@gmail.com>
 *         Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

#ifndef TCP_ACCECN_DATA_H
#define TCP_ACCECN_DATA_H

#include "ns3/object.h"
#include "ns3/traced-value.h"

namespace ns3
{

/**
 * @ingroup tcp
 *
 * @brief Holds sender and receiver Accurate ECN (AccECN) state counters and traces.
 *
 * Implements counter structures and tracking specified in draft-ietf-tcpm-accurate-ecn.
 */
class TcpAccEcnData : public Object
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    /**
     * @brief Constructor.
     */
    TcpAccEcnData();

    /**
     * @brief Destructor.
     */
    ~TcpAccEcnData() override = default;

    /**
     * @brief Initialize sender counters upon connection establishment.
     */
    void IniSenderCounters();

    /**
     * @brief Initialize receiver counters upon connection establishment.
     */
    void IniReceiverCounters();

    // Sender mirrored counters (s.*)
    TracedValue<uint32_t> m_ecnCepS{0}; ///< Sender CE packet counter
    TracedValue<uint32_t> m_ecnCebS{0}; ///< Sender CE payload byte counter
    TracedValue<uint32_t> m_ecnE0bS{0}; ///< Sender ECT(0) payload byte counter
    TracedValue<uint32_t> m_ecnE1bS{0}; ///< Sender ECT(1) payload byte counter

    // Receiver local counters (r.*)
    TracedValue<uint32_t> m_ecnCepR{0}; ///< Receiver CE packet counter
    TracedValue<uint32_t> m_ecnCebR{0}; ///< Receiver CE payload byte counter
    TracedValue<uint32_t> m_ecnE0bR{0}; ///< Receiver ECT(0) payload byte counter
    TracedValue<uint32_t> m_ecnE1bR{0}; ///< Receiver ECT(1) payload byte counter

    bool m_useDelAckAccEcn{true}; ///< Flag for change-triggered delayed ACKs

  private:
    bool m_isIniS{false}; ///< Whether sender counters have been initialized
    bool m_isIniR{false}; ///< Whether receiver counters have been initialized
};

} // namespace ns3

#endif /* TCP_ACCECN_DATA_H */
