/*
 * Copyright (c) 2018 Tsinghua University
 * Copyright (c) 2018 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Wenying Dai <dwy927@gmail.com>
 *          Mohit P. Tahiliani <tahiliani.nitk@gmail.com>
 */

#ifndef TCP_OPTION_ACCECN_H
#define TCP_OPTION_ACCECN_H

#include "tcp-option.h"

namespace ns3
{

/**
 * @brief Defines the AccECN TCP option.
 *
 * Carries ECT(0), CE, and ECT(1) byte counters as 3-byte fields.
 * Uses experimental option kind (254) with ExID 0xACCE.
 */
class TcpOptionAccEcn : public TcpOptionExperimental
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    TcpOptionAccEcn();
    ~TcpOptionAccEcn() override;

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    uint32_t GetSerializedSize() const override;

    uint16_t GetExID() const override;

    /**
     * @brief Get the ECT(0) byte counter.
     * @return the ECT(0) byte count
     */
    uint32_t GetE0B() const;
    /**
     * @brief Get the CE byte counter.
     * @return the CE byte count
     */
    uint32_t GetCEB() const;
    /**
     * @brief Get the ECT(1) byte counter.
     * @return the ECT(1) byte count
     */
    uint32_t GetE1B() const;
    /**
     * @brief Set the ECT(0) byte counter.
     * @param e0b the ECT(0) byte count
     */
    void SetE0B(uint32_t e0b);
    /**
     * @brief Set the CE byte counter.
     * @param ceb the CE byte count
     */
    void SetCEB(uint32_t ceb);
    /**
     * @brief Set the ECT(1) byte counter.
     * @param e1b the ECT(1) byte count
     */
    void SetE1B(uint32_t e1b);

  protected:
    uint32_t m_e0b; ///< TCP payload bytes marked with ECT(0)
    uint32_t m_ceb; ///< TCP payload bytes marked with CE
    uint32_t m_e1b; ///< TCP payload bytes marked with ECT(1)
};

} // namespace ns3

#endif /* TCP_OPTION_ACCECN */