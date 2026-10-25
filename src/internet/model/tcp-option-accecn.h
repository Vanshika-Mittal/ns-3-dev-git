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
 * @ingroup tcp
 *
 * @brief Base class for Accurate ECN (AccECN) TCP Options (RFC 9768).
 *
 * AccECN provides supplementary feedback on arriving ECN markings using
 * TCP options carrying 24-bit counters for ECT(0), CE, and ECT(1) bytes.
 * Two option kinds are defined by RFC 9768: AccECN0 (Kind 172, Order 0)
 * and AccECN1 (Kind 174, Order 1).
 */
class TcpOptionAccEcn : public TcpOption
{
  public:
    TcpOptionAccEcn();
    ~TcpOptionAccEcn() override;

    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    uint32_t GetSerializedSize() const override;

    uint8_t GetKind() const override;

    /**
     * @brief Get the field ordering of this option (0 for Order 0, 1 for Order 1).
     * @return 0 for AccECN0, 1 for AccECN1
     */
    virtual uint8_t GetFieldOrder() const;

    /**
     * @brief Get the ECT(0) byte counter.
     * @return the ECT(0) byte count (24-bit)
     */
    uint32_t GetE0B() const;

    /**
     * @brief Get the CE byte counter.
     * @return the CE byte count (24-bit)
     */
    uint32_t GetCEB() const;

    /**
     * @brief Get the ECT(1) byte counter.
     * @return the ECT(1) byte count (24-bit)
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

    /**
     * @brief Check whether the ECT(0) byte counter field is present in this option.
     * @return true if EE0B is present
     */
    bool HasE0B() const;

    /**
     * @brief Check whether the CE byte counter field is present in this option.
     * @return true if ECEB is present
     */
    bool HasCEB() const;

    /**
     * @brief Check whether the ECT(1) byte counter field is present in this option.
     * @return true if EE1B is present
     */
    bool HasE1B() const;

    /**
     * @brief Set the serialized length of the option in octets.
     * @param length the option length (e.g. 11, 8, 5, or 2)
     */
    void SetLength(uint8_t length);

    /**
     * @brief Get the serialized length of the option in octets.
     * @return the option length
     */
    uint8_t GetLength() const;

  protected:
    uint32_t m_e0b{0};    ///< TCP payload bytes marked with ECT(0) (24 bits)
    uint32_t m_ceb{0};    ///< TCP payload bytes marked with CE (24 bits)
    uint32_t m_e1b{0};    ///< TCP payload bytes marked with ECT(1) (24 bits)
    uint8_t m_length{11}; ///< Option length in bytes (RFC 9768 Table 5: 11, 8, 5, 2, etc.)
};

/**
 * @ingroup tcp
 *
 * @brief AccECN Order 0 TCP option (Kind 172, RFC 9768).
 *
 * Order 0 layout:
 * - Length 11: EE0B (3B), ECEB (3B), EE1B (3B)
 * - Length 8:  EE0B (3B), ECEB (3B)
 * - Length 5:  EE0B (3B)
 * - Length 2:  empty (Kind + Length only)
 */
class TcpOptionAccEcn0 : public TcpOptionAccEcn
{
  public:
    TcpOptionAccEcn0();
    ~TcpOptionAccEcn0() override;

    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    uint8_t GetKind() const override;
    uint8_t GetFieldOrder() const override;
};

/**
 * @ingroup tcp
 *
 * @brief AccECN Order 1 TCP option (Kind 174, RFC 9768).
 *
 * Order 1 layout:
 * - Length 11: EE1B (3B), ECEB (3B), EE0B (3B)
 * - Length 8:  EE1B (3B), ECEB (3B)
 * - Length 5:  EE1B (3B)
 * - Length 2:  empty (Kind + Length only)
 */
class TcpOptionAccEcn1 : public TcpOptionAccEcn
{
  public:
    TcpOptionAccEcn1();
    ~TcpOptionAccEcn1() override;

    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    uint8_t GetKind() const override;
    uint8_t GetFieldOrder() const override;
};

} // namespace ns3

#endif /* TCP_OPTION_ACCECN_H */
