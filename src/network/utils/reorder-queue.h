/*
 * Copyright (c) 2007 University of Washington
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 *
 */

#ifndef REORDER_QUEUE_H
#define REORDER_QUEUE_H

#include "queue-size.h"
#include "queue.h"

#include <queue>

namespace ns3
{

/**
 * @ingroup queue
 *
 * @brief A FIFO packet queue that drops tail-end packets on overflow
 */
template <typename Item>
class ReorderQueue : public Queue<Item>
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();
    /**
     * @brief ReorderQueue Constructor
     *
     * Creates a droptail queue with a maximum size of 100 packets by default
     */
    ReorderQueue();

    ~ReorderQueue() override;

    bool Enqueue(Ptr<Item> item) override;
    Ptr<Item> Dequeue() override;
    Ptr<Item> Remove() override;
    Ptr<const Item> Peek() const override;

  private:
    QueueSize m_maxSize; //!< max queue size
    using Queue<Item>::GetContainer;
    using Queue<Item>::DoEnqueue;
    using Queue<Item>::DoDequeue;
    using Queue<Item>::DoRemove;
    using Queue<Item>::DoPeek;
    using Queue<Item>::DropBeforeEnqueue;
    std::queue<Ptr<Item>> m_packets; //!< the packets in the queue
    uint32_t m_bytesInQueue;         //!< actual bytes in the queue
    uint32_t m_reorderDepth;         //!< the maximum reorder buffer depth
    uint32_t m_inSequenceLength;     //!< the length of in-sequence packet burst
    uint32_t m_holdCount;            //!< number of packets currently held for reordering
    uint32_t m_inSequenceCount;      //!< number of in-order packets delivered
    Ptr<Packet> m_held;              //!< pointer to the currently held packet/item

    NS_LOG_TEMPLATE_DECLARE; //!< redefinition of the log component
};

} // namespace ns3

#endif /* REORDER_QUEUE_H */
