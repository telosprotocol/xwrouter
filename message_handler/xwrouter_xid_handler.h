// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "xwrouter/message_handler/xwrouter_handler.h"
#include "xkad/routing_table/callback_manager.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"
#include "xbase/xbase.h"
#include "xbase/xrouter.h"
#include "xgossip/include/broadcast_layered.h"

namespace top {

namespace transport {
class MultiThreadHandler;
class Transport;
typedef std::shared_ptr<Transport> TransportPtr;

namespace protobuf {
class RoutingMessage;
};
};

namespace base {
class XipParser;
};

namespace kadmlia {
class RoutingTable;
struct NodeInfo;
typedef std::shared_ptr<RoutingTable> RoutingTablePtr;
typedef std::shared_ptr<NodeInfo> NodeInfoPtr;
};

namespace gossip {
class GossipInterface;
}

namespace wrouter {

using Xip2Header = _xip2_header;

class WrouterXidHandler : public WrouterHandler {
public:
    WrouterXidHandler(
            transport::TransportPtr transport_ptr,
            std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> set_layer_gossip_ptr);
 
    ~WrouterXidHandler();
public:
    virtual int32_t SendPacket(transport::protobuf::RoutingMessage& message) override;
    virtual int32_t RecvPacket(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    int32_t SendToLocal(transport::protobuf::RoutingMessage& message);
    int32_t SendDirect(
            transport::protobuf::RoutingMessage& message,
            const std::string& ip,
            uint16_t port);
    void SupportRandomPattern();
    bool BroadcastByMultiRandomKadKey(
            const transport::protobuf::RoutingMessage& message,
            kadmlia::ResponseFunctor call_back,
            int64_t recursive_count = kRecursiveCount);
protected:
    uint64_t ParserServiceType(const std::string& kad_key);
    bool SendToByRandomNeighbors(
            const transport::protobuf::RoutingMessage& message);
    int32_t RandomlyCommunicate(
            transport::protobuf::RoutingMessage& message);
    void SendLinksAckToPeer(
        uint64_t src_message_id,
        const std::string& src_node_id,
        const std::string& peer_ip,
        uint16_t peer_port,
        uint64_t ack_type);

    bool MulticastPacketCheck(transport::protobuf::RoutingMessage& message);
    bool GossipPacketCheck(transport::protobuf::RoutingMessage& message);

    int32_t SendMulticast(transport::protobuf::RoutingMessage& message);
    int32_t SendGossip(transport::protobuf::RoutingMessage& message);
    int32_t SendGeneral(transport::protobuf::RoutingMessage& message);

    // judge packet arrive the dest or not
    int32_t JudgeOwnPacket(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    int32_t GossipBroadcast(
            transport::protobuf::RoutingMessage& message,
            kadmlia::RoutingTablePtr& routing_table);
    int32_t SendData(
            transport::protobuf::RoutingMessage& message,
            const std::vector<kadmlia::NodeInfoPtr>& neighbors,
            uint32_t next_size,
            bool broadcast_stride);
    int32_t HandleClientMessage(
            transport::protobuf::RoutingMessage& message,
            kadmlia::RoutingTablePtr routing_table);
    bool HandleSystemMessage(
            transport::protobuf::RoutingMessage& message,
            kadmlia::RoutingTablePtr& routing_table);

private:
    bool support_random_pattern_ {false};

    DISALLOW_COPY_AND_ASSIGN(WrouterXidHandler);
};

} // namespace wrouter 

} // namespace top
