// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "xbase/xbase.h"
#include "xbase/xrouter.h"

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

class WrouterHandler {
public:
    WrouterHandler(
            transport::TransportPtr transport_ptr,
            std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> set_layer_gossip_ptr);
    virtual ~WrouterHandler();

    // xip
    virtual int32_t SendPacket(base::xpacket_t& packet) { return 0; }
    virtual int32_t RecvPacket(base::xpacket_t& packet) { return 0; }
    virtual int32_t SendToLocal(base::xpacket_t& packet) { return 0; }
    virtual int32_t SendDirect(
            base::xpacket_t& packet,
            const std::string& ip,
            uint16_t port) { return 0; }

    // xid
    virtual int32_t SendPacket(transport::protobuf::RoutingMessage& message) { return 0; }
    virtual int32_t RecvPacket(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet) { return 0; }
    virtual int32_t SendToLocal(transport::protobuf::RoutingMessage& message) { return 0; }
    virtual int32_t SendDirect(
            transport::protobuf::RoutingMessage& message,
            const std::string& ip,
            uint16_t port) { return 0; }

    virtual bool CloserToTarget(
            const std::string& id1,
            const std::string& id2,
            const std::string& target_id);

protected:
    kadmlia::RoutingTablePtr FindRoutingTable(
            bool is_root,
            uint64_t service_type,
            bool root_backup,
            const std::string msg_des_node_id = "");
    std::vector<kadmlia::NodeInfoPtr> GetClosestNodes(
            kadmlia::RoutingTablePtr routing_table,
            const std::string& target_id,
            uint32_t number_to_get,
            bool base_xip);
    std::vector<kadmlia::NodeInfoPtr> GetRandomNodes(std::vector<kadmlia::NodeInfoPtr>& neighbors,uint32_t number_to_get) const;

protected:
    transport::TransportPtr transport_ptr_;
    std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr_;
    std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr_;
    std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr_;
    std::shared_ptr<gossip::GossipInterface> set_layer_gossip_ptr_;
};

} // namespace wrouter 

} // namespace top
