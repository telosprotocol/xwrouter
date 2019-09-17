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
#include "xgossip/gossip_interface.h"

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

class WrouterXipHandler : public WrouterHandler {
public:
    WrouterXipHandler(
            transport::TransportPtr transport_ptr,
            std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr,
            std::shared_ptr<gossip::GossipInterface> set_layer_gossip_ptr);
 
    ~WrouterXipHandler();

public:
    virtual int32_t SendPacket(base::xpacket_t& packet) override;
    virtual int32_t RecvPacket(base::xpacket_t& packet) override;
    virtual int32_t SendToLocal(base::xpacket_t& packet) override;
    virtual int32_t SendDirect(
            base::xpacket_t& packet,
            const std::string& ip,
            uint16_t port) override;

private:
    Xip2Header* ParserXip2Header(base::xpacket_t& packet);
    bool ParserDesXip(Xip2Header* xip2_header, base::XipParser& des_xip);
    uint64_t ParserServiceType(uint64_t to_xip_addr_low, uint64_t to_xip_addr_high);

    bool MulticastPacketCheck(Xip2Header* xip2_header);
    bool GossipPacketCheck(Xip2Header* xip2_header);

    int32_t SendMulticast(Xip2Header* xip2_header, base::xpacket_t& packet);
    int32_t SendGossip(Xip2Header* xip2_header, base::xpacket_t& packet);
    int32_t SendGeneral(Xip2Header* xip2_header, base::xpacket_t& packet);

    // judge packet arrive the dest or not
    int32_t JudgeOwnPacket(base::xpacket_t& packet);
    int32_t JudgeOwnPacketMulticast(Xip2Header* xip2_header, base::xpacket_t& packet);

    int32_t GossipBroadcast(
            const std::string& routing_local_id,
            base::xpacket_t& packet,
            const std::vector<kadmlia::NodeInfoPtr>& neighbors,
            bool use_filter);
    int32_t SendData(
            base::xpacket_t& packet,
            const std::vector<kadmlia::NodeInfoPtr>& neighbors,
            uint32_t next_size,
            bool broadcast_stride);

private:
    DISALLOW_COPY_AND_ASSIGN(WrouterXipHandler);
};

} // namespace wrouter 

} // namespace top
