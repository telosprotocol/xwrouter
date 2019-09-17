// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/message_handler/xwrouter_xip_handler.h"

#include <algorithm>

#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xpbase/base/xip_parser.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/routing_utils.h"
#include "xwrouter/register_routing_table.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xpbase/base/xip_parser.h"
#include "xkad/routing_table/client_node_manager.h"
#include "xkad/routing_table/dynamic_xip_manager.h"
#include "xtransport/utils/transport_utils.h"
//#include "xtransport/message_manager/multi_message_handler.h"
#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xpbase/base/uint64_bloomfilter.h"
#include "xpbase/base/redis_client.h"
#include "xkad/gossip/rumor_filter.h"
#include "xgossip/include/broadcast_layered.h"
#include "xgossip/include/gossip_bloomfilter.h"
#include "xgossip/include/gossip_bloomfilter_layer.h"
#include "xgossip/include/gossip_utils.h"
#include "xbase/xutl.h"
#include "xtransport/message_manager/message_manager_intf.h"

namespace top {

using namespace kadmlia;
using namespace gossip;

namespace wrouter {

WrouterXipHandler::WrouterXipHandler(
        transport::TransportPtr transport_ptr,
        std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> setlayer_gossip_ptr)
        : WrouterHandler(
                transport_ptr,
                bloom_gossip_ptr,
                layered_gossip_ptr,
                bloom_layer_gossip_ptr,
                setlayer_gossip_ptr) {}

WrouterXipHandler::~WrouterXipHandler() {}

int32_t WrouterXipHandler::SendPacket(base::xpacket_t& packet) {
    Xip2Header* xip2_header = ParserXip2Header(packet);
    if (!xip2_header) {
        TOP_WARN("xip2_header invalid, wsend failed");
        return enum_xerror_code_fail;
    }

    if (MulticastPacketCheck(xip2_header)) {
        return SendMulticast(xip2_header, packet);
    }

    if (GossipPacketCheck(xip2_header)) {
        return SendGossip(xip2_header, packet);
    }

    return SendGeneral(xip2_header, packet);
}

int32_t WrouterXipHandler::RecvPacket(base::xpacket_t& packet) {
    int32_t judgeown_code = JudgeOwnPacket(packet);

    switch (judgeown_code) {
        case kJudgeOwnError: {
            TOP_WARN("RecvBaseXid failed");
            return kRecvError;
        }
        case kJudgeOwnYes: {
            return kRecvOwn;
        }
        case kJudgeOwnNoAndContinue: {
            SendPacket(packet);
            return kRecvOk;
        }
        case kJudgeOwnYesAndContinue: {
            SendPacket(packet);
            return kRecvOwn;
        }
        default:
            break;
    }

    return kRecvOk;
}

int32_t WrouterXipHandler::SendDirect(
        base::xpacket_t& packet,
        const std::string& ip,
        uint16_t port) {
    packet.set_to_ip_addr(ip);
    packet.set_to_ip_port(port);
    return transport_ptr_->SendData(packet);
}

int32_t WrouterXipHandler::SendToLocal(base::xpacket_t& packet) {
    return transport_ptr_->SendToLocal(packet);
}

// parse xip2_header from packet
Xip2Header* WrouterXipHandler::ParserXip2Header(base::xpacket_t& packet)
{
    if((size_t)packet.get_size() < enum_xip2_header_len)//test size of header and body together
    {
        TOP_WARN("xip2_header_len invalid, packet_size(%d) smaller than enum_xip2_header_len(%d)",
                packet.get_body().size(),
                enum_xip2_header_len);
        return nullptr;
    }
    if(packet.get_header().size() > 0)
        return (Xip2Header*)(packet.get_header().data());
    else
        return (Xip2Header*)(packet.get_body().data());
}


bool WrouterXipHandler::ParserDesXip(Xip2Header* xip2_header, base::XipParser& des_xip) {
    if (!xip2_header) {
        TOP_WARN("xip2_header invalid");
        return false;
    }
    base::XipParser tmp_des_xip(xip2_header->to_xaddr_high, xip2_header->to_xaddr_low);
    des_xip = tmp_des_xip;
    return des_xip.valid();
}

uint64_t WrouterXipHandler::ParserServiceType(uint64_t to_xip_addr_low, uint64_t to_xip_addr_high) {
    base::XipParser xip_par(to_xip_addr_high, to_xip_addr_low);
    if (!xip_par.valid()) {
        return kInvalidType;
    }
    auto kad_key_ptr = base::GetKadmliaKey(xip_par);
    return kad_key_ptr->GetServiceType();
}

int32_t WrouterXipHandler::SendGeneral(Xip2Header* xip2_header, base::xpacket_t& packet) {
    base::XipParser des_xip;
    if (!ParserDesXip(xip2_header, des_xip)) {
        TOP_WARN("ParserDesXip failed");
        return enum_xerror_code_bad_packet;
    }

    auto kad_key_ptr = base::GetKadmliaKey(des_xip);
    uint64_t d_service_type = kad_key_ptr->GetServiceType();

    // TODO(smaug) there is another way to use root network, getrootnodes first than send
    RoutingTablePtr routing_table = FindRoutingTable(false, d_service_type, true);
    if (!routing_table) {
        TOP_WARN("FindRoutingTable failed");
        return enum_xerror_code_fail;
    }

    // choose one src_xip for this packet
    if (xip2_header->from_xaddr_low == 0 && xip2_header->from_xaddr_high == 0) {
        base::XipParser src_xip = routing_table->get_local_node_info()->GetXipParser();
        uint64_t src_high, src_low;
        src_xip.xip(src_high, src_low);
        xip2_header->from_xaddr_low = src_low;
        xip2_header->from_xaddr_high = src_high;
    }

    std::string des_xip_str = des_xip.xip();
    std::vector<kadmlia::NodeInfoPtr> nodes = GetClosestNodes(
            routing_table,
            des_xip_str,
            //kBroadcastGeneral,
            8,
            true);
    if (nodes.empty()) {
        TOP_WARN("GetClosestNodes failed");
        return enum_xerror_code_fail;
    }
    // TODO(smaug)
    return SendData(packet, nodes, kBroadcastGeneral, false);
}

int32_t WrouterXipHandler::GossipBroadcast(
        const std::string& routing_local_id,
        base::xpacket_t& packet,
        const std::vector<kadmlia::NodeInfoPtr>& neighbors,
        bool use_filter) {
    // TODO(smaug)
    return 0;
}

int32_t WrouterXipHandler::SendData(
        base::xpacket_t& packet,
        const std::vector<kadmlia::NodeInfoPtr>& neighbors,
        uint32_t next_size,
        bool broadcast_stride) {
    if (neighbors.empty()) {
        TOP_WARN("invliad neighbors");
        return enum_xerror_code_fail;
    }
    Xip2Header* header_ptr = ParserXip2Header(packet);
    if (header_ptr == nullptr) {
        TOP_WARN("bad packet header");
        return enum_xerror_code_bad_packet;
    }
    header_ptr->TTL += 1;
    std::vector<NodeInfoPtr> rest_neighbors;
    for (uint32_t i = 0; i < neighbors.size(); ++i) {
        NodeInfoPtr node_ptr = neighbors[i];
        if ((node_ptr->xid).empty()) {
            TOP_WARN("xid empty");
            continue;
        }

        rest_neighbors.push_back(node_ptr);
        if (rest_neighbors.size() >= next_size) {
            break;
        }
    }

    base::xpacket_t tmp_packet;
    tmp_packet.copy_from(packet);
    auto each_call = [this, &packet, &tmp_packet] (kadmlia::NodeInfoPtr node_info_ptr) {
        if (!node_info_ptr) {
            TOP_WARN("kadmlia::NodeInfoPtr null");
            return false;
        }
        packet.reset();
        packet.copy_from(tmp_packet);
        packet.set_to_ip_addr(node_info_ptr->public_ip);
        packet.set_to_ip_port(node_info_ptr->public_port);
        if (kadmlia::kKadSuccess != transport_ptr_->SendData(packet)) {
            TOP_WARN("SendData to  endpoint(%s:%d) failed",
                    node_info_ptr->public_ip.c_str(),
                    node_info_ptr->public_port);
            return false;
        }
        return true;
    };

    std::for_each(rest_neighbors.begin(), rest_neighbors.end(), each_call);
    return enum_xcode_successful;
}

int32_t WrouterXipHandler::SendMulticast(Xip2Header* xip2_header, base::xpacket_t& packet){
    base::XipParser des_xip;
    if (!ParserDesXip(xip2_header, des_xip)) {
        TOP_WARN("ParserDesXip failed");
        return enum_xerror_code_bad_packet;
    }
    std::string des_xip_str = des_xip.xip();

    auto kad_key_ptr = base::GetKadmliaKey(des_xip);
    uint64_t d_service_type = kad_key_ptr->GetServiceType();
    // multicast same network
    if (xip2_header->to_xaddr_low == xip2_header->from_xaddr_low
            && xip2_header->to_xaddr_high == xip2_header->from_xaddr_high) {
        RoutingTablePtr routing_table = FindRoutingTable(false, d_service_type, false);
        if (!routing_table) {
            TOP_WARN("FindRoutingTable failed");
            return enum_xerror_code_fail;
        }

        std::vector<kadmlia::NodeInfoPtr> nodes = GetClosestNodes(
                routing_table,
                des_xip_str,
                kBroadcastMax,
                true);
        if (nodes.empty()) {
            TOP_WARN("GetClosestNodes failed");
            return enum_xerror_code_fail;
        }
        return GossipBroadcast(routing_table->get_local_node_info()->id(), packet, nodes, true);
    }

    // multicast to different network
    // attention the third parameter, the reason setting true is des is different network,there is  need for kRoot
    RoutingTablePtr routing_table = FindRoutingTable(false, d_service_type, true);
    if (!routing_table) {
        TOP_WARN("FindRoutingTable failed");
        return enum_xerror_code_fail;
    }

    if (routing_table->get_local_node_info()->GetXipParser().xnetwork_id() == top::kRoot) {
        // when packet arrive des network, than,multi_flag = default_value,that is kBroadcastGossip
        std::vector<kadmlia::NodeInfoPtr> nodes = GetClosestNodes(
                routing_table,
                des_xip_str,
                8,
                false);

        if (nodes.empty()) {
            TOP_WARN("GetClosestNodes failed");
            return enum_xerror_code_fail;
        }
        return SendData(packet, nodes, 1, true);
    }

    return GossipBroadcast(
            routing_table->get_local_node_info()->id(),
            packet,
            routing_table->nodes(),
            true);
}


int32_t WrouterXipHandler::SendGossip(Xip2Header* xip2_header, base::xpacket_t& packet) {
    auto kad_key_ptr = base::GetKadmliaKey();
    kad_key_ptr->set_xnetwork_id(top::kRoot);
    kad_key_ptr->set_network_type(top::kRoleService);
    uint64_t d_service_type = kad_key_ptr->GetServiceType();
    RoutingTablePtr routing_table = FindRoutingTable(true, d_service_type, true);
    if (!routing_table) {
        TOP_WARN("FindRoutingTable failed");
        return enum_xerror_code_fail;
    }

    return GossipBroadcast(
            routing_table->get_local_node_info()->id(),
            packet,
            routing_table->nodes(),
            true);
}

int32_t WrouterXipHandler::JudgeOwnPacket(base::xpacket_t& packet) {
    Xip2Header* xip2_header = ParserXip2Header(packet);
    if (!xip2_header) {
        TOP_WARN("xip2_header invalid, JudgeOwnPacket failed");
        return kJudgeOwnError;
    }

    if (GossipPacketCheck(xip2_header)) {
        // gossip for kRoot, any node will handle this packet
        return kJudgeOwnYesAndContinue;
    }

    base::XipParser des_xip;
    if (!ParserDesXip(xip2_header, des_xip)) {
        return kJudgeOwnError;
    }

   // broadcast to different network or the same network, exclude kRoot
    if (MulticastPacketCheck(xip2_header)) {
        return JudgeOwnPacketMulticast(xip2_header, packet);
    }

    auto kad_key = GetKadmliaKey(des_xip);
    uint64_t d_service_type = kad_key->GetServiceType();
    RoutingTablePtr routing_table = FindRoutingTable(false, d_service_type, false);
    if (!routing_table) {
        return kJudgeOwnNoAndContinue;
    }
    
    std::string des_xip_str = des_xip.xip();
    std::string match_kad_xip = routing_table->get_local_node_info()->xip();

    if (match_kad_xip.compare(des_xip_str) == 0 ) {
        return kJudgeOwnYes;
    }

    // for now, just three cases:
    // 1: this is client node , and has more than one kad_xip
    // 2: this is node which dispatch dynamic xip for client, so next step will send to client
    // 3: this is node which is just not the dest node
    
    if (routing_table->get_local_node_info()->HasDynamicXip(des_xip_str)) {
        // usually this is client
        return kJudgeOwnYes;
    }

    kadmlia::ClientNodeInfoPtr client_info_ptr = routing_table->get_dy_manager()->FindClientNode(des_xip_str);
    if (client_info_ptr) {
        packet.set_to_ip_addr(client_info_ptr->public_ip);
        packet.set_to_ip_port(client_info_ptr->public_port);
        transport_ptr_->SendData(packet);

        return kJudgeOwnNo;
    }

    return kJudgeOwnNoAndContinue;
}


int32_t WrouterXipHandler::JudgeOwnPacketMulticast(Xip2Header* xip2_header, base::xpacket_t& packet) {
    base::XipParser des_xip;
    if (!ParserDesXip(xip2_header, des_xip)) {
        TOP_WARN("ParserDesXip failed");
        return kJudgeOwnError;
    }
    std::string des_xip_str = des_xip.xip();
    auto kad_key = base::GetKadmliaKey(des_xip);
    uint64_t d_service_type = kad_key->GetServiceType();
    // multicast same network
    if (xip2_header->to_xaddr_low == xip2_header->from_xaddr_low
            && xip2_header->to_xaddr_high == xip2_header->from_xaddr_high) {

        // attention the third parameter, the reason setting false is at same network, no need for kRoot
        RoutingTablePtr routing_table = FindRoutingTable(false, d_service_type, false);
        if (!routing_table) {
            TOP_WARN("FindRoutingTable failed");
            return kJudgeOwnError;
        }

        // find the same network
        return kJudgeOwnYesAndContinue;
    }

    // multicast to different network
    RoutingTablePtr routing_table = FindRoutingTable(false, d_service_type, false);
    if (!routing_table) {
        TOP_WARN("FindRoutingTable failed");
        return kJudgeOwnNoAndContinue;
    }
    // find the target network(different from own network)
    return kJudgeOwnYesAndContinue;
}

bool WrouterXipHandler::MulticastPacketCheck(Xip2Header* xip2_header) {
    if (xip2_header->flags == enum_xpacket_multicast_flag) {
        return true;
    }
    return false;
}

// equal broadcast
bool WrouterXipHandler::GossipPacketCheck(Xip2Header* xip2_header) {
    if (xip2_header->flags == enum_xpacket_gossip_flag) {
        return true;
    }
    return false;
}

} // namespace wrouter 

} // namespace top
