// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/message_handler/xwrouter_xid_handler.h"

#include <algorithm>

#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xpbase/base/xip_parser.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#include "xpbase/base/top_utils.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/routing_utils.h"
#include "xwrouter/register_routing_table.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xpbase/base/xip_parser.h"
#include "xkad/routing_table/client_node_manager.h"
#include "xkad/routing_table/dynamic_xip_manager.h"
#include "xtransport/utils/transport_utils.h"
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
#include "xpbase/base/redis_utils.h"
#include "xgossip/include/gossip_filter.h"

namespace top {

using namespace kadmlia;
using namespace gossip;

namespace wrouter {

WrouterXidHandler::WrouterXidHandler(
        transport::TransportPtr transport_ptr,
        std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> set_layer_gossip_ptr)
        : WrouterHandler(
                transport_ptr,
                bloom_gossip_ptr,
                layered_gossip_ptr,
                bloom_layer_gossip_ptr,
                set_layer_gossip_ptr) {}

WrouterXidHandler::~WrouterXidHandler() {}

int32_t WrouterXidHandler::SendPacket(transport::protobuf::RoutingMessage& message) {
    if (message.des_node_id().empty()) {
        TOP_WARN2("send illegal");
        return enum_xerror_code_fail;
    }
    if (message.hop_num() >= kadmlia::kHopToLive) {
        TOP_WARN2("stop SendPacket hop_num(%d) beyond max_hop_num(%d)",
                message.hop_num(),
                kadmlia::kHopToLive);
        return enum_xerror_code_fail;
    }
    int ret = RandomlyCommunicate(message);
    if(enum_xerror_code_no_resource != ret) {
        TOP_WARN2("enum_xerror_code_no_resource");
        return ret;
    }

    if (message.src_node_id().empty()) {
        // choose one random(right) id for this message
        uint64_t service_type = ParserServiceType(message.des_node_id());
        RoutingTablePtr routing_table = nullptr;
        if (message.has_is_root() && message.is_root()) {
            routing_table = FindRoutingTable(true, static_cast<uint64_t>(kRoot), true, message.des_node_id());
        } else {
            // attention: the last parameter set false is necessary
            routing_table = FindRoutingTable(false, service_type, false);
        }

        if (!routing_table) {
            TOP_WARN2("FindRoutingTable failed");
            return enum_xerror_code_fail;
        }
        message.set_src_node_id(routing_table->get_local_node_info()->id());
    }

    if (GossipPacketCheck(message)) {
        return SendGossip(message);
    }

    if (MulticastPacketCheck(message)) {
        return SendMulticast(message);
    }

    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("SendPacket base xid", message);
    return SendGeneral(message);
}


int32_t WrouterXidHandler::SendToLocal(transport::protobuf::RoutingMessage& message) {
    std::string data;
    if (!message.SerializeToString(&data)) {
        TOP_WARN2("wrouter message SerializeToString failed");
        return enum_xerror_code_fail;
    }

    uint8_t local_buf[kUdpPacketBufferSize];
    base::xpacket_t packet(base::xcontext_t::instance(), local_buf, sizeof(local_buf), 0, false);
    Xip2Header header;
    memset(&header, 0, sizeof(header));
    packet.get_body().push_back((uint8_t*)&header, enum_xip2_header_len);
    packet.get_body().push_back((uint8_t*)data.data(), data.size());
    return transport_ptr_->SendToLocal(packet);
}

int32_t WrouterXidHandler::SendDirect(
        transport::protobuf::RoutingMessage& message,
        const std::string& ip,
        uint16_t port) {
    std::string data;
    if (!message.SerializeToString(&data)) {
        TOP_WARN2("wrouter message SerializeToString failed");
        return enum_xerror_code_fail;
    }

    uint8_t local_buf[kUdpPacketBufferSize];
    base::xpacket_t packet(base::xcontext_t::instance(), local_buf, sizeof(local_buf), 0, false);
    Xip2Header header;
    memset(&header, 0, sizeof(header));
    packet.get_body().push_back((uint8_t*)&header, enum_xip2_header_len);
    packet.get_body().push_back((uint8_t*)data.data(), data.size());
    packet.set_to_ip_addr(ip);
    packet.set_to_ip_port(port);
    return transport_ptr_->SendData(packet);
}

int32_t WrouterXidHandler::RecvPacket(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    int32_t judgeown_code = JudgeOwnPacket(message, packet);

    switch (judgeown_code) {
        case kJudgeOwnError: {
            TOP_WARN2("RecvBaseXid failed");
            return kRecvError;
        }
        case kJudgeOwnYes: {
            return kRecvOwn;
        }
        case kJudgeOwnNoAndContinue: {
            SendPacket(message);
            return kRecvOk;
        }
        case kJudgeOwnYesAndContinue: {
            SendPacket(message);
            return kRecvOwn;
        }
        default:
            break;
    }

    return kRecvOk;
}

uint64_t WrouterXidHandler::ParserServiceType(const std::string& kad_key) {
    auto kad_key_ptr = base::GetKadmliaKey(kad_key);
    return kad_key_ptr->GetServiceType();
}

bool WrouterXidHandler::BroadcastByMultiRandomKadKey(
        const transport::protobuf::RoutingMessage& message,
        kadmlia::ResponseFunctor call_back,
        int64_t recursive_count) {
    auto main_call_back = [this,recursive_count,call_back](int status,transport::protobuf::RoutingMessage& message,base::xpacket_t& packet) {
        if(kKadTimeout == status) {
            if(0 == recursive_count) {
                return;
            }
            int64_t next_recursive_count = recursive_count - 1;
            BroadcastByMultiRandomKadKey(message,call_back,next_recursive_count);
            return;
        }
        call_back(status,message,packet);
    };
    uint32_t channel_size = kMaxChannelSize;   
    uint32_t message_id =  CallbackManager::MessageId();
    CallbackManager::Instance()->Add(message_id, kEnoughSuccessAckTimeout, main_call_back, 1);
    while(channel_size--) {
        auto des_service_type = ParserServiceType(message.des_node_id());
        auto kad_key = std::make_shared<base::PlatformKadmliaKey>(des_service_type);
        transport::protobuf::RoutingMessage mutil_channel_message;
        mutil_channel_message.set_id(message_id);
        mutil_channel_message.set_des_node_id(kad_key->Get());
        std::string data;
        if (!message.SerializeToString(&data)) {
            TOP_WARN2("wrouter message SerializeToString failed");
            continue;
        }
        mutil_channel_message.set_is_root(message.is_root());
        mutil_channel_message.set_broadcast(true);
        mutil_channel_message.set_data(data);
        mutil_channel_message.set_xid(global_xid->Get());
        mutil_channel_message.set_type(kKadBroadcastFromMultiChannelRequest);
        mutil_channel_message.set_enable_ack(true);
        if(enum_xerror_code_fail == SendPacket(mutil_channel_message)) {
            TOP_WARN2("SendAfterAchiveMultiChannel failed");
            continue;
        }
    }
    return true;
}

bool WrouterXidHandler::SendToByRandomNeighbors(
        const transport::protobuf::RoutingMessage& message) {
    std::string src_node_id = message.src_node_id();
    if(src_node_id.empty()) {
        TOP_WARN2("src node id invalid.");
        return false;
    }
    uint64_t service_type = ParserServiceType(message.des_node_id());
    RoutingTablePtr routing_table = nullptr;
    if (message.has_is_root() && message.is_root()) {
        routing_table = FindRoutingTable(true, static_cast<uint64_t>(kRoot), true, message.des_node_id());
    } else {
        routing_table = FindRoutingTable(false, service_type, true, message.des_node_id());
    }

    if (!routing_table) {
        TOP_WARN2("FindRoutingTable failed");
        return false;
    }
    std::string des_xid = message.des_node_id();
    std::vector<kadmlia::NodeInfoPtr> nodes = GetClosestNodes(
            routing_table,
            des_xid,
            kP2pRandomNumGeneral,
            false);
    std::string data;
    if (!message.SerializeToString(&data)) {
        TOP_WARN2("wrouter message SerializeToString failed");
        return false;
    }
    auto it_find = std::find_if(
        nodes.begin(),
        nodes.end(),
        [des_xid](const kadmlia::NodeInfoPtr& node_info_ptr) {  
        return node_info_ptr->node_id == des_xid; 
    });
    if(it_find != nodes.end()) {
        nodes = { *it_find };
    }
    for(auto& node_ptr : nodes) {
        if(!node_ptr) {
            continue;
        }
        transport::protobuf::RoutingMessage send_to_message;
        send_to_message.set_is_root(message.is_root());
        send_to_message.set_broadcast(false);
        send_to_message.set_data(data);
        send_to_message.set_xid(global_xid->Get());
        send_to_message.set_type(kKadSendToFromRandomNeighborsRequest);
        send_to_message.set_enable_ack(false);
        send_to_message.set_des_node_id(node_ptr->node_id);
        if(enum_xerror_code_fail == SendPacket(send_to_message)) {
            TOP_WARN2("SendToByRandomNeighbors failed");
            continue;
        }
    }
    
    return true;
}

void WrouterXidHandler::SendLinksAckToPeer(
        uint64_t src_message_id,
        const std::string& src_node_id,
        const std::string& peer_ip,
        uint16_t peer_port,
        uint64_t ack_type) {
    transport::protobuf::RoutingMessage message;
    message.set_des_node_id(src_node_id);
    message.set_data(base::xstring_utl::tostring(src_message_id));
    message.set_type(ack_type);
    message.set_id(CallbackManager::MessageId());
    message.set_xid(global_xid->Get());
    message.set_broadcast(false);
    std::string msg;
    if (!message.SerializeToString(&msg)) {
        TOP_INFO("RoutingMessage SerializeToString failed!");
        return ;
    }
    xbyte_buffer_t xdata{msg.begin(), msg.end()};

    transport_ptr_->SendData(xdata, peer_ip, peer_port);
}

int32_t WrouterXidHandler::RandomlyCommunicate(
        transport::protobuf::RoutingMessage& message) {
    if(support_random_pattern_) {
        bool ret = true;
        if(message.has_broadcast() && message.broadcast()) {
            auto response_functor = [](int,transport::protobuf::RoutingMessage&,base::xpacket_t&) {};
            ret = BroadcastByMultiRandomKadKey(message,response_functor);
        } else {
            ret = SendToByRandomNeighbors(message);
        }
        return (true == ret ? enum_xcode_successful : enum_xerror_code_fail);
    }
    return enum_xerror_code_no_resource;
}

void WrouterXidHandler::SupportRandomPattern() {
    support_random_pattern_ = true;
}

int32_t WrouterXidHandler::SendGeneral(transport::protobuf::RoutingMessage& message) {
    if (message.des_node_id().empty()) {
        assert(false);
    }

    uint64_t service_type = ParserServiceType(message.des_node_id());
    RoutingTablePtr routing_table = nullptr;
    if (message.has_is_root() && message.is_root()) {
        routing_table = FindRoutingTable(true, static_cast<uint64_t>(kRoot), true, message.des_node_id());
    } else {
        routing_table = FindRoutingTable(false, service_type, true, message.des_node_id());
    }

    if (!routing_table) {
        TOP_WARN2("FindRoutingTable failed");
        return enum_xerror_code_fail;
    }

    std::string des_xid = message.des_node_id();
    std::vector<kadmlia::NodeInfoPtr> nodes = GetClosestNodes(
            routing_table,
            des_xid,
            8,   // choose 8 nodes then use bloomfilter choose kBroadcastGeneral nodes
            false);
    if (nodes.empty()) {
        TOP_WARN2("GetClosestNodes failed[%d][%d]",
                routing_table->nodes_size(),
                routing_table->get_local_node_info()->kadmlia_key()->xnetwork_id());
        return enum_xerror_code_fail;
    }
    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("SendData", message);
    return SendData(message, nodes, kBroadcastGeneral, false);
}

int32_t WrouterXidHandler::SendMulticast(transport::protobuf::RoutingMessage& message) {
    if (message.is_root()) {
        TOP_WARN2("wsend: send multicast base xid invalid, must not root message");
        return enum_xerror_code_fail;
    }
    if (message.src_node_id().empty() || message.des_node_id().empty()) {
        assert(false);
    }
    auto gossip = message.mutable_gossip();
    if (!gossip->has_msg_hash()) {
        std::string bin_data = message.data();
        if (gossip->has_block()) {
            bin_data = gossip->block();
        }
        if (!gossip->has_block() && gossip->has_header_hash()) {
            bin_data = gossip->header_hash();
        }
        uint32_t msg_hash =
            base::xhash32_t::digest(message.xid() + std::to_string(message.id()) + bin_data);
        gossip->set_msg_hash(msg_hash);
    }

    uint64_t des_service_type = ParserServiceType(message.des_node_id());
    RoutingTablePtr routing_table = FindRoutingTable(false, des_service_type, false);
    if (!routing_table || routing_table->nodes_size() == 0) {
        // attention: using the right root-routing (not exactlly kRoot)
        routing_table = FindRoutingTable(true, des_service_type, true, message.des_node_id());
        if (!routing_table) {
            TOP_WARN2("FindRoutingTable failed");
            return enum_xerror_code_fail;
        }

        // when packet arrive des network, than,multi_flag = default_value,that is kBroadcastGossip
        std::vector<kadmlia::NodeInfoPtr> nodes = GetClosestNodes(
                routing_table,
                message.des_node_id(),
                8,
                false);

        if (nodes.empty()) {
            TOP_WARN2("GetClosestNodes failed");
            return enum_xerror_code_fail;
        }
#ifdef TOP_TESTING_PERFORMANCE
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE(
                std::string("SendData with root unicast to other net: ") +
                std::to_string(message.hop_nodes_size()), message);
#endif
        //return SendData(message, nodes, 3, true);
        return SendData(message, nodes, 1, true);
    }

#ifdef TOP_TESTING_PERFORMANCE
    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE(
            std::string("SendData with root broadcast to other net: ") +
            std::to_string(message.hop_nodes_size()), message);
#endif
    return GossipBroadcast(
            message,
            routing_table);
}

int32_t WrouterXidHandler::SendGossip(transport::protobuf::RoutingMessage& message) {
    if (!message.has_is_root() || !message.is_root()) {
        TOP_WARN2("SendGossip must be root_msg");
        return enum_xerror_code_fail;
    }
    auto gossip = message.mutable_gossip();
    if (!gossip->has_msg_hash()) {
        std::string bin_data = message.data();
        if (gossip->has_block()) {
            bin_data = gossip->block();
        }
        if (!gossip->has_block() && gossip->has_header_hash()) {
            bin_data = gossip->header_hash();
        }
        uint32_t msg_hash =
            base::xhash32_t::digest(message.xid() + std::to_string(message.id()) + bin_data);
        gossip->set_msg_hash(msg_hash);
    }

    RoutingTablePtr routing_table = FindRoutingTable(true, static_cast<uint64_t>(kRoot), true, message.des_node_id());
    if (!routing_table) {
        TOP_WARN2("FindRoutingTable failed");
        return enum_xerror_code_fail;
    }

    return GossipBroadcast(
            message,
            routing_table);
}

int32_t WrouterXidHandler::GossipBroadcast(
        transport::protobuf::RoutingMessage& message,
        kadmlia::RoutingTablePtr& routing_table) {
    uint32_t gossip_type = message.gossip().gossip_type();
    if (gossip_type == 0) {
        gossip_type = kGossipBloomfilter;
    }

    auto neighbors = routing_table->GetUnLockNodes();
    if (!neighbors) {
        TOP_WARN2("GetUnLockNodes empty");
        return enum_xerror_code_fail;
    }
    switch (gossip_type) {
    case kGossipBloomfilter:
        bloom_gossip_ptr_->Broadcast(
                routing_table->get_local_node_info()->hash64(),
                message,
                neighbors);
        break;
    case kGossipLayeredBroadcast:
        layered_gossip_ptr_->Broadcast(
                message,
                routing_table);
        break;
    case kGossipBloomfilterAndLayered:
        /*
        bloom_layer_gossip_ptr_->Broadcast(
                routing_table->get_local_node_info()->hash64(),
                message,
                neighbors);
                */
        bloom_layer_gossip_ptr_->Broadcast(message, routing_table);
        break;
    case kGossipSetFilterAndLayered:
        set_layer_gossip_ptr_->Broadcast(
                routing_table->get_local_node_info()->hash64(),
                message,
                neighbors);
        break;
    default:
        TOP_WARN2("invalid gossip_type:%d", gossip_type);
        assert(false);
        break;
    }
    return enum_xcode_successful;
}

int32_t WrouterXidHandler::SendData(
        transport::protobuf::RoutingMessage& message,
        const std::vector<kadmlia::NodeInfoPtr>& neighbors,
        uint32_t next_size,
        bool broadcast_stride) {
    if (neighbors.empty()) {
        TOP_WARN2("invliad neighbors");
        return enum_xerror_code_fail;
    }

    std::vector<NodeInfoPtr> rest_neighbors;
    if (message.broadcast()) {
        auto gossip_info = message.mutable_gossip();
        gossip_info->set_diff_net(broadcast_stride);
        std::vector<uint64_t> new_bloomfilter_vec;
        for (auto i = 0; i < message.bloomfilter_size(); ++i) {
            new_bloomfilter_vec.push_back(message.bloomfilter(i));
        }

        std::shared_ptr<base::Uint64BloomFilter> new_bloomfilter;
	    if (new_bloomfilter_vec.empty()) {
	        new_bloomfilter = std::make_shared<base::Uint64BloomFilter>(
	                gossip::kGossipBloomfilterSize,
	                gossip::kGossipBloomfilterHashNum);
            auto tmp_routing_table = FindRoutingTable(true, static_cast<uint64_t>(kRoot), true, message.des_node_id());
	        new_bloomfilter->Add(tmp_routing_table->get_local_node_info()->hash64());
	    } else {
	        new_bloomfilter = std::make_shared<base::Uint64BloomFilter>(
	                new_bloomfilter_vec,
	                gossip::kGossipBloomfilterHashNum);
	    }
	    for (uint32_t i = 0; i < neighbors.size(); ++i) {
	        NodeInfoPtr node_ptr = neighbors[i];
	        if ((node_ptr->xid).empty()) {
	            TOP_WARN2("xid empty");
	            continue;
	        }

	        if (new_bloomfilter->Contain(node_ptr->hash64) &&
	                node_ptr->node_id != message.des_node_id()) {
#ifdef TOP_TESTING_PERFORMANCE
	            TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE(
	                    std::string("already sended to this node: ") +
	                    HexEncode(node_ptr->xid) +
	                    node_ptr->public_ip + ":" +
	                    check_cast<std::string>(node_ptr->public_port) +
	                    " : " + std::to_string(neighbors.size()),
	                    message);
#endif
	            continue;
	        }

	        rest_neighbors.push_back(node_ptr);
	        new_bloomfilter->Add(node_ptr->hash64);
	        if (rest_neighbors.size() >= next_size) {
	            break;
	        }
	    }

	    const std::vector<uint64_t>& bloomfilter_vec = new_bloomfilter->Uint64Vector();
	    message.clear_bloomfilter();
	    for (uint32_t i = 0; i < bloomfilter_vec.size(); ++i) {
	        message.add_bloomfilter(bloomfilter_vec[i]);
	    }
    }
	base::xpacket_t packet(base::xcontext_t::instance());
    _xip2_header xip2_header;
    memset(&xip2_header, 0, sizeof(xip2_header));
    std::string header((const char*)&xip2_header, sizeof(xip2_header));

    std::string xbody;
    if (!message.SerializeToString(&xbody)) {
        TOP_WARN2("wrouter message SerializeToString failed");
        return enum_xerror_code_fail;
    }

    std::string xdata = header + xbody;

    auto each_call = [this, &packet, &message, neighbors, &xdata] (kadmlia::NodeInfoPtr node_info_ptr) {
        if (!node_info_ptr) {
            TOP_WARN2("kadmlia::NodeInfoPtr null");
            return false;
        }
        packet.reset();
        packet.get_body().push_back((uint8_t*)xdata.data(), xdata.size());
        packet.set_to_ip_addr(node_info_ptr->public_ip);
        packet.set_to_ip_port(node_info_ptr->public_port);
//        if (kadmlia::kKadSuccess != transport_ptr_->SendData(packet)) {
		if (kadmlia::kKadSuccess != transport_ptr_->SendDataWithProp(packet, node_info_ptr->udp_property)) {
            TOP_WARN2("SendData to  endpoint(%s:%d) failed",
                    node_info_ptr->public_ip.c_str(),
                    node_info_ptr->public_port);
            return false;
        }
#ifdef TOP_TESTING_PERFORMANCE
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE(
                std::string("send to: ") +
                node_info_ptr->public_ip + ":" +
                check_cast<std::string>(node_info_ptr->public_port) +
                ":" + std::to_string(neighbors.size()),
                message);
#endif
        return true;
    };

    if (message.broadcast()) {
	    std::for_each(rest_neighbors.begin(), rest_neighbors.end(), each_call);
    } else {
		std::for_each(neighbors.begin(), neighbors.begin()+1, each_call);
    }
    return enum_xcode_successful;
}


bool WrouterXidHandler::HandleSystemMessage(
        transport::protobuf::RoutingMessage& message,
        kadmlia::RoutingTablePtr& routing_table) {
    static std::vector<int32_t> direct_vec = {
        kKadBootstrapJoinRequest,
        kKadBootstrapJoinResponse,
        kKadFindNodesRequest,
        kKadFindNodesResponse,
        kKadHeartbeatRequest,
        kKadHeartbeatResponse,
        kKadHandshake,
        kKadConnectRequest,

        kNatDetectRequest,
        kNatDetectResponse,
        kNatDetectHandshake2Node,
        kNatDetectHandshake2Boot,
        kNatDetectFinish,
        kUdpNatDetectRequest,
        kUdpNatDetectResponse,
        kUdpNatHeartbeat,
        kKadBroadcastFromMultiChannelRequest,
        kKadBroadcastFromMultiChannelAck,
        kKadSendToFromRandomNeighborsRequest,

        kGossipBlockSyncAsk,
        kGossipBlockSyncAck,
        kGossipBlockSyncRequest,
        kGossipBlockSyncResponse,
    };
    auto it = std::find(direct_vec.begin(), direct_vec.end(), message.type());
    if (it != direct_vec.end()) {
        return true;
    }
    /*
    // special for kconnect msg
    if (message.type() == kKadConnectRequest
            || message.type() == kKadConnectResponse) {
        if ((message.des_node_id()).compare(routing_table->get_local_node_info()->id()) == 0) {
            return true;
        }
    }
    */
    return false;
}

int32_t WrouterXidHandler::HandleClientMessage(
        transport::protobuf::RoutingMessage& message,
        kadmlia::RoutingTablePtr routing_table) {
    if (!message.has_client_id()) {
        return kContinueReturn;
    }
    if (!routing_table) {
        return kErrorReturn;
    }

    kadmlia::LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return kErrorReturn;
    }

    if (!message.relay_flag()) {
        if (message.client_id() == local_node->id()) {
            return  kContinueReturn;
        }
        // this is first relay node
        return kFirstRelayRetrun;
    }
    return kContinueReturn;
}

int32_t WrouterXidHandler::JudgeOwnPacket(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
#ifndef NDEBUG
    // for test
    static uint64_t recv_start_time = 0;
    static std::atomic<uint32_t> recv_count(0);
    if (message.type() == kTestChainTrade || message.type() == kTestWpingRequest) {
        if (recv_start_time == 0) {
            recv_start_time = GetCurrentTimeMsec();
        }
        ++recv_count;
        if (recv_count % 10000 == 0) {
            auto use_time_ms = double(GetCurrentTimeMsec() - recv_start_time) / 1000.0;
            uint32_t qps = (uint32_t)((double)recv_count / use_time_ms);
            std::cout << "recv " << recv_count << " use time:" << double(GetCurrentTimeMsec() - recv_start_time)
                << " ms. QPS:" << qps << std::endl;

            TOP_NETWORK_DEBUG_FOR_REDIS(message, "netqps", qps);
        }
    }
#endif

    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE(
            std::string("wrouter recv from: ") + packet.get_from_ip_addr()
            + std::string(":") + std::to_string(packet.get_from_ip_port()) + std::string(" to: ")
            + packet.get_to_ip_addr() + std::string(":") + std::to_string(packet.get_to_ip_port()),
            message);

    // usually only bootstrap message will come here
    if (message.des_node_id().empty()) {
        TOP_DEBUG("message type(%d) id(%d) des_node_id empty", message.type(), message.id());
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYes", message);
        return kJudgeOwnYes;
    }

    if(message.has_enable_ack() && message.enable_ack()
            && kKadBroadcastFromMultiChannelRequest == message.type()) {
        kadmlia::RoutingTablePtr routing_table = GetRoutingTable(kRoot, true);
        auto local_node_info = routing_table->get_local_node_info();
        std::string local_ip = local_node_info->local_ip();
        uint16_t local_port = local_node_info->local_port();
        std::string packet_from_ip = packet.get_from_ip_addr();
        uint16_t packet_from_port = packet.get_from_ip_port();
        if(local_ip != packet_from_ip || local_port != packet_from_port) {       
            SendLinksAckToPeer(
                message.id(),
                message.src_node_id(),
                packet_from_ip,
                packet_from_port,
                static_cast<uint64_t>(kKadBroadcastFromMultiChannelAck));
            message.set_enable_ack(false);
            std::string body;
            if (!message.SerializeToString(&body)) {
                TOP_WARN2("wrouter message SerializeToString failed");
                TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnError", message);
                return kJudgeOwnError;
            }
            std::string header((const char*)packet.get_body().data(), enum_xip2_header_len);
            std::string xdata = header + body;
            packet.reset();
            packet.get_body().push_back((uint8_t*)xdata.data(), xdata.size());
        }
    }

    if(kKadSendToFromRandomNeighborsRequest == message.type()) {
        uint64_t service_type = ParserServiceType(message.des_node_id());
        auto routing_table = FindRoutingTable(message.is_root(), service_type, true, message.des_node_id());
        if (!routing_table) {
            TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnError", message);
            return kJudgeOwnError;
        }
        auto local_node_info = routing_table->get_local_node_info();
        if(local_node_info && message.des_node_id() != local_node_info->id()) {
            if(!SendToByRandomNeighbors(message)) {
                TOP_WARN2("SendToByRandomNeighbors failed");
                TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnError", message);
                return kJudgeOwnError;
            }
        }
    }
     
    if (message.has_broadcast() && message.broadcast()) {
        auto gossip = message.mutable_gossip();
        // TODO(smaug)  get_from_ip_addr decrease performance
        gossip->set_pre_ip(packet.get_from_ip_addr());
        gossip->set_pre_port(packet.get_from_ip_port());
#ifdef TOP_TESTING_PERFORMANCE
        static std::atomic<uint32_t> brt_rcv_count(0);
        static std::atomic<uint32_t> brt_filtered_rcv_count(0);
        static std::atomic<uint32_t> pre_all(0);
        static std::atomic<uint32_t> pre_filtered(0);
        static int64_t b_time = GetCurrentTimeMsec();
        if (message.type() == kBroadcastPerformaceTest) {
            ++brt_rcv_count;
        }
        if (message.type() == kBroadcastPerformaceTestReset || (message.type() == kBroadcastPerformaceTest && brt_rcv_count % 50000 == 0)) {
            auto use_sec_time = (float)(GetCurrentTimeMsec() - b_time) / (float)1000.0;
            b_time = GetCurrentTimeMsec();
            if (use_sec_time > 0.0 && brt_rcv_count > 0) {
                uint32_t tmp_all = brt_rcv_count - pre_all;
                uint32_t tmp_filter = brt_filtered_rcv_count - pre_filtered;
                std::string debug_info = base::StringUtil::str_fmt("brt receive all pkg: %u, qps: %f, filtered: %u, qps: %f",
                        (uint32_t)brt_rcv_count,
                        (float)tmp_all / (float)use_sec_time,
                        (uint32_t)brt_filtered_rcv_count,
                        (float)tmp_filter / (float)use_sec_time);
                std::cout << debug_info << std::endl;
                TOP_ERROR(debug_info.c_str());
            }
            pre_all = (uint32_t)brt_rcv_count;
            pre_filtered = (uint32_t)brt_filtered_rcv_count;
            if (message.type() == kBroadcastPerformaceTestReset) {
                brt_rcv_count = 0;
                brt_filtered_rcv_count = 0;
            }
        }
#endif
        if (gossip::GossipFilter::Instance()->FilterMessage(message)) {
            TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnNoAndContinue", message);
            return kJudgeOwnNoAndContinue;
        }

#ifndef NDEBUG
        if (message.type() == kBroadcastPerformaceTest) {
            ++brt_filtered_rcv_count;
        }
        if (message.type() == kTestChainTrade) {
            TOP_NETWORK_DEBUG_FOR_REDIS(message, "stability_af");
        }

        static uint64_t af_recv_start_time = 0;
        static std::atomic<uint32_t> af_recv_count(0);
        if (message.type() == kTestChainTrade || message.type() == kTestWpingRequest) {
            if (af_recv_start_time == 0) {
                af_recv_start_time = GetCurrentTimeMsec();
            }
            ++af_recv_count;
            if (af_recv_count % 10000 == 0) {
                auto use_time_ms = double(GetCurrentTimeMsec() - af_recv_start_time) / 1000.0;
                uint32_t qps = (uint32_t)((double)af_recv_count / use_time_ms);
                std::cout << "$$$$$$$$$after filter recv " << af_recv_count << " use time:" << double(GetCurrentTimeMsec() - af_recv_start_time)
                    << " ms. QPS:" << qps << std::endl;

            }
        }
#endif

        if (message.is_root()) {
            TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYesAndContinue", message);
            return kJudgeOwnYesAndContinue;
        }
        if (message.src_node_id().empty() || message.des_node_id().empty()) {
            assert(false);
        }

        uint64_t src_service_type = ParserServiceType(message.src_node_id());
        uint64_t des_service_type = ParserServiceType(message.des_node_id());
        if (src_service_type == des_service_type) {
            TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYesAndContinue", message);
            return kJudgeOwnYesAndContinue;
        }

        RoutingTablePtr routing_table = FindRoutingTable(false, des_service_type, false);
        if (routing_table) {
            TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYesAndContinue", message);
            return kJudgeOwnYesAndContinue;
        }
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnNoAndContinue", message);
        return kJudgeOwnNoAndContinue;
    }

    if (message.has_is_root() && message.is_root()) {
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYes", message);
        return kJudgeOwnYes;
    }

    uint64_t service_type = ParserServiceType(message.des_node_id());
    RoutingTablePtr routing_table = FindRoutingTable(false, service_type, false);

    if (!routing_table) {
        TOP_WARN2("FindRoutingTable failed, judge own packet: type(%d) failed", message.type());
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnNoAndContinue", message);
        return kJudgeOwnNoAndContinue;
    }

    if (HandleSystemMessage(message, routing_table)) {
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYes", message);
        return kJudgeOwnYes;
    }

    int32_t client_ret = HandleClientMessage(message, routing_table);
    if (client_ret == kErrorReturn) {
        TOP_WARN2("HandleClientMessageBaseXid failed");
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnError", message);
        return kJudgeOwnError;
    }
    if (client_ret == kFirstRelayRetrun) {
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYes", message);
        return kJudgeOwnYes;
    }
    
    std::string match_kad_xid = routing_table->get_local_node_info()->id();
    if (message.des_node_id().compare(match_kad_xid) == 0) {
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYes", message);
        return kJudgeOwnYes;
    }

    bool closest = false;
    if (routing_table->ClosestToTarget(message.des_node_id(), closest)
            != kadmlia::kKadSuccess) {
        TOP_WARN2("ClosestToTarget goes wrong");
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnError", message);
        return kJudgeOwnError;
    }
    if (closest) {
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnYes", message);
        return kJudgeOwnYes;
    }

    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter kJudgeOwnNoAndContinue", message);
    return kJudgeOwnNoAndContinue;
}

bool WrouterXidHandler::MulticastPacketCheck(transport::protobuf::RoutingMessage& message) {
    if (!message.has_broadcast() || !message.broadcast()) {
        return false;
    }

    if (message.has_is_root() && message.is_root()) {
        return false;
    }
    // broadcast to same network or different network
    return true;
}

bool WrouterXidHandler::GossipPacketCheck(transport::protobuf::RoutingMessage& message) {
    if (!message.has_broadcast() || !message.broadcast()) {
        return false;
    }

    if (!message.has_is_root() || !message.is_root()) {
        return false;
    }
    // broadcast to root network(all nodes)
    return true;

}

} // namespace wrouter 

} // namespace top
