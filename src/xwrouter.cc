// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/xwrouter.h"

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
#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xpbase/base/uint64_bloomfilter.h"
#include "xpbase/base/redis_client.h"
#include "xkad/gossip/rumor_filter.h"
#include "xgossip/include/broadcast_layered.h"
#include "xgossip/include/gossip_bloomfilter.h"
#include "xgossip/include/gossip_bloomfilter_layer.h"
#include "xgossip/include/gossip_set_layer.h"
#include "xgossip/include/gossip_utils.h"
#include "xbase/xutl.h"
#include "xtransport/message_manager/message_manager_intf.h"
#include "xwrouter/message_handler/xwrouter_xid_handler.h"
#include "xwrouter/message_handler/xwrouter_xip_handler.h"
#include "xgossip/include/gossip_filter.h"

namespace top {

using namespace kadmlia;
using namespace gossip;

namespace wrouter {

Wrouter::Wrouter()
    : max_broadcast_num_(0),
    wxid_handler_(nullptr),
    wxip_handler_(nullptr) {}

Wrouter::~Wrouter() {
    max_broadcast_num_ = 0;
}

Wrouter* Wrouter::Instance() {
    static Wrouter ins;
    return &ins;
}

void Wrouter::Init(
        base::xcontext_t& context,
        const uint32_t thread_id,
        transport::TransportPtr transport_ptr,
        const uint32_t max_broadcast_num) {
    assert(transport_ptr);
    auto bloom_gossip_ptr = std::make_shared<GossipBloomfilter>(transport_ptr);
    auto layered_gossip_ptr = std::make_shared<BroadcastLayered>(transport_ptr);
    auto bloom_layer_gossip_ptr = std::make_shared<GossipBloomfilterLayer>(transport_ptr);
    auto set_layer_gossip_ptr = std::make_shared<GossipSetLayer>(transport_ptr);
    max_broadcast_num_ = max_broadcast_num;

    wxid_handler_ = std::make_shared<WrouterXidHandler>(
            transport_ptr,
            bloom_gossip_ptr,
            layered_gossip_ptr,
            bloom_layer_gossip_ptr,
            set_layer_gossip_ptr);
    wxip_handler_ = std::make_shared<WrouterXipHandler>(
            transport_ptr,
            bloom_gossip_ptr,
            layered_gossip_ptr,
            bloom_layer_gossip_ptr,
            set_layer_gossip_ptr);

    // GossipFilter for global 
    gossip::GossipFilter::Instance()->Init();
}

void Wrouter::register_on_receive_own_callback(on_receive_own_callback_t callback) {
    std::unique_lock<std::mutex> lock(callback_mutex_);
    assert(callback_ == nullptr);
    callback_ = callback;
}

void Wrouter::unregister_on_receive_own_callback() {
    std::unique_lock<std::mutex> lock(callback_mutex_);
    callback_ = nullptr;
}

int32_t Wrouter::send(base::xpacket_t& packet) {
    Xip2Header* xip2_header = ParserXip2Header(packet);
    if (!xip2_header) {
        TOP_WARN("xip2_header invalid,send failed");
        return enum_xerror_code_fail;
    }
    if (xip2_header->to_xaddr_low != 0x0
            && xip2_header->to_xaddr_low  != 0xFFFFFFFFFFFFFFFFULL
            && xip2_header->to_xaddr_high != 0x0
            && xip2_header->to_xaddr_high != 0xFFFFFFFFFFFFFFFFULL) {
        return wxip_handler_->SendPacket(packet);
    }

    std::string content((const char*)packet.get_body().data() + enum_xip2_header_len,
            packet.get_body().size() - enum_xip2_header_len);
    transport::protobuf::RoutingMessage message;
    if (!message.ParseFromString(content)) {
        TOP_WARN("Message ParseFromString failed");
        return enum_xerror_code_bad_data;
    }
    return wxid_handler_->SendPacket(message);
}

int32_t Wrouter::send(transport::protobuf::RoutingMessage& message) {
    return wxid_handler_->SendPacket(message);
}

int32_t Wrouter::SendToLocal(transport::protobuf::RoutingMessage& message) {
    return wxid_handler_->SendToLocal(message);
}

int32_t Wrouter::SendDirect(
        transport::protobuf::RoutingMessage& message,
        const std::string& ip,
        uint16_t port) {
    return wxid_handler_->SendDirect(message, ip, port);
}

int32_t Wrouter::recv(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
//     Xip2Header* xip2_header = ParserXip2Header(packet);
//     if (!xip2_header) {
//         TOP_WARN("ParserXip2Header error, recv failed");
//         return enum_xerror_code_fail;
//     }
//     
//     if (xip2_header->to_xaddr_low != 0x0
//             && xip2_header->to_xaddr_low  != 0xFFFFFFFFFFFFFFFFULL
//             && xip2_header->to_xaddr_high != 0x0
//             && xip2_header->to_xaddr_high != 0xFFFFFFFFFFFFFFFFULL) {
//         int32_t rcode = wxip_handler_->RecvPacket(packet);
//         if (rcode == kRecvOwn) {
//             return HandleOwnPacket(packet);
//         }
//         return rcode;
//     }

    if (message.hop_num() >= kHopToLive) {
        TOP_WARN("stop send msg because hop to live is max: %d [%s] des[%s] "
             "message_type[%d]",
             kHopToLive,
             HexSubstr(message.src_node_id()).c_str(),
             HexSubstr(message.des_node_id()).c_str(),
             message.type());
        return enum_xerror_code_fail;
    }

    int32_t rcode = wxid_handler_->RecvPacket(message, packet);
    if (message.type() == kTestChainTrade) {
        TOP_WARN("recv2 testchaintradehash:%u", message.gossip().msg_hash());
    }

    if (rcode == kRecvOwn) {
        return HandleOwnPacket(message, packet);
    }
    return rcode;
}

void Wrouter::SupportRandomPattern() {
    WrouterXidHandler* sub_wxid = dynamic_cast<WrouterXidHandler*>(wxid_handler_.get());
    if (sub_wxid != nullptr) {
        sub_wxid->SupportRandomPattern();
    }
}


bool Wrouter::BroadcastByMultiRandomKadKey(
        const transport::protobuf::RoutingMessage& message,
        kadmlia::ResponseFunctor call_back,
        int64_t recursive_count) {
    WrouterXidHandler* sub_wxid = dynamic_cast<WrouterXidHandler*>(wxid_handler_.get());
    if (sub_wxid != nullptr) {
        return sub_wxid->BroadcastByMultiRandomKadKey(message, call_back, recursive_count);
    }
    return false;
}

int32_t Wrouter::HandleOwnPacket(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (callback_) {
        callback_(message, packet);
    }

    WrouterMessageHandler::Instance()->HandleMessage(message, packet);
    return enum_xcode_successful;
}

int32_t Wrouter::HandleOwnSyncPacket(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (gossip::GossipFilter::Instance()->FilterMessage(message)) {
        TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter sync filtered", message);
        return enum_xcode_successful;
    }

    WrouterMessageHandler::Instance()->HandleSyncMessage(message, packet);
    return enum_xcode_successful;
}

int32_t Wrouter::HandleOwnPacket(base::xpacket_t& packet) {
    transport::protobuf::RoutingMessage message;
    std::string content(
            (const char*)packet.get_body().data() + enum_xip2_header_len,
            packet.get_body().size() - enum_xip2_header_len);
    if (!message.ParseFromString(content)) {
        TOP_ERROR("Message ParseFromString from string failed!");
        return enum_xerror_code_fail;
    }
    return HandleOwnPacket(message, packet);
}

// parse xip2_header from packet
Xip2Header* Wrouter::ParserXip2Header(base::xpacket_t& packet)
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


std::vector<std::string> Wrouter::GetAllLocalIds() {
    std::vector<std::string> all_id_vec;
    std::vector<uint64_t> vec_type;
    GetAllRegisterType(vec_type);
    kadmlia::RoutingTablePtr routing_table = GetRoutingTable(kRoot, true);

    if (vec_type.empty() && !routing_table) {
        return {};
    }

    all_id_vec.push_back(routing_table->get_local_node_info()->id());

    for (auto& t : vec_type) {
        routing_table = GetRoutingTable(t, false);
        if (routing_table) {
            all_id_vec.push_back(routing_table->get_local_node_info()->id());
        }

        routing_table = GetRoutingTable(t, true);
        if (routing_table) {
            all_id_vec.push_back(routing_table->get_local_node_info()->id());
        }
    }
    return all_id_vec;
}

std::vector<std::string> Wrouter::GetAllLocalXips() {
    std::vector<std::string> all_id_vec;
    std::vector<uint64_t> vec_type;
    GetAllRegisterType(vec_type);
    kadmlia::RoutingTablePtr routing_table = GetRoutingTable(kRoot, true);

    if (vec_type.empty() && !routing_table) {
        return {};
    }

    all_id_vec.push_back(routing_table->get_local_node_info()->xip());

    for (auto& t : vec_type) {
        routing_table = GetRoutingTable(t, false);
        if (routing_table) {
            all_id_vec.push_back(routing_table->get_local_node_info()->xip());
        }

        routing_table = GetRoutingTable(t, true);
        if (routing_table) {
            all_id_vec.push_back(routing_table->get_local_node_info()->xip());
        }
    }
    return all_id_vec;
}

} // namespace wrouter 

} // namespace top
