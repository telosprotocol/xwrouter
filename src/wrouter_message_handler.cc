// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/message_handler/wrouter_message_handler.h"

#include <vector>
#include <string>
#include <utility>
#include <map>

#include "xpbase/base/line_parser.h"
#include "xpbase/base/top_utils.h"
#include "xpbase/base/top_log.h"
#include "xkad/routing_table/routing_utils.h"
#include "xkad/routing_table/callback_manager.h"
#include "xkad/routing_table/node_info.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/node_detection_manager.h"
#include "xkad/routing_table/client_node_manager.h"
#include "xkad/routing_table/local_node_info.h"
#include "xwrouter/register_routing_table.h"
#include "xpbase/base/multirelay_log.h"

namespace top {

using namespace kadmlia;  // NOLINT

namespace wrouter {

WrouterMessageHandler::WrouterMessageHandler() {
    AddBaseHandlers();
}

WrouterMessageHandler::~WrouterMessageHandler() {
    for (uint32_t index = 0; index < array_handlers_.size(); ++index) {
        message_manager_->UnRegisterMessageProcessor(index);
        array_handlers_[index] = nullptr;
    }
}

WrouterMessageHandler* WrouterMessageHandler::Instance() {
    static WrouterMessageHandler ins;
    return &ins;
}

void WrouterMessageHandler::HandleMessage(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (message.hop_num() >= kHopToLive) {
        std::string nodes;
        for (int i = 0; i < message.hop_nodes_size(); ++i) {
            nodes += HexSubstr(message.hop_nodes(i).node_id()) + " -> ";
        }
        TOP_WARN("stop send msg because hop to live is max: %d [%s] des[%s] "
             "message_type[%d] nodes[%s]",
             kHopToLive,
             HexSubstr(message.src_node_id()).c_str(),
             HexSubstr(message.des_node_id()).c_str(),
             message.type(), nodes.c_str());
        return;
    }

    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter handle message", message);
    CheckBitVPNClientMessage(message);
    CheckNatDetectMessage(message);

    std::string version;
    if (message.has_version_tag()) {
        transport::protobuf::VersionTag version_tag = message.version_tag();
        version = version_tag.version();
    }

    int ret = HandleClientMessage(message, packet);
    if (ret != kContinue) {
        return;
    }
    if (message.type() >= MsgHandlerMaxSize) {
        TOP_WARN("invalid message.type(%d), beyond %d", message.type(), MsgHandlerMaxSize);
        return;
    }
    transport::HandlerProc call = array_handlers_[message.type()];
    if (!call) {
        TOP_WARN("invalid message.type(%d), callback not registered", message.type());
        return;
    }
    TOP_NETWORK_DEBUG_FOR_PROTOMESSAGE("wrouter func called", message);
    call(message, packet);
}

void WrouterMessageHandler::HandleSyncMessage(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    TOP_DEBUG("HandleSyncMessage msgtype:%d", message.type());
    transport::HandlerProc call = array_handlers_[message.type()];
    if (!call) {
        TOP_WARN("invalid message.type(%d), callback not registered", message.type());
        return;
    }
    call(message, packet);
}

void WrouterMessageHandler::AddBaseHandlers() {
    AddHandler(kKadConnectRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleConnectRequest(message, packet);
    });
    AddHandler(kKadDropNodeRequest, [this](
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet) {
        HandleNodeQuit(message, packet);
    });
    AddHandler(kKadHandshake, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleHandshake(message, packet);
    });
    AddHandler(kKadBootstrapJoinRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleBootstrapJoinRequest(message, packet);
    });
    AddHandler(kKadBootstrapJoinResponse, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleBootstrapJoinResponse(message, packet);
    });
    AddHandler(kKadFindNodesRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleFindNodesRequest(message, packet);
    });
    AddHandler(kKadFindNodesResponse, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleFindNodesResponse(message, packet);
    });
    AddHandler(kKadHeartbeatRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleHeartbeatRequest(message, packet);
    });
    AddHandler(kKadHeartbeatResponse, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleHeartbeatResponse(message, packet);
    });
    AddHandler(kKadAck, [](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
    });
    AddHandler(kKadNatDetectRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        nat_manager_->PushMessage(message, packet);
    });
    AddHandler(kKadNatDetectResponse, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        nat_manager_->PushMessage(message, packet);
    });
    AddHandler(kKadNatDetectHandshake2Node, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        nat_manager_->PushMessage(message, packet);
    });
    AddHandler(kKadNatDetectHandshake2Boot, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        nat_manager_->PushMessage(message, packet);
    });
    AddHandler(kKadNatDetectFinish, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        nat_manager_->PushMessage(message, packet);
    });
    AddHandler(kKadBroadcastFromMultiChannelRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleBroadcastFromMultiChannelRequest(message, packet);
    });
    AddHandler(kKadBroadcastFromMultiChannelAck, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleBroadcastFromMultiChannelAck(message, packet);
    });
    AddHandler(kKadSendToFromRandomNeighborsRequest, [this](transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet){
        HandleSendToFromRandomNeighborsRequest(message, packet);
    });    
}

void WrouterMessageHandler::HandleNodeQuit(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetRoutingTable(
            message.des_service_type(),
            message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("service type[%llu] [%d] has not register routing table.",
            message.des_service_type(), message.is_root());
        return;
    }
    routing_table->HandleNodeQuit(message, packet);
}


void WrouterMessageHandler::AddHandler(int msg_type, transport::HandlerProc handler_proc) {
    assert(handler_proc);
    assert(msg_type < MsgHandlerMaxSize);
    assert(!array_handlers_[msg_type]);

    message_manager_->RegisterMessageProcessor(msg_type, [this](
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet) {
        HandleMessage(message, packet);
    });

    array_handlers_[msg_type] = handler_proc;

}

void WrouterMessageHandler::AddRequestType(int msg_type, int request_type) {
    if (request_type != kRequestMsg && request_type != kResponseMsg) {
        request_type = kNone;
    }
    std::unique_lock<std::mutex> lock(map_request_type_mutex_);
    map_request_type_[msg_type] = request_type;  // just cover
}

int WrouterMessageHandler::GetRequestType(int msg_type) {
    std::unique_lock<std::mutex> lock(map_request_type_mutex_);
    auto it = map_request_type_.find(msg_type);
    if (it != map_request_type_.end()) {
        return it->second;
    }
    return kNone;
}

void WrouterMessageHandler::RemoveHandler(int msg_type) {
    message_manager_->UnRegisterMessageProcessor(msg_type);
    assert(msg_type < MsgHandlerMaxSize);
    array_handlers_[msg_type] = nullptr;
}

void WrouterMessageHandler::RemoveRequestType(int msg_type) {
    std::unique_lock<std::mutex> lock(map_request_type_mutex_);
    auto it = map_request_type_.find(msg_type);
    if (it != map_request_type_.end()) {
        map_request_type_.erase(it);
        return;
    }
}

// check bitvpn 0.5.0(just for now) message 
void WrouterMessageHandler::CheckBitVPNClientMessage(
        transport::protobuf::RoutingMessage& message) {
    std::string version;
    if (!message.has_version_tag()) {
        return;
    }

    transport::protobuf::VersionTag version_tag = message.version_tag();
    version = version_tag.version();
    if (version.compare("0.5.0") != 0)  {
        return;
    }

    if (!message.has_src_service_type() || !message.has_des_service_type()){
        // usually this is the first node which recv client msg,meaning node is the relay node
        message.set_src_service_type(top::kEdgeXVPN);
        message.set_des_service_type(top::kEdgeXVPN);
        message.set_client_id(message.src_node_id());
        message.set_relay_flag(false);
        TOP_DEBUG("client version 0.5.0 msg come, set service_type %d, "
                "set client_id and relay_flag",
                top::kEdgeXVPN);
    }
}

void WrouterMessageHandler::CheckNatDetectMessage(transport::protobuf::RoutingMessage& message) {
    switch (message.type()) {
    case kKadNatDetectRequest:
    case kKadNatDetectResponse:
    case kKadNatDetectHandshake2Node:
    case kKadNatDetectHandshake2Boot:
    case kKadNatDetectFinish:
        message.set_src_service_type(top::kRoot);
        message.set_des_service_type(top::kRoot);
        TOP_DEBUG("bluenat nat detect set to kRoot", top::kRoot);
        break;
    }
}

int WrouterMessageHandler::HandleClientMessage(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (!message.has_client_id()) {
        return kContinue;
    }

    auto routing_table = GetRoutingTable(
            message.des_service_type(),
            message.has_is_root() && message.is_root());
    if (!routing_table) {
        return kContinue;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        TOP_ERROR("get routing table by next service type[%llu] failed!",
            message.des_service_type());
        return kKadFailed;
    }

    if (!message.relay_flag()) {
        if (message.client_id() == local_node->id()) {
            return kContinue;
        }

        ClientNodeInfoPtr client_node_ptr;
        client_node_ptr.reset(new ClientNodeInfo(message.client_id()));
        client_node_ptr->public_ip = packet.get_from_ip_addr();
        client_node_ptr->public_port = packet.get_from_ip_port();
        ClientNodeManager::Instance()->AddClientNode(client_node_ptr);  // just cover
        if (message.has_xid() && !message.xid().empty()) {
            ClientNodeInfoPtr client_node_ptr;
            client_node_ptr.reset(new ClientNodeInfo(message.xid()));
            client_node_ptr->public_ip = packet.get_from_ip_addr();
            client_node_ptr->public_port = packet.get_from_ip_port();
            ClientNodeManager::Instance()->AddClientNode(client_node_ptr);  // just cover
        }
        message.set_relay_flag(true);
        message.set_src_node_id(local_node->id());
        return kContinue;
    }

    if (message.des_node_id() != local_node->id()) {
        return kContinue;
    }

    // request message arrive des node or  response message arrive the first relay node
    ClientNodeInfoPtr client_node_ptr = ClientNodeManager::Instance()->FindClientNode(
            message.client_id());
    if (!client_node_ptr) {
        return kContinue;
    }
    std::string client_pub_ip = client_node_ptr->public_ip;
    uint16_t client_pub_port = client_node_ptr->public_port;
    message.set_relay_flag(false);
    message.set_des_node_id(client_node_ptr->node_id);
    return SendData(message, client_pub_ip, client_pub_port);
}

void WrouterMessageHandler::HandleHeartbeatRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_node_id(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("heartbeat msg.des[%s], msg.is_root[%d] has not register routing table.",
            HexEncode(message.des_node_id()).c_str(), message.is_root());
        return;
    }
    routing_table->HandleHeartbeatRequest(message, packet);
}

void WrouterMessageHandler::HandleHeartbeatResponse(
    transport::protobuf::RoutingMessage& message,
    base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_node_id(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("heartbeat msg.des[%s], msg.is_root[%d] has not register routing table.",
            HexEncode(message.des_node_id()).c_str(), message.is_root());
        return;
    }
    routing_table->HandleHeartbeatResponse(message, packet);
}

void WrouterMessageHandler::SendAck(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    transport::protobuf::RoutingMessage res_message;
    RoutingTablePtr routing_table = GetRoutingTable(
            message.des_service_type(),
            message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("service type[%llu] has not register routing table.", message.des_service_type());
        return;
    }
    routing_table->SetFreqMessage(res_message);
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return;
    }

    res_message.set_src_service_type(message.des_service_type());
    res_message.set_des_service_type(message.src_service_type());
    res_message.set_des_node_id(message.src_node_id());
    res_message.set_type(kKadAck);
    res_message.set_id(0);
    res_message.set_ack_id(message.ack_id());
    SendData(res_message, packet.get_from_ip_addr(), packet.get_from_ip_port());
}

void WrouterMessageHandler::HandleFindNodesRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    // TODO(smaug) handle kRoot parse
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_node_id(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_WARN2("HandleFindNodesRequest msg.is_root(%d) msg.src_node_id(%s) msg.des_node_id(%s)",
                message.is_root(),
                HexEncode(message.src_node_id()).c_str(),
                HexEncode(message.des_node_id()).c_str());
        return;
    }
    routing_table->HandleFindNodesRequest(message, packet);
}

void WrouterMessageHandler::HandleFindNodesResponse(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_node_id(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_WARN2("HandleFindNodesResponse msg.is_root(%d) msg.src_node_id(%s) msg.des_node_id(%s)",
                message.is_root(),
                HexEncode(message.src_node_id()).c_str(),
                HexEncode(message.des_node_id()).c_str());

        return;
    }
    routing_table->HandleFindNodesResponse(message, packet);
}

int WrouterMessageHandler::SendData(
        const transport::protobuf::RoutingMessage& message,
        const std::string& peer_ip,
        uint16_t peer_port) {
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_service_type(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("routing table not registered[%llu]", message.des_service_type());
        return kKadFailed;
    }

    auto transport_ptr = routing_table->get_transport();
    if (!transport_ptr) {
        TOP_ERROR("service type[%llu] has not register udp transport.", message.des_service_type());
        return kKadFailed;
    }

    std::string msg;
    if (!message.SerializeToString(&msg)) {
        TOP_INFO("RoutingMessage SerializeToString failed!");
        return kKadFailed;
    }
    xbyte_buffer_t xdata{msg.begin(), msg.end()};

    return transport_ptr->SendData(xdata, peer_ip, peer_port);
}

void WrouterMessageHandler::HandleBootstrapJoinRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_service_type(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("service type[%llu][%d] has not register routing table.",
                message.des_service_type(), message.is_root());
        return;
    }
    routing_table->HandleBootstrapJoinRequest(message, packet);
}

void WrouterMessageHandler::HandleBootstrapJoinResponse(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    TOP_DEBUG("join response coming,[%d]", message.is_root());
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_service_type(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("service type[%llu] has not register routing table.", message.des_service_type());
        return;
    }
    routing_table->HandleBootstrapJoinResponse(message, packet);
}

void WrouterMessageHandler::HandleHandshake(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetRoutingTable(
        message.des_node_id(),
        message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_WARN2("HandleHandshake msg.is_root(%d) msg.src_node_id(%s) msg.des_node_id(%s)",
                message.is_root(),
                HexEncode(message.src_node_id()).c_str(),
                HexEncode(message.des_node_id()).c_str());
        return;
    }
    routing_table->HandleHandshake(message, packet);
}

void WrouterMessageHandler::HandleConnectRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    std::string relay_routing_id;
    // from relay_routing
    RoutingTablePtr routing_table = GetRoutingTable(
            message.des_node_id(),
            message.has_is_root() && message.is_root());
    if (!routing_table) {
        // mostly this is relay routing
        protobuf::ConnectReq conn_req;
        if (!conn_req.ParseFromString(message.data())) {
            TOP_WARN2("ConnectRequest ParseFromString from string failed!");
            return;
        }
        relay_routing_id = conn_req.relay_routing_id();
        routing_table = GetRoutingTable(
                relay_routing_id,
                message.has_is_root() && message.is_root());
    }

    if (!routing_table) {
        TOP_WARN2("HandleConnectRequest msg.is_root(%d) msg.src_node_id(%s) msg.des_node_id(%s) msg.relay_routing_id(%s)",
                message.is_root(),
                HexEncode(message.src_node_id()).c_str(),
                HexEncode(message.des_node_id()).c_str(),
                HexEncode(relay_routing_id).c_str());
        return;
    }
    routing_table->HandleConnectRequest(message, packet);
}


// just rewrite this function for other service
void WrouterMessageHandler::HandleTestMultiRelayRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetSmartRoutingTable(message.des_service_type());
    if (!routing_table) {
        TOP_ERROR("<smaug>MultiRelay:: service type[%llu] has not register routing table.",
                message.des_service_type());
        return;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        TOP_ERROR("<smaug>MultiRelay:: get local_node_info failed "
                "for des_service_type[%llu]",
                message.des_service_type());
        return ;
    }
    uint64_t chosen_service_type = local_node->service_type();
    // from the same network and des_service_type equal chosen_service_type
    if (chosen_service_type != message.src_service_type()
            || chosen_service_type != message.des_service_type()) {
        return;
    }

    // usually after multirelay handle func handled, this node is the dest node or the closest node
    if (message.des_node_id() != local_node->id()) {
        bool closest = false;
        if (routing_table->ClosestToTarget(
                    message.des_node_id(), closest) != kKadSuccess) {
            TOP_ERROR("ClosestToTarget goes wrong");
            return;
        }

        if (!closest) {
            TOP_DEBUG("request arrive this node[%s] and SendToClosestNode",
                    HexSubstr(local_node->id()).c_str());
            return routing_table->SendToClosestNode(message);
        }
    }

    TOP_DEBUG("<smaug>MultiRelay:: message from %s arrive the dest node[%s],"
            "will send response",
            HexEncode(message.src_node_id()).c_str(),
            HexEncode(message.des_node_id()).c_str());

    protobuf::TestMultiRelayRequest test_multi_relay_request;
    if (!test_multi_relay_request.ParseFromString(message.data())) {
        TOP_ERROR("<smaug>MultiRelay:: TestMultiRelayRequest ParseFromString failed");
        return;
    }
    std::string ping = test_multi_relay_request.ping();
    TOP_INFO("<smaug>MultiRelay:: Get TestMultiRelayRequest ping[%s], will send response", ping.c_str());

    // send response
    protobuf::TestMultiRelayResponse test_multi_relay_response;
    std::string pong = "pong from " + HexEncode(local_node->id());
    test_multi_relay_response.set_pong(pong);
    std::string data;
    if (!test_multi_relay_response.SerializeToString(&data)) {
        TOP_ERROR("<smaug>MultiRelay:: TestMultiRelayResponse SerializeToString failed");
        return;
    }

    transport::protobuf::RoutingMessage res_message;
    res_message.set_src_service_type(message.des_service_type());
    res_message.set_des_service_type(message.src_service_type());
    res_message.set_hop_num(0);
    res_message.set_src_node_id(local_node->id());
    res_message.set_des_node_id(message.src_node_id());
    res_message.set_type(kTestMultiRelayResponse);
    res_message.set_id(message.id());

    // attention: important
    routing_table->SetMultiRelayMsg(message, res_message);
    res_message.set_data(data);

    return routing_table->SmartSendReply(res_message);
}


void WrouterMessageHandler::HandleTestMultiRelayResponse(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    RoutingTablePtr routing_table = GetSmartRoutingTable(message.des_service_type());
    if (!routing_table) {
        TOP_ERROR("<smaug>MultiRelay:: service type[%llu] has not register routing table.",
                message.des_service_type());
        return;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        TOP_ERROR("<smaug>MultiRelay:: get local_node_info failed "
                "for des_service_type[%llu]",
                message.des_service_type());
        return;
    }
    uint64_t chosen_service_type = local_node->service_type();
    if (chosen_service_type != message.src_service_type()
            || chosen_service_type != message.des_service_type()) {
        TOP_ERROR("<smaug>MultiRelay:: TestMultiRelayResponse service_type not right, "
                "local_service_type[%llu];message_src_service_type[%llu];"
                "message_des_service_type[%llu]",
                chosen_service_type,
                message.src_service_type(),
                message.des_service_type());
        return;
    }
    // multirelay msg finished
    if (message.relay_hop_info_size() == 0 && message.des_node_id() == local_node->id()) {
        TOP_INFO("<smaug>MultiRelay:: kTestMultiRelayResponse arrive the original asker[%s],"
                "multirelay request finished",
                HexEncode(local_node->id()).c_str());
        return CallbackManager::Instance()->Callback(message.id(), message, packet);
    }

    return routing_table->SmartSendReply(message);
} // end test multi relay

void WrouterMessageHandler::HandleBroadcastFromMultiChannelRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    transport::protobuf::RoutingMessage business_message;
    business_message.ParseFromString(message.data());
    HandleMessage(business_message,packet);
}

void WrouterMessageHandler::HandleBroadcastFromMultiChannelAck(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    uint32_t src_message_id = base::xstring_utl::toint64(message.data());
    static std::mutex ack_mutex;
    {
        std::lock_guard<std::mutex> lock(ack_mutex);
        CallbackManager::Instance()->Callback(src_message_id,message,packet);
    }
}

void WrouterMessageHandler::HandleSendToFromRandomNeighborsRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {    
    transport::protobuf::RoutingMessage business_message;
    business_message.ParseFromString(message.data());
    HandleMessage(business_message,packet);
}

// begin handle multi relay message
int WrouterMessageHandler::HandleMultiRelayMessage(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (!CheckMultiRelay(message)) {
        return kContinue;
    }

    int request_type = GetRequestType(message.type());
    if (request_type == kNone) {
        return kContinue;
    }

    int spearhead_ret = HandleMultiRelayMessageSpearHead(message, packet);
    if (spearhead_ret == kSuccessReturn) {
        return kSuccessReturn;
    }
    if (spearhead_ret != kContinue) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "HandleMultiRelayMessageSpearHead failed");
        return kErrorReturn;
    }
    if (request_type == kRequestMsg) {
        return HandleMultiRelayRequest(message, packet);
    } else {
        return HandleMultiRelayResponse(message, packet);
    }
}

void WrouterMessageHandler::PrintRelayHopInfo(transport::protobuf::RoutingMessage& message) {
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "type(%d),src_node_id(%s),des_node_id(%s),src_service_type(%llu),des_service_type(%llu)",
            message.type(),
            HexEncode(message.src_node_id()).c_str(),
            HexEncode(message.des_node_id()).c_str(),
            message.src_service_type(),
            message.des_service_type());

    for (int i = 0; i < message.relay_hop_info_size(); ++i) {
        const transport::protobuf::RelayHopInfo& relay_hop_info = message.relay_hop_info(i);
        SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                "routeinfo(%d) relay_hop_info is:"
                "{relay_entry_id:(%s), relay_exit_id:(%s), service_type:(%llu)}",
                i,
                HexEncode(relay_hop_info.relay_entry_id()).c_str(),
                HexEncode(relay_hop_info.relay_exit_id()).c_str(),
                relay_hop_info.service_type());
    }
}

bool WrouterMessageHandler::CheckMultiRelay(transport::protobuf::RoutingMessage& message) {
    if (!message.has_multi_relay() || !message.multi_relay()) {
        return false;
    }

    if (message.has_is_root() && message.is_root()) {
        return false;
    }

    // direct message, no need relay TODO(smaug) add other kind of message type
    if (message.type() == kKadBootstrapJoinRequest
            || message.type() == kKadBootstrapJoinResponse
            || message.type() == kKadHandshake
            || message.type() == kKadFindNodesRequest
            || message.type() == kKadFindNodesResponse
            || message.type() == kKadHeartbeatRequest
            || message.type() == kKadHeartbeatResponse
            || message.type() == kRootMessage
            || message.type() == kKadNatDetectRequest
            || message.type() == kKadNatDetectResponse
            || message.type() == kKadNatDetectHandshake2Node
            || message.type() == kKadNatDetectHandshake2Boot
            || message.type() == kKadNatDetectFinish) {
        return false;
    }
    return true;
}


int WrouterMessageHandler::HandleMultiRelayMessageSpearHead(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (CheckRelayMsgToNextEdgeNetwork(message) != kContinue) {
        return kSuccessReturn;
    }

    RoutingTablePtr routing_table = MultiRelayGetSmartRoutingTable(message);
    if (!routing_table) {
        TOP_ERROR("get smart routing table failed!");
        return kErrorReturn;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return kErrorReturn;
    }
    uint64_t chosen_service_type = local_node->service_type();

    std::string last_relay_hop_entry_id, last_relay_hop_exit_id;
    int relay_hop_info_size = message.relay_hop_info_size();
   if (relay_hop_info_size > 0) {
       const transport::protobuf::RelayHopInfo& last_relay_hop_info = 
           message.relay_hop_info(relay_hop_info_size - 1);
       last_relay_hop_entry_id  = last_relay_hop_info.relay_entry_id();
       last_relay_hop_exit_id   = last_relay_hop_info.relay_exit_id();
   }

    if (chosen_service_type == message.src_service_type()) {
        SMINFO(message.xrequest_id().c_str(), message.seq(),
                "message type(%d) from the same p2p network",
                message.type());
        return kContinue;
    }

    // message from different p2p network, if message is request type,
    // then this node become relay node ,otherwise this node is some exit node 
   if (GetRequestType(message.type()) == kResponseMsg
           && last_relay_hop_exit_id == local_node->id()) {
       // message is response type, and arrive some exit node or the original asker
       message.set_src_service_type(chosen_service_type);
       // TODO(smaug)
       // message.set_src_node_id(local_node->id());
       // remove the last relay_hop_info 
       ::google::protobuf::RepeatedPtrField<transport::protobuf::RelayHopInfo >* list_ptr =
           message.mutable_relay_hop_info();
       list_ptr->RemoveLast();
       SMINFO(message.xrequest_id().c_str(), message.seq(),
               "response message type(%d) arrive some exit node(%s) of network(%llu),will send to node(%s)",
               message.type(),
               HexEncode(local_node->id()).c_str(),
               chosen_service_type,
               HexEncode(last_relay_hop_entry_id).c_str());
       return kContinue;
   } // end if (GetRequestType...

    // message is request type
    // the entry of this p2p network, keep the exit node of last p2p network
    ClientNodeInfoPtr client_node_ptr;
    if (relay_hop_info_size == 0) {
        transport::protobuf::RelayHopInfo* relay_hop_info = message.add_relay_hop_info();
        relay_hop_info->set_relay_entry_id(message.src_node_id());
        relay_hop_info->set_relay_exit_id(message.src_node_id());
        relay_hop_info->set_relay_flag(true);
        relay_hop_info->set_service_type(message.src_service_type());
        relay_hop_info_size = message.relay_hop_info_size();
        SMDEBUG(message.xrequest_id().c_str(), message.seq(), "addrelayhopinfo[b] (%s->%s)",
                HexEncode(message.src_node_id()).c_str(),
                HexEncode(message.src_node_id()).c_str());

        last_relay_hop_entry_id  = message.src_node_id();
        last_relay_hop_exit_id   = message.src_node_id();
    }

    client_node_ptr.reset(new ClientNodeInfo(last_relay_hop_exit_id));
    client_node_ptr->public_ip = packet.get_from_ip_addr();
    client_node_ptr->public_port = packet.get_from_ip_port();
    client_node_ptr->src_service_type = message.src_service_type();     // important
    ClientNodeManager::Instance()->AddClientNode(client_node_ptr);  // just cover
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "add client node[%s:%s:%d]",
            HexEncode(client_node_ptr->node_id).c_str(),
            (client_node_ptr->public_ip).c_str(),
            client_node_ptr->public_port);

    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "network[%llu] message arrive this network[%llu], "
            "message went through %d network befor this network, "
            "and this node[%s] will become %d relay_hop_node.",
            message.src_service_type(),
            chosen_service_type,
            relay_hop_info_size,
            HexEncode(local_node->id()).c_str(),
            relay_hop_info_size);



    // push entry info of this p2p network
    transport::protobuf::RelayHopInfo* relay_hop_info = message.add_relay_hop_info();
    relay_hop_info->set_relay_entry_id(local_node->id());
    relay_hop_info->set_service_type(chosen_service_type);

    std::string next_relay_exit_id;
    if (chosen_service_type == message.des_service_type()) {
        next_relay_exit_id = message.des_node_id();
        SMINFO(message.xrequest_id().c_str(), message.seq(),
                "message from %llu network, and arrive the des %llu network",
                message.src_service_type(),
                message.des_service_type());
    } else {
        // TODO(smaug) for now, just use US country 
        // relay_target_id can be equal to this node id TODO(smaug) use some field control
        next_relay_exit_id  = GenRandomID(
                top::kCountry_US,
                static_cast<uint8_t>(chosen_service_type));
        if (next_relay_exit_id.empty()) {
            SMERROR(message.xrequest_id().c_str(), message.seq(),
                    "GenRandomID for relay_exit_id failed"
                    "in %llu p2p network",
                    chosen_service_type);
            return kErrorReturn;
        }
        SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                "in network(%llu) generate random target_id(%s)",
                chosen_service_type,
                HexEncode(next_relay_exit_id).c_str());
    }

    relay_hop_info->set_relay_exit_id(next_relay_exit_id);
    relay_hop_info->set_relay_flag(false);

    message.set_src_service_type(chosen_service_type);
    // TODO(smaug) maybe should not change the original src_node_id
    message.set_src_node_id(local_node->id());
    SMDEBUG(message.xrequest_id().c_str(), message.seq(), "addrelayhopinfo[c] (%s->%s)",
            HexEncode(local_node->id()).c_str(),
            HexEncode(next_relay_exit_id).c_str());
    return kContinue;
}

std::shared_ptr<kadmlia::RoutingTable> WrouterMessageHandler::MultiRelayGetSmartRoutingTable(
        transport::protobuf::RoutingMessage& message) {
    RoutingTablePtr routing_table = GetSmartRoutingTable(message.des_service_type());
    if (!routing_table) {
        TOP_ERROR("get routing table by des service type[%llu] failed!",
                message.des_service_type());
        return nullptr;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return nullptr;
    }

    int relay_hop_info_size = message.relay_hop_info_size();
    if (relay_hop_info_size == 0) {
        return routing_table;
    }

    uint64_t chosen_service_type = local_node->service_type();
    bool last_relay_flag = false;
    uint64_t last_service_type = top::kInvalidType;

    // make sure the first node choose the right one routing table
    // the reason is the first node may have edge and server role at the same time
    const transport::protobuf::RelayHopInfo& last_relay_hop_info = 
        message.relay_hop_info(relay_hop_info_size - 1);
    last_relay_flag = last_relay_hop_info.relay_flag();
    last_service_type = last_relay_hop_info.service_type();
 
    if (!last_relay_flag && chosen_service_type != last_service_type) {
        // this node choosen wrong routing table, should re-choose
        routing_table = GetSmartRoutingTable(last_service_type);
        if (routing_table) {
            return routing_table;
        } else {
            return nullptr;
        }
    }
    return routing_table;
}



int WrouterMessageHandler::CheckRelayMsgToNextEdgeNetwork(transport::protobuf::RoutingMessage& message) {
    if (message.relay_hop_info_size() > 0) {
        return kContinue;
    }
    RoutingTablePtr routing_table = MultiRelayGetSmartRoutingTable(message);
    if (routing_table) {
        return kContinue;
    }

   SMDEBUG(message.xrequest_id().c_str(), message.seq(),
           "this is the first network, message should relay to next edge network");
   RelayMsgToNextEdgeNetwork(message);
   return kSuccessReturn;
}

// as client, send request relay msg to edge
// usually when send to the first relay network(meaning the second network)
void WrouterMessageHandler::RelayMsgToNextEdgeNetwork(transport::protobuf::RoutingMessage& message) {
    if (!message.has_multi_relay() || !message.multi_relay()) {
        return ;
    }
    RoutingTablePtr routing_table = MultiRelayGetSmartRoutingTable(message);
    if (routing_table) {
        // only use when can not get any smart routing table
        return;
    }
    std::vector<uint64_t> vec_type;
    GetAllRegisterType(vec_type);
    if (vec_type.empty()) {
        SMERROR(message.xrequest_id().c_str(), message.seq(), "none routing table registered");
        return;
    }
    // choose the first routing table
    routing_table = GetRoutingTable(vec_type[0]);
    if (!routing_table) {
        SMERROR(message.xrequest_id().c_str(), message.seq(), "routing table of %llu none", vec_type[0]);
        return;
    }
    int relay_hop_info_size = message.relay_hop_info_size();
    if (relay_hop_info_size != 0) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "RelayMsgToNextEdgeNetwork relay_hop_info_size"
                "should be zero,but is %d",
                relay_hop_info_size);
        return;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return;
    }
    int request_type = GetRequestType(message.type());
    // TODO(smaug) for now, just allow request msg
    if (request_type != kRequestMsg) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "error use,RelayMsgToNextEdgeNetwork should be"
                "request type message,send failed");
        return ;
    }
//     RoutingTablePtr root_routing_table_ptr = GetRoutingTable(top::kRoot, true);
//     if (!root_routing_table_ptr) {
//         SMERROR(message.xrequest_id().c_str(), message.seq(),
//                 "kRoot RoutingTable None");
//         return ;
//     }
//     uint64_t next_edge_service_type = TryGetSmartRoutingTable(message.des_service_type());
//     if (!wrouter::SetCacheServiceType(next_edge_service_type)) {
//         SMERROR(message.xrequest_id().c_str(), message.seq(),
//                 "SetCacheServiceType of %llu failed",
//                 next_edge_service_type);
//         return ;
//     }
    std::set<std::pair<std::string, uint16_t>> boot_endpoints;
    if (!wrouter::GetServiceBootstrapRootNetwork(message.des_service_type(), boot_endpoints)) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "GetServiceBootstrapRootNetwork failed");
        return;
    }
    transport::protobuf::RelayHopInfo* relay_hop_info = message.add_relay_hop_info();
    relay_hop_info->set_relay_entry_id(message.src_node_id());
    relay_hop_info->set_relay_exit_id(local_node->id());
    relay_hop_info->set_relay_flag(true);
    relay_hop_info->set_service_type(message.src_service_type());

    SMDEBUG(message.xrequest_id().c_str(), message.seq(), "addrelayhopinfo[a] (%s->%s)",
            HexEncode(message.src_node_id()).c_str(),
            HexEncode(local_node->id()).c_str());

    auto it = boot_endpoints.begin();
    routing_table->SendData(message, it->first, it->second);
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "RelayMsgToNextEdgeNetwork[%llu] src_node_id[%s] this_node_id[%s]",
            message.des_service_type(),
            HexEncode(message.src_node_id()).c_str(),
            HexEncode(local_node->id()).c_str());
    return;
}

// the exit node of one p2p network how to send message to next different p2p network
void WrouterMessageHandler::RelayMsgToNextServiceNetwork(
        transport::protobuf::RoutingMessage& message,
        std::shared_ptr<kadmlia::RoutingTable> routing_table) {
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return ;
    }
    uint64_t chosen_service_type = local_node->service_type();
    // from the same network and des_service_type equal chosen_service_type
    if (chosen_service_type != message.src_service_type()) {
        return;
    }
    if (message.des_node_id() == local_node->id()) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "local_node_id[%s] should not equal message_des_node_id[%s]"
                "in RelayMsgToNextServiceNetwork",
                HexEncode(local_node->id()).c_str(),
                HexEncode(message.des_node_id()).c_str());
        return;
    }
    if (chosen_service_type == message.des_service_type()) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "local_service_type[%llu] should not equal"
                "message_des_service_type[%llu] in RelayMsgToNextServiceNetwork",
                chosen_service_type,
                message.des_service_type());
        return;
    }
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "now in %llu p2p network, message from %s arrive the dest node[%s],"
            "will relay to next network[%d]",
            chosen_service_type,
            HexEncode(message.src_node_id()).c_str(),
            HexEncode(message.des_node_id()).c_str(),
            message.des_service_type());
    // TODO(smaug) if middle p2p network more than one, that will not support
    if (!wrouter::SetCacheServiceType(message.des_service_type())) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "SetCacheServiceType[%llu] failed",
                message.des_service_type());
        return;
    }
    std::set<std::pair<std::string, uint16_t>> boot_endpoints;
    if (!wrouter::GetServiceBootstrapRootNetwork(message.des_service_type(), boot_endpoints)) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "GetServiceBootstrapRootNetwork of %llu failed",
                message.des_service_type());
        return;
    }
    uint32_t rand_idx = base::GetRandomInt64() % boot_endpoints.size();
    auto it = boot_endpoints.begin();
    std::advance(it, rand_idx);
    std::pair<std::string, uint16_t> rand_next_bootstrap_endpoint = *it;
    SMINFO(message.xrequest_id().c_str(), message.seq(),
            "RelayMsgToNextServiceNetwork get %d endpoints of %llu p2p network,"
            "using [%s:%d] SendData",
            boot_endpoints.size(),
            message.des_service_type(),
            rand_next_bootstrap_endpoint.first.c_str(),
            rand_next_bootstrap_endpoint.second);
    routing_table->SendData(
            message,
            rand_next_bootstrap_endpoint.first,
            rand_next_bootstrap_endpoint.second);

    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "RelayMsgToNextServiceNetwork[%llu] directsend[%s:%d]",
            message.des_service_type(),
            rand_next_bootstrap_endpoint.first.c_str(),
            rand_next_bootstrap_endpoint.second);
    return;
}

int WrouterMessageHandler::HandleMultiRelayRequest(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    if (!message.has_multi_relay() || !message.multi_relay()) {
        return kErrorReturn;
    }
    int request_type = GetRequestType(message.type());
    if (request_type != kRequestMsg) {
        return kErrorReturn;
    }
    RoutingTablePtr routing_table = MultiRelayGetSmartRoutingTable(message);
    if (!routing_table) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "service type[%llu] has not register routing table.", message.des_service_type());
        return kErrorReturn;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return kErrorReturn;
    }

    uint64_t chosen_service_type = local_node->service_type();
    if (chosen_service_type != message.src_service_type()) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "something goes wrong");
        return kErrorReturn;
    }

    if (message.des_node_id() == local_node->id()) {
        // this is the dest
        SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                "message(%d) arrive the dest node[%s], will send response",
                message.type(),
                HexEncode(local_node->id()).c_str());
        // return SendTestMultiRelayResponse(message, packet);
        SendMultiRelayResponse(message);
        return kContinue;
    }

    // message from same p2p network, and go to the same p2p network
    if (chosen_service_type == message.des_service_type()) {
        // this is dest p2p network
        bool closest = false;
        if (routing_table->ClosestToTarget(message.des_node_id(), closest) != kKadSuccess) {
            SMERROR(message.xrequest_id().c_str(), message.seq(),
                    "ClosestToTarget goes wrong");
            return kErrorReturn;
        }
        if (!closest) {
            SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                    "SendToClosestNode");
            routing_table->SendToClosestNode(message);
            return kSuccessReturn;
        }

        SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                "message(%d) arrive the dest node[%s], will send response",
                message.type(),
                HexEncode(local_node->id()).c_str());

       // this node is the closest node, drop message or send response 
       // according to diffenent message type
       // for test, send response
       //return SendTestMultiRelayResponse(message, packet);
       SendMultiRelayResponse(message);
       return kContinue;
    } else {
        // this is not dest p2p network, continue send msg
        int relay_hop_info_size = message.relay_hop_info_size();
        if (relay_hop_info_size == 0) {
            // usually this is edge network, and message from same edge network, will go to service network
            transport::protobuf::RelayHopInfo* relay_hop_info = message.add_relay_hop_info();
            relay_hop_info->set_relay_entry_id(message.src_node_id());
            /*
            std::string this_relay_exit_id = GenRandomID(
                    top::kCountry_US,
                    static_cast<uint8_t>(chosen_service_type));
            if (this_relay_exit_id.empty()) {
                TOP_ERROR("<smaug>MultiRelay:: GenRandomID for this_relay_exit_id failed");
                return kErrorReturn;
            }
            TOP_DEBUG("<smaug>MultiRelay:: randomid2[%s]", HexEncode(this_relay_exit_id).c_str());
            relay_hop_info->set_relay_exit_id(this_relay_exit_id);
            */
            relay_hop_info->set_relay_exit_id(local_node->id());
            relay_hop_info->set_service_type(chosen_service_type);
            relay_hop_info->set_relay_flag(true);
            
            SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                    "relay_hop_info_size 0, will RelayMsgToNextServiceNetwork");
            RelayMsgToNextServiceNetwork(message, routing_table);
            return kSuccessReturn;
        }

        relay_hop_info_size = message.relay_hop_info_size();
        transport::protobuf::RelayHopInfo* relay_hop_info = message.mutable_relay_hop_info(
                relay_hop_info_size - 1);
        std::string next_relay_exit_id = relay_hop_info->relay_exit_id();
        if (local_node->id() == next_relay_exit_id) {
            // usually can not happend, because next_relay_exit_id is generagted randomly
            SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                    "message in %llu p2p network arrive"
                    "the destnode [%s] of this p2p network,"
                    "will begin get cache_service_public_nodes",
                    chosen_service_type,
                    HexEncode(next_relay_exit_id).c_str());

            relay_hop_info->set_relay_flag(true);
            RelayMsgToNextServiceNetwork(message, routing_table);
            return kSuccessReturn;
        } else {
            bool closest = false;
            if (routing_table->ClosestToTarget(next_relay_exit_id, closest) != kKadSuccess) {
                SMERROR(message.xrequest_id().c_str(), message.seq(),
                        "ClosestToTarget goes wrong");
                return kErrorReturn;
            }
            if (!closest) {
                SMERROR(message.xrequest_id().c_str(), message.seq(),
                        "SendToClosestNode");
                routing_table->SendToClosestNode(message);
                return kSuccessReturn;
            }
            // in this relay p2p network, arrive the closest node of next_relay_exit_id
            SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                    "message in %llu p2p network arrive"
                    "the closest_node[%s] of the next_relay_exit_id of this p2p network,"
                    "will begin get cache_service_public_nodes",
                    chosen_service_type,
                    HexEncode(local_node->id()).c_str());
            // need modify next_relay_exit_id 
            transport::protobuf::RelayHopInfo* relay_hop_info_mutable =
                    message.mutable_relay_hop_info(relay_hop_info_size - 1);
            relay_hop_info_mutable->set_relay_exit_id(local_node->id());
            relay_hop_info_mutable->set_relay_flag(true);

            RelayMsgToNextServiceNetwork(message, routing_table);
            return kSuccessReturn;
        }
    }
}


void WrouterMessageHandler::SendMultiRelayResponse(transport::protobuf::RoutingMessage& message) {
    // do nothing but debug in this function
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "message(%d) arrive dest node ,will send response", message.type());
    //PrintTraceRoute(message);
}

void WrouterMessageHandler::PrintTraceRoute(transport::protobuf::RoutingMessage& message) {
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "message(%d) trace_route size %d", message.type(), message.trace_route_size());
    for (int i = 0; i < message.trace_route_size(); ++i) {
        SMDEBUG(message.xrequest_id().c_str(), message.seq(),
                "trace_route(%d) is (%s)",
                i,
                message.trace_route(i).c_str());
    }
}

void WrouterMessageHandler::CallbackMultiRelayResponse(transport::protobuf::RoutingMessage& message) {
    // do nothing but debug in this function
    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "message(%d) arrive asker node ,relay message finished", message.type());
    PrintTraceRoute(message);
}

int WrouterMessageHandler::HandleMultiRelayResponse(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    SMDEBUG(message.xrequest_id().c_str(), message.seq(), "HandleMultiRelayResponse");
    if (!message.has_multi_relay() || !message.multi_relay()) {
        return kErrorReturn;
    }
    int request_type = GetRequestType(message.type());
    if (request_type != kResponseMsg) {
        return kErrorReturn;
    }

    RoutingTablePtr routing_table = MultiRelayGetSmartRoutingTable(message);
    if (!routing_table) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "service type[%llu] has not register routing table.",
                message.des_service_type());
        return kErrorReturn;
    }
    LocalNodeInfoPtr local_node = routing_table->get_local_node_info();
    if (!local_node) {
        return kErrorReturn;
    }
    uint64_t chosen_service_type = local_node->service_type();
    if (chosen_service_type != message.src_service_type()
            || chosen_service_type != message.des_service_type()) {
        SMERROR(message.xrequest_id().c_str(), message.seq(),
                "TestMultiRelayResponse service_type not right, "
                "local_service_type[%llu];message_src_service_type[%llu];"
                "message_des_service_type[%llu]",
                chosen_service_type,
                message.src_service_type(),
                message.des_service_type());
        return kErrorReturn;
    }
    // multirelay msg finished
    if (message.relay_hop_info_size() == 0 && message.des_node_id() == local_node->id()) {
        message.add_trace_route(HexEncode(local_node->id()));
        CallbackMultiRelayResponse(message);
        return kContinue;
    }

    SMDEBUG(message.xrequest_id().c_str(), message.seq(),
            "HandleMultiRelayResponse SmartSendReply");
    routing_table->SmartSendReply(message);
    return kSuccessReturn;
}


}  // namespace wrouter

}  // namespace top
