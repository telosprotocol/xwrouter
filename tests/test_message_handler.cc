// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>

#include <string>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define protected public
#define private public

#include "xpbase/base/top_log.h"
#include "xpbase/base/top_utils.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#include "xtransport/udp_transport/udp_transport.h"
#include "xtransport/proto/transport.pb.h"
#include "xtransport/message_manager/message_manager_intf.h"
#include "xkad/routing_table/routing_utils.h"
#include "xkad/routing_table/node_info.h"
#include "xkad/routing_table/node_detection_manager.h"
#include "xkad/routing_table/callback_manager.h"
#include "xtransport/message_manager/multi_message_handler.h"
#include "xstobject/smart_object.h"
#include "xkad/routing_table/routing_table.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xkad/routing_table/local_node_info.h"
#include "xwrouter/register_routing_table.h"
#include "xkad/nat_detect/nat_manager_intf.h"
#include "routing_performance/performance_utils.h"  // TODO: ?
#include "xstobject/smart_object_utils.h"

using ::testing::AtLeast;
using ::testing::_;
using testing::Return;

namespace top {

namespace kadmlia {

namespace test {

class TestMessageHandler : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
        base::Config config;
        ASSERT_TRUE(config.Init("./conf.ut/test_routing_table.conf"));
        std::string local_ip;
        ASSERT_TRUE(config.Get("node", "local_ip", local_ip));
        uint16_t local_port = 0;
        ASSERT_TRUE(config.Get("node", "local_port", local_port));
        NatManagerIntf::Instance()->SetNatType(kNatTypePublic);
        udp_transport_.reset(new transport::UdpTransport());
        thread_message_handler_ = std::make_shared<transport::MultiThreadHandler>();
        thread_message_handler_->Init();
        ASSERT_TRUE(udp_transport_->Start(
            local_ip,
            local_port,
            thread_message_handler_.get()) == top::kadmlia::kKadSuccess);

        auto kad_key = std::make_shared<base::PlatformKadmliaKey>();
        kad_key->set_xnetwork_id(top::kEdgeXVPN);
        uint32_t zone_id = 0;
        ASSERT_TRUE(GetZoneIdFromConfig(config, zone_id));
        kad_key->set_zone_id(zone_id);
        auto local_node_ptr = CreateLocalInfoFromConfig(config, kad_key);

        routing_table_ptr_.reset(new top::kadmlia::RoutingTable(udp_transport_, kNodeIdSize, local_node_ptr));
        ASSERT_TRUE(routing_table_ptr_->Init());
        local_node_info_ = routing_table_ptr_->local_node_ptr_;
        top::wrouter::UnregisterRoutingTable(top::kEdgeXVPN);
        top::wrouter::RegisterRoutingTable(kEdgeXVPN, routing_table_ptr_);
    }

    virtual void TearDown() {
        wrouter::UnregisterRoutingTable(kEdgeXVPN);
    }

private:
    std::shared_ptr<RoutingTable> routing_table_ptr_;
    LocalNodeInfoPtr local_node_info_;
    top::transport::UdpTransportPtr udp_transport_;
    std::shared_ptr<transport::MultiThreadHandler> thread_message_handler_;
};

TEST_F(TestMessageHandler, AddBaseHandlers) {
    wrouter::WrouterMessageHandler message_handler;
}

TEST_F(TestMessageHandler, HandleConnectRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    hop->set_ip(local_node_info_->public_ip());
    hop->set_port(local_node_info_->public_port());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kKadConnectRequest);
    message.set_id(CallbackManager::MessageId());

    if (local_node_info_->client_mode()) {
        message.set_client_msg(true);
        message.set_relay_flag(true);
        message.set_request_type(true);
        message.set_client_id(local_node_info_->id());
    }

    protobuf::ConnectReq conn_req;
    conn_req.set_local_ip(local_node_info_->local_ip());
    conn_req.set_local_port(local_node_info_->local_port());
    conn_req.set_public_ip(local_node_info_->public_ip());
    conn_req.set_public_port(local_node_info_->public_port());
    std::string data;
    if (!conn_req.SerializeToString(&data)) {
        TOP_INFO("ConnectReq SerializeToString failed!");
        return;
    }
    message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleMessage(message, packet);
    message_handler.HandleConnectRequest(message, packet);

    message.set_des_node_id(local_node_info_->id());
    message_handler.HandleConnectRequest(message, packet);

    message.set_hop_num(100);
    message_handler.HandleMessage(message, packet);
    message.set_hop_num(1);
    message.set_client_msg(true);
    message_handler.HandleMessage(message, packet);
    message_handler.HandleConnectRequest(message, packet);

    message.set_request_type(false);
    message.set_relay_flag(false);
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_request_type(false);
    message.set_relay_flag(true);
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_request_type(true);
    message.set_relay_flag(false);
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_request_type(true);
    message.set_relay_flag(true);
    message.set_des_node_id(GenRandomID("CN", "VPN"));
}

TEST_F(TestMessageHandler, HandleHandshake) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());

    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id("");
    message.set_type(kKadHandshake);
    message.set_id(CallbackManager::MessageId());
    protobuf::Handshake handshake;
    handshake.set_type(kHandshakeRequest);
    handshake.set_local_ip(local_node_info_->local_ip());
    handshake.set_local_port(local_node_info_->local_port());
    std::string data;
    ASSERT_TRUE(handshake.SerializeToString(&data));
    message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleHandshake(message, packet);

    message.set_type(kHandshakeResponse);
    message_handler.HandleHandshake(message, packet);
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleBootstrapJoinRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id("");
    message.set_type(kKadBootstrapJoinRequest);
    message.set_id(CallbackManager::MessageId());
    if (local_node_info_->client_mode()) {
        message.set_client_msg(true);
    }

    protobuf::BootstrapJoinRequest conn_req;
    conn_req.set_local_ip(local_node_info_->local_ip());
    conn_req.set_local_port(local_node_info_->local_port());
    std::string data;
    ASSERT_TRUE(conn_req.SerializeToString(&data));
    message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleBootstrapJoinRequest(message, packet);
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleBootstrapJoinResponse) {
    transport::protobuf::RoutingMessage res_message;
    transport::protobuf::HopInfo* hop = res_message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    res_message.set_src_service_type(kEdgeXVPN);
    res_message.set_des_service_type(kEdgeXVPN);
    res_message.set_hop_num(0);
    res_message.set_src_node_id(local_node_info_->id());
    res_message.set_des_node_id("");
    res_message.set_type(kKadBootstrapJoinResponse);
    res_message.set_id(CallbackManager::MessageId());

    protobuf::BootstrapJoinResponse con_res;
    con_res.set_public_ip("");
    con_res.set_public_port(0);
    con_res.set_bootstrap_id(local_node_info_->id());
    std::string data;
    ASSERT_TRUE(con_res.SerializeToString(&data));
    res_message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleBootstrapJoinResponse(res_message, packet);
    message_handler.HandleMessage(res_message, packet);
}

TEST_F(TestMessageHandler, HandleFindNodesRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kKadFindNodesRequest);
    message.set_id(CallbackManager::MessageId());

    for (int i = 0; i < 10; ++i) {
        std::string id = GenRandomID("CN", "VPN");
        NodeInfoPtr node_ptr;
        node_ptr.reset(new NodeInfo(id));
        node_ptr->public_ip = "127.0.0.1";
        node_ptr->public_port = i + 1;
        node_ptr->local_ip = "127.0.0.1";
        node_ptr->local_port = i + 1;
        routing_table_ptr_->AddNode(node_ptr);
    }

    protobuf::FindClosestNodesRequest find_nodes_req;
    find_nodes_req.set_count(10);
    find_nodes_req.set_target_id(local_node_info_->id());
    std::string data;
    ASSERT_TRUE(find_nodes_req.SerializeToString(&data));
    message.set_data(data);    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleFindNodesRequest(message, packet);
    local_node_info_->first_node_ = true;
    message_handler.HandleFindNodesRequest(message, packet);
    local_node_info_->first_node_ = false;
    message_handler.HandleMessage(message, packet);
    message.set_des_node_id(local_node_info_->id());
    message_handler.HandleFindNodesRequest(message, packet);
    local_node_info_->first_node_ = true;
    message_handler.HandleFindNodesRequest(message, packet);
    message.clear_data();
    message_handler.HandleFindNodesRequest(message, packet);
    message.set_data("data");
    message_handler.HandleFindNodesRequest(message, packet);
    routing_table_ptr_->nodes_.clear();
}

TEST_F(TestMessageHandler, HandleFindNodesResponse) {
    protobuf::FindClosestNodesResponse find_nodes_res;
    for (uint32_t i = 0; i < 10; ++i) {
        protobuf::NodeInfo* tmp_node = find_nodes_res.add_nodes();
        tmp_node->set_id(GenRandomID("CN", "VPN"));
        tmp_node->set_public_ip("127.0.0.1");
        tmp_node->set_public_port(i);
        tmp_node->set_local_ip("127.0.0.1");
        tmp_node->set_local_port(i);
    }

    if (find_nodes_res.nodes_size() <= 0) {
        return;
    }

    std::string data;
    ASSERT_TRUE(find_nodes_res.SerializeToString(&data));
    transport::protobuf::RoutingMessage res_message;
    transport::protobuf::HopInfo* hop = res_message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    res_message.set_src_service_type(kEdgeXVPN);
    res_message.set_des_service_type(kEdgeXVPN);
    res_message.set_hop_num(0);
    res_message.set_src_node_id(local_node_info_->id());
    res_message.set_des_node_id(GenRandomID("CN", "VPN"));
    res_message.set_type(kKadFindNodesResponse);
    res_message.set_id(0);
    res_message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleFindNodesResponse(res_message, packet);
    message_handler.HandleMessage(res_message, packet);
    res_message.clear_data();
    message_handler.HandleFindNodesResponse(res_message, packet);
    res_message.set_data("data");
    message_handler.HandleFindNodesResponse(res_message, packet);
}

TEST_F(TestMessageHandler, HandleHeartbeatRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    hop->set_ip(local_node_info_->public_ip());
    hop->set_port(local_node_info_->public_port());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kKadHeartbeatRequest);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleHeartbeatRequest(message, packet);
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleHeartbeatResponse) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    hop->set_ip(local_node_info_->public_ip());
    hop->set_port(local_node_info_->public_port());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kKadHeartbeatResponse);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleHeartbeatResponse(message, packet);
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleRoundTripTimeRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kRoundTripTimeRequest);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;

    message.set_des_node_id(local_node_info_->id());
    message.set_type(kRoundTripTimeRequest);
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleRoundTripTimeResponse) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kRoundTripTimeResponse);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;

    message.set_des_node_id(local_node_info_->id());
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleRelayTestRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kRelayTestRequest);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message.set_des_node_id(local_node_info_->id());
    message.set_type(kRelayTestRequest);
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleRelayTestResponse) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kRelayTestResponse);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleTellBootstrapStopped) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(local_node_info_->id());
    message.set_type(kTellBootstrapStopped);
    message.set_id(CallbackManager::MessageId());
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleMessage(message, packet);
}

TEST_F(TestMessageHandler, HandleGetGroupNodesRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kGetGroupNodesRequest);
    message.set_id(CallbackManager::MessageId());
    protobuf::GetNearestNodesRequest get_nodes_req;
    get_nodes_req.set_target_id(GenRandomID("CN", "VPN"));
    get_nodes_req.set_count(4);
    std::string data;
    ASSERT_TRUE(get_nodes_req.SerializeToString(&data));
    message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleMessage(message, packet);
    message.set_des_node_id(local_node_info_->id());
}

TEST_F(TestMessageHandler, HandleGetGroupNodesResponse) {
    transport::protobuf::RoutingMessage res_message;
    transport::protobuf::HopInfo* hop = res_message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    res_message.set_src_service_type(kEdgeXVPN);
    res_message.set_des_service_type(kEdgeXVPN);
    res_message.set_hop_num(0);
    res_message.set_src_node_id(local_node_info_->id());
    res_message.set_des_node_id(GenRandomID("CN", "VPN"));
    res_message.set_type(kGetGroupNodesResponse);
    res_message.set_id(0);
    protobuf::GetNearestNodesResponse get_nodes_res;
    protobuf::NodeInfo* node_info = get_nodes_res.add_nodes();
    node_info->set_id(local_node_info_->id());
    for (uint32_t i = 0; i < 4; ++i) {
        protobuf::NodeInfo* node_info = get_nodes_res.add_nodes();
        node_info->set_id(GenRandomID("CN", "VPN"));
    }
    std::string data;
    ASSERT_TRUE(get_nodes_res.SerializeToString(&data));
    res_message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleMessage(res_message, packet);
}
// 
// TEST_F(TestMessageHandler, HandleUdpNatDetectRequest) {
//     transport::protobuf::RoutingMessage message;
        //message.set_src_service_type(kEdgeXVPN);
        //message.set_des_service_type(kEdgeXVPN);
//     message.set_src_node_id("");
//     message.set_des_node_id("");
//     message.set_type(kUdpNatDetectRequest);
//     message.set_id(0);
//     message.set_hop_num(0);
// 
//     kadmlia::protobuf::UdpNatDetectRequest detect_req;
//     detect_req.set_resv(0);
//     std::string data;
//     ASSERT_TRUE(detect_req.SerializeToString(&data));
//     message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleUdpNatDetectRequest(message, packet);
// 
//     packet.set_from_ip_addr("127.0.0.1");
//     packet.set_from_sys_port(10);
//     message_handler.HandleUdpNatDetectRequest(message, packet);
//     message_handler.HandleMessage(message, packet);
//     message.clear_data();
//     message_handler.HandleUdpNatDetectRequest(message, packet);
//     message.set_data("data");
//     message_handler.HandleUdpNatDetectRequest(message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleUdpNatDetectResponse) {
//     transport::protobuf::RoutingMessage res_message;
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_src_node_id("");
//     res_message.set_des_node_id("");
//     res_message.set_type(UdpNatDetectResponse);
//     res_message.set_id(1);
//     res_message.set_hop_num(0);
// 
//     protobuf::UdpNatDetectResponse detect_res;
//     detect_res.set_public_ip("127.0.0.1");
//     detect_res.set_public_port(1000);
//     std::string data;
//     ASSERT_TRUE(detect_res.SerializeToString(&data));
//     res_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleUdpNatDetectResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
//     res_message.clear_data();
//     message_handler.HandleUdpNatDetectResponse(res_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleUdpNatHeartbeat) {
//     transport::protobuf::RoutingMessage message;
//     message.set_src_service_type(kEdgeXVPN);
//     message.set_des_service_type(kEdgeXVPN);
//     message.set_src_node_id("");
//     message.set_des_node_id("");
//     message.set_type(kUdpNatHeartbeat);
//     message.set_id(0);
//     message.set_hop_num(0);
// 
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleUdpNatHeartbeat(message, packet);
//     message_handler.HandleMessage(message, packet);
// }

TEST_F(TestMessageHandler, HandleGetAllNodesFromBootRequest) {
    transport::protobuf::RoutingMessage message;
    transport::protobuf::HopInfo* hop = message.add_hop_nodes();
    hop->set_node_id(local_node_info_->id());
    message.set_src_service_type(kEdgeXVPN);
    message.set_des_service_type(kEdgeXVPN);
    message.set_hop_num(0);
    message.set_src_node_id(local_node_info_->id());
    message.set_des_node_id(GenRandomID("CN", "VPN"));
    message.set_type(kGetAllNodesFromBootRequest);
    message.set_id(0);

    protobuf::GetAllNodesFromBootRequest req;
    req.set_start_pos(0);
    req.set_len(10);
    std::string data;
    ASSERT_TRUE(req.SerializeToString(&data));
    message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message.set_des_node_id(local_node_info_->id());
    message_handler.HandleMessage(message, packet);
    for (int i = 0; i < 10; ++i) {
        std::string id = GenRandomID("CN", "VPN");
        NodeInfoPtr node_ptr;
        node_ptr.reset(new NodeInfo(id));
        node_ptr->public_ip = "127.0.0.1";
        node_ptr->public_port = i + 1;
        node_ptr->local_ip = "127.0.0.1";
        node_ptr->local_port = i + 1;
    }
}

TEST_F(TestMessageHandler, HandleGetAllNodesFromBootResponse) {
    transport::protobuf::RoutingMessage res_message;
    res_message.set_src_node_id(GenRandomID("CN", "VPN"));
    res_message.set_des_node_id(GenRandomID("CN", "VPN"));
    res_message.set_type(kGetAllNodesFromBootResponse);
    res_message.set_id(1);
    res_message.set_hop_num(1);
    res_message.set_src_service_type(kEdgeXVPN);
    res_message.set_des_service_type(kEdgeXVPN);

    protobuf::GetAllNodesFromBootResponse nodes_res;
    for (uint32_t i = 0; i < 10; ++i) {
        auto ptr_node_info = nodes_res.add_nodes();
        ptr_node_info->set_id(GenRandomID("CN", "VPN"));
    }
    std::string data;
    ASSERT_TRUE(nodes_res.SerializeToString(&data));
    res_message.set_data(data);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.HandleMessage(res_message, packet);
}

// TEST_F(TestMessageHandler, HandleEdgeNodesRequest) {
//     transport::protobuf::RoutingMessage message;
//     transport::protobuf::HopInfo* hop = message.add_hop_nodes();
//     hop->set_node_id(kadmlia::local_node_info_->id());
//     message.set_src_service_type(kEdgeXVPN);
//     message.set_des_service_type(kEdgeXVPN);
//     message.set_hop_num(0);
//     message.set_src_node_id(kadmlia::local_node_info_->id());
//     message.set_des_node_id(GenRandomID("CN", "VPN"));
//     message.set_type(EdgeNodesRequest);
//     message.set_id(CallbackManager::MessageId());
//     if (kadmlia::local_node_info_->client_mode()) {
//         message.set_client_msg(true);
//         message.set_relay_flag(true);
//         message.set_request_type(true);
//         message.set_client_id(kadmlia::local_node_info_->id());
//     }
// 
//     protobuf::EdgeNodesRequest get_nodes_req;
//     get_nodes_req.set_target_id(GenRandomID("CN", "VPN"));
//     get_nodes_req.set_count(4);
//     std::string data;
//     ASSERT_TRUE(get_nodes_req.SerializeToString(&data));
//     message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleEdgeNodesRequest(message, packet);
//     message.set_des_node_id(kadmlia::local_node_info_->id());
//     message_handler.HandleEdgeNodesRequest(message, packet);
//     message.set_client_msg(true);
//     message.set_des_node_id(GenRandomID("CN", "VPN"));
//     message_handler.HandleEdgeNodesRequest(message, packet);
//     message_handler.HandleMessage(message, packet);
// }

// TEST_F(TestMessageHandler, HandleEdgeNodesResponse) {
//     transport::protobuf::RoutingMessage res_message;
//     transport::protobuf::HopInfo* hop = res_message.add_hop_nodes();
//     hop->set_node_id(local_node_info_->id());
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_hop_num(0);
//     res_message.set_src_node_id(local_node_info_->id());
//     res_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     res_message.set_type(EdgeNodesResponse);
//     res_message.set_id(1);
//     protobuf::EdgeNodesResponse get_nodes_res;
//     protobuf::NodeInfo* node_info = get_nodes_res.add_nodes();
//     node_info->set_id(local_node_info_->id());
//     node_info->set_public_ip(local_node_info_->public_ip());
//     node_info->set_public_port(local_node_info_->public_port());
//     node_info->set_local_ip(local_node_info_->local_ip());
//     node_info->set_local_port(local_node_info_->local_port());
//     std::string target_type = (GenRandomID("CN", "VPN")).substr(0, 2);
//     for (uint32_t i = 0; i < 4; ++i) {
//         std::string node_id_type = (GenRandomID("CN", "VPN")).substr(0, 2);
//         if (target_type.compare(node_id_type) == 0) {
//             protobuf::NodeInfo* node_info = get_nodes_res.add_nodes();
//             node_info->set_id(GenRandomID("CN", "VPN"));
//             node_info->set_public_ip("127.0.0.1");
//             node_info->set_public_port(i);
//             node_info->set_local_ip("127.0.0.1");
//             node_info->set_local_port(i);
//         }
//     }
//     std::string data;
//     ASSERT_TRUE(get_nodes_res.SerializeToString(&data));
//     res_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleEdgeNodesResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
//     res_message.set_client_msg(true);
//     message_handler.HandleEdgeNodesResponse(res_message, packet);
//     res_message.set_des_node_id(local_node_info_->id());
//     message_handler.HandleEdgeNodesResponse(res_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectStoreRelayRequest) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage req_message;
//     transport::protobuf::HopInfo* hop = req_message.add_hop_nodes();
//     hop->set_node_id(local_node_info_->id());
//     req_message.set_hop_num(0);
//     req_message.set_src_service_type(kEdgeXVPN);
//     req_message.set_des_service_type(kEdgeXVPN);
//     req_message.set_src_node_id(local_node_info_->id());
//     req_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     req_message.set_type(SmartObjectStoreRelayRequest);
//     req_message.set_id(1);
// 
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_type(SmartObjectKv);
//     smart_object_data.set_oper(kSmartObjectPut);
//     smart_object_data.set_key("key");
//     smart_object_data.set_value("value");
//     smart_object_data.set_ttl(1000);
// 
//     std::string data;
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     req_message.set_data(data);
//     base::xpacket_t packet;
// 
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectStoreRelayRequest(req_message, packet);
//     smart_object_data.set_type(SmartObjectList);
//     message_handler.HandleSmartObjectStoreRelayRequest(req_message, packet);
//     req_message.set_des_node_id(local_node_info_->id());
//     smart_object_data.set_type(SmartObjectKv);
//     message_handler.HandleSmartObjectStoreRelayRequest(req_message, packet);
//     req_message.set_des_node_id(local_node_info_->id());
//     smart_object_data.set_type(SmartObjectList);
//     message_handler.HandleSmartObjectStoreRelayRequest(req_message, packet);
//     message_handler.HandleMessage(req_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectStoreRelayResponse) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage res_message;
//     transport::protobuf::HopInfo* hop_info = res_message.add_hop_nodes();
//     hop_info->set_node_id(local_node_info_->id());
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_hop_num(0);
//     res_message.set_src_node_id(local_node_info_->id());
//     res_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     res_message.set_type(SmartObjectStoreRelayResponse);
//     res_message.set_id(1);
//     res_message.set_status(kKadSuccess);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectStoreRelayResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectStoreRequest) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage req_message;
//     transport::protobuf::HopInfo* hop = req_message.add_hop_nodes();
//     hop->set_node_id(local_node_info_->id());
//     req_message.set_src_service_type(kEdgeXVPN);
//     req_message.set_des_service_type(kEdgeXVPN);
//     req_message.set_hop_num(0);
//     req_message.set_src_node_id(local_node_info_->id());
//     req_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     req_message.set_type(SmartObjectStoreRequest);
//     req_message.set_id(1);
// 
//     std::string data;
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_key("test");
//     smart_object_data.set_value("test");
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     req_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectStoreRequest(req_message, packet);
//     message_handler.HandleMessage(req_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectStoreResponse) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage res_message;
//     transport::protobuf::HopInfo* hop_info = res_message.add_hop_nodes();
//     hop_info->set_node_id(local_node_info_->id());
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_hop_num(0);
//     res_message.set_src_node_id(local_node_info_->id());
//     res_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     res_message.set_type(SmartObjectStoreResponse);
//     res_message.set_id(1);
//     res_message.set_status(kKadSuccess);
// 
//     std::string data;
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_key("test");
//     smart_object_data.set_value("test");
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     res_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectStoreResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectFindValueRequest) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage req_message;
//     transport::protobuf::HopInfo* hop = req_message.add_hop_nodes();
//     hop->set_node_id(local_node_info_->id());
//     req_message.set_src_service_type(kEdgeXVPN);
//     req_message.set_des_service_type(kEdgeXVPN);
//     req_message.set_hop_num(0);
//     req_message.set_src_node_id(local_node_info_->id());
//     req_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     req_message.set_type(SmartObjectFindValueRequest);
//     req_message.set_id(1);
//     std::string data;
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_key("test");
//     smart_object_data.set_value("test");
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     req_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectFindValueRequest(req_message, packet);
//     message_handler.HandleMessage(req_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectFindValueResponse) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage res_message;
//     transport::protobuf::HopInfo* hop_info = res_message.add_hop_nodes();
//     hop_info->set_node_id(local_node_info_->id());
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_hop_num(0);
//     res_message.set_src_node_id(local_node_info_->id());
//     res_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     res_message.set_type(SmartObjectFindValueResponse);
//     res_message.set_id(1);
//     res_message.set_status(kKadSuccess);
// 
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_type(top::storage::kSmartObjectKv);
//     smart_object_data.set_oper(top::storage::kSmartObjectGet);
//     smart_object_data.set_key("key");
//     smart_object_data.set_value("value");
//     std::string data;
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     res_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectFindValueResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectFindValueRelayRequest) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage req_message;
//     transport::protobuf::HopInfo* hop = req_message.add_hop_nodes();
//     hop->set_node_id(local_node_info_->id());
//     req_message.set_src_service_type(kEdgeXVPN);
//     req_message.set_des_service_type(kEdgeXVPN);
//     req_message.set_hop_num(0);
//     req_message.set_src_node_id(local_node_info_->id());
//     req_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     req_message.set_type(SmartObjectFindValueRelayRequest);
//     req_message.set_id(1);
// 
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_type(SmartObjectKv);
//     smart_object_data.set_oper(kSmartObjectGet);
//     smart_object_data.set_key("key");
//     std::string data;
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     req_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectFindValueRelayRequest(req_message, packet);
//     message_handler.HandleMessage(req_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectFindValueRelayResponse) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage res_message;
//     transport::protobuf::HopInfo* hop_info = res_message.add_hop_nodes();
//     hop_info->set_node_id(local_node_info_->id());
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_hop_num(0);
//     res_message.set_src_node_id(local_node_info_->id());
//     res_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     res_message.set_type(SmartObjectFindValueRelayResponse);
//     res_message.set_id(1);
//     res_message.set_status(kKadSuccess);
// 
//     std::string data;
//     protobuf::SmartObjectData smart_object_data;
//     smart_object_data.set_type(SmartObjectKv);
//     smart_object_data.set_oper(kSmartObjectGet);
//     smart_object_data.set_key("key");
//     ASSERT_TRUE(smart_object_data.SerializeToString(&data));
//     res_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectFindValueRelayResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
// }
// 
// TEST_F(TestMessageHandler, HandleSmartObjectRefreshKeyRequest) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage req_message;
//     transport::protobuf::HopInfo* hop = req_message.add_hop_nodes();
//     hop->set_node_id(local_node_info_->id());
//     req_message.set_src_service_type(kEdgeXVPN);
//     req_message.set_des_service_type(kEdgeXVPN);
//     req_message.set_hop_num(0);
//     req_message.set_src_node_id(local_node_info_->id());
//     req_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     req_message.set_type(SmartObjectRefreshKeyRequest);
//     req_message.set_id(1);
// 
//     protobuf::SmartObjectRefreshData refresh_data;
//     for (uint32_t i = 0; i < 10; i++) {
//         protobuf::SmartObjectTuple* tuple;
//         tuple = refresh_data.add_list_tuple();
//         tuple->set_type(kSmartObjectKv);
//         tuple->set_key("key");
//         tuple->set_save_time(10);
//     }
// 
//     std::string data;
//     ASSERT_TRUE(refresh_data.SerializeToString(&data));
//     req_message.set_data(data);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectRefreshKeyRequest(req_message, packet);
//     message_handler.HandleMessage(req_message, packet);
// }

// TEST_F(TestMessageHandler, HandleSmartObjectRefreshKeyResponse) {
//     using namespace top::storage;
//     transport::protobuf::RoutingMessage res_message;
//     transport::protobuf::HopInfo* hop_info = res_message.add_hop_nodes();
//     hop_info->set_node_id(local_node_info_->id());
//     res_message.set_src_service_type(kEdgeXVPN);
//     res_message.set_des_service_type(kEdgeXVPN);
//     res_message.set_hop_num(0);
//     res_message.set_src_node_id(local_node_info_->id());
//     res_message.set_des_node_id(GenRandomID("CN", "VPN"));
//     res_message.set_type(SmartObjectRefreshKeyResponse);
//     res_message.set_id(1);
//     res_message.set_status(kKadSuccess);
//     base::xpacket_t packet;
//     wrouter::WrouterMessageHandler message_handler;
//     message_handler.HandleSmartObjectRefreshKeyResponse(res_message, packet);
//     message_handler.HandleMessage(res_message, packet);
// }

TEST_F(TestMessageHandler, SendAck) {
    using namespace top::storage;
    transport::protobuf::RoutingMessage res_message;
    transport::protobuf::HopInfo* hop_info = res_message.add_hop_nodes();
    hop_info->set_node_id(local_node_info_->id());
    res_message.set_src_service_type(kEdgeXVPN);
    res_message.set_des_service_type(kEdgeXVPN);
    res_message.set_hop_num(0);
    res_message.set_src_node_id(local_node_info_->id());
    res_message.set_des_node_id(GenRandomID("CN", "VPN"));
    res_message.set_type(storage::kSmartObjectRefreshKeyResponse);
    res_message.set_id(1);
    res_message.set_status(kKadSuccess);
    base::xpacket_t packet;
    wrouter::WrouterMessageHandler message_handler;
    message_handler.SendAck(res_message, packet);
}

// TEST_F(TestMessageHandler, SendConnectRequest) {
//     using namespace top::storage;
//     wrouter::WrouterMessageHandler message_handler;
//     auto nodes = routing_table_ptr_->nodes_;
//     routing_table_ptr_->nodes_.clear();
//     message_handler.SendConnectRequest(GenRandomID("CN", "VPN"), kEdgeXVPN);
//     local_node_info_->client_mode_ = true;
//     message_handler.SendConnectRequest(GenRandomID("CN", "VPN"), kEdgeXVPN);
//     local_node_info_->client_mode_ = false;
//     routing_table_ptr_->nodes_ = nodes;
// }

}  // namespace test

}  // namespace kadmlia

}  // namespace top
