// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>

#include <string>
#include <set>

#include <gtest/gtest.h>

#include "xpbase/base/endpoint_util.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#define protected public
#define private public
#include "xtransport/udp_transport/udp_transport.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/local_node_info.h"
#include "xwrouter/root/root_routing.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xtransport/message_manager/multi_message_handler.h"
#include "xwrouter/root/root_routing_manager.h"
#include "xwrouter/register_routing_table.h"
#include "xkad/nat_detect/nat_manager_intf.h"

namespace top {

namespace kadmlia {

namespace test {

class TestRootRoutingManager : public testing::Test {
public:
	static void SetUpTestCase() {
	}

	static void TearDownTestCase() {
	}

	virtual void SetUp() {
	}

	virtual void TearDown() {
	}
};

TEST_F(TestRootRoutingManager, GetRootNodesFail) {
    wrouter::RootRoutingManager root_manager;
    std::vector<NodeInfoPtr> root_nodes;
    ASSERT_EQ(root_manager.GetRootNodes(kRoot, root_nodes), kKadFailed);
}

TEST_F(TestRootRoutingManager, GetRootBootstrapCacheFail) {
    wrouter::RootRoutingManager root_manager;
    std::set<std::pair<std::string, uint16_t>> boot_endpoints;
    ASSERT_EQ(root_manager.GetRootBootstrapCache(boot_endpoints), kKadFailed);
}

TEST_F(TestRootRoutingManager, AddRoutingTableFail) {
    wrouter::RootRoutingManager root_manager;
    base::Config config;
    base::KadmliaKeyPtr kad_key_ptr = std::make_shared<base::PlatformKadmliaKey>();
    ASSERT_EQ(root_manager.AddRoutingTable(nullptr, config, kad_key_ptr), kKadFailed);

    top::transport::UdpTransportPtr udp_transport;
    udp_transport.reset(new top::transport::UdpTransport());
    ASSERT_EQ(root_manager.AddRoutingTable(nullptr, config, kad_key_ptr), kKadFailed);
}

TEST_F(TestRootRoutingManager, ClientTest) {
    wrouter::WrouterMessageHandler message_handler;
    std::shared_ptr<wrouter::RootRoutingManager> root_manager;
    root_manager.reset(new wrouter::RootRoutingManager());
    wrouter::SetRootRoutingManager(root_manager);
    base::Config config;
    ASSERT_TRUE(config.Init("./conf.ut/test_root.conf"));
    std::string local_ip;
    ASSERT_TRUE(config.Get("node", "local_ip", local_ip));
    uint16_t local_port = 0;
    ASSERT_TRUE(config.Get("node", "local_port", local_port));
    ASSERT_TRUE(config.Set("node", "client_mode", true));
    top::transport::UdpTransportPtr udp_transport;
    udp_transport.reset(new top::transport::UdpTransport());
    std::set<std::pair<std::string, uint16_t>> public_endpoints_config;
    std::string public_endpoints;
    if (!config.Get("node", "public_endpoints", public_endpoints)) {
        TOP_INFO("<blueshi> node join must has bootstrap endpoints!");
        return;
    }
    top::base::ParseEndpoints(public_endpoints, public_endpoints_config);
    auto thread_message_handler = std::make_shared<transport::MultiThreadHandler>();
    thread_message_handler->Init();

    ASSERT_TRUE(udp_transport->Start(local_ip, local_port, thread_message_handler.get()) == kKadSuccess);
    NatManagerIntf::Instance()->SetNatType(kNatTypePublic);
    base::KadmliaKeyPtr kad_key_ptr = std::make_shared<base::PlatformKadmliaKey>();
    kad_key_ptr->set_xnetwork_id(kRoot);
    ASSERT_EQ(root_manager->AddRoutingTable(
        udp_transport, config, kad_key_ptr), kKadSuccess);
    std::shared_ptr<RoutingTable> root_table = root_manager->GetRoutingTable(kRoot);
    ASSERT_TRUE(root_table != nullptr);
    kad_key_ptr->set_xnetwork_id(kEdgeTopMessage);
    ASSERT_EQ(root_manager->AddRoutingTable(
        udp_transport, config, kad_key_ptr), kKadSuccess);
    std::shared_ptr<RoutingTable> client_table = root_manager->GetRoutingTable(
            kad_key_ptr->GetServiceType());
    ASSERT_TRUE(client_table != nullptr);
    std::vector<NodeInfoPtr> nodes;
    ASSERT_EQ(root_manager->GetRootNodes(kRoot, nodes), kKadSuccess);
    ASSERT_TRUE(!nodes.empty());
    root_manager->RemoveRoutingTable(kRoot);
    root_manager->RemoveRoutingTable(kad_key_ptr->GetServiceType());
    ASSERT_TRUE(root_manager->root_routing_map_.empty());
    udp_transport->Stop();
}

TEST_F(TestRootRoutingManager, NodeTest) {
    wrouter::WrouterMessageHandler message_handler;
    std::shared_ptr<wrouter::RootRoutingManager> root_manager;
    root_manager.reset(new wrouter::RootRoutingManager());
    SetRootRoutingManager(root_manager);
    base::Config config;
    ASSERT_TRUE(config.Init("./conf.ut/test_root.conf"));
    std::string local_ip;
    ASSERT_TRUE(config.Get("node", "local_ip", local_ip));
    uint16_t local_port = 0;
    ASSERT_TRUE(config.Get("node", "local_port", local_port));
    ASSERT_TRUE(config.Set("node", "client_mode", false));
    top::transport::UdpTransportPtr udp_transport;
    udp_transport.reset(new top::transport::UdpTransport());
    std::set<std::pair<std::string, uint16_t>> public_endpoints_config;
    std::string public_endpoints;
    if (!config.Get("node", "public_endpoints", public_endpoints)) {
        TOP_INFO("<blueshi> node join must has bootstrap endpoints!");
        return;
    }
    top::base::ParseEndpoints(public_endpoints, public_endpoints_config);
    auto thread_message_handler = std::make_shared<transport::MultiThreadHandler>();
    thread_message_handler->Init();
    ASSERT_TRUE(udp_transport->Start(local_ip, local_port, thread_message_handler.get()) == kKadSuccess);
    NatManagerIntf::Instance()->SetNatType(kNatTypePublic);
    base::KadmliaKeyPtr kad_key_ptr = std::make_shared<base::PlatformKadmliaKey>();
    kad_key_ptr->set_xnetwork_id(kRoot);
    ASSERT_EQ(root_manager->AddRoutingTable(
        udp_transport, config, kad_key_ptr), kKadSuccess);
    std::shared_ptr<RoutingTable> root_table = root_manager->GetRoutingTable(kRoot);
    ASSERT_TRUE(root_table != nullptr);

    std::vector<NodeInfoPtr> nodes;
    int ret = root_manager->GetRootNodes(kRoot, nodes);
    if (ret != kKadSuccess) {
        SleepUs(10 * 1000 * 1000);
        ASSERT_EQ(root_manager->GetRootNodes(kRoot, nodes), kKadSuccess);
        ASSERT_TRUE(!nodes.empty());
    } else {
        ASSERT_TRUE(!nodes.empty());
    }

    std::set<std::pair<std::string, uint16_t>> boot_endpoints;
    ASSERT_EQ(root_manager->GetBootstrapRootNetwork(kRoot, boot_endpoints), kKadSuccess);
    ASSERT_TRUE(!boot_endpoints.empty());

    kad_key_ptr->set_xnetwork_id(kEdgeTopStorage);
    ASSERT_EQ(root_manager->AddRoutingTable(
        udp_transport, config, kad_key_ptr), kKadSuccess);
    std::shared_ptr<RoutingTable> storage_table = root_manager->GetRoutingTable(
            kad_key_ptr->GetServiceType());
    ASSERT_TRUE(storage_table != nullptr);
    kad_key_ptr->set_xnetwork_id(kEdgeTopMessage);
    ASSERT_EQ(root_manager->AddRoutingTable(
        udp_transport, config, kad_key_ptr), kKadSuccess);
    std::shared_ptr<RoutingTable> message_table = root_manager->GetRoutingTable(
            kad_key_ptr->GetServiceType());
    ASSERT_TRUE(message_table != nullptr);
    kad_key_ptr->set_xnetwork_id(kEdgeXVPN);
    ASSERT_EQ(root_manager->AddRoutingTable(
        udp_transport, config, kad_key_ptr), kKadSuccess);
    std::shared_ptr<RoutingTable> vpn_table = root_manager->GetRoutingTable(
            kad_key_ptr->GetServiceType());
    ASSERT_TRUE(vpn_table != nullptr);

    root_manager->RemoveRoutingTable(kRoot);
    root_manager->RemoveRoutingTable(kEdgeTopMessage);
    root_manager->RemoveRoutingTable(kEdgeXVPN);
    ASSERT_FALSE(root_manager->root_routing_map_.empty());
    udp_transport->Stop();
}

}  // namespace test

}  // namespace kadmlia

}  // namespace top
