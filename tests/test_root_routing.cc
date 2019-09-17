// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>

#include <string>

#include <gtest/gtest.h>

#include "xpbase/base/endpoint_util.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#define protected public
#define private public
#include "xtransport/udp_transport/udp_transport.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/local_node_info.h"
#include "xwrouter/register_routing_table.h"
#include "xwrouter/root/root_routing.h"
#include "xwrouter/root/root_routing_manager.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xtransport/message_manager/multi_message_handler.h"
#include "xkad/nat_detect/nat_manager_intf.h"

namespace top {

namespace kadmlia {

namespace test {

class TestRootRouting : public testing::Test {
public:
	static void SetUpTestCase() {
	}

	static void TearDownTestCase() {
	}

	virtual void SetUp() {
        base::Config config;
        ASSERT_TRUE(config.Init("./conf.ut/test_root.conf"));
        std::string local_ip;
        ASSERT_TRUE(config.Get("node", "local_ip", local_ip));
        uint16_t local_port = 0;
        ASSERT_TRUE(config.Get("node", "local_port", local_port));
        udp_transport_.reset(new top::transport::UdpTransport());
        thread_message_handler_ = std::make_shared<transport::MultiThreadHandler>();
        thread_message_handler_->Init();
        ASSERT_TRUE(udp_transport_->Start(
                local_ip,
                local_port,
                thread_message_handler_.get()) == kKadSuccess);
	}

	virtual void TearDown() {
        ASSERT_TRUE(udp_transport_);
        udp_transport_->Stop();
	}

    top::transport::UdpTransportPtr udp_transport_;
    std::shared_ptr<transport::MultiThreadHandler> thread_message_handler_;
};

TEST_F(TestRootRouting, IsDestination) {
    wrouter::WrouterMessageHandler message_handler;
    std::shared_ptr<wrouter::RootRoutingManager> root_manager;
    root_manager.reset(new wrouter::RootRoutingManager());
    wrouter::SetRootRoutingManager(root_manager);
    base::Config config;
    ASSERT_TRUE(config.Init("./conf.ut/test_root.conf"));
    auto kad_key_ptr = std::make_shared<base::PlatformKadmliaKey>();
    kadmlia::NatManagerIntf::Instance()->SetNatType(kNatTypePublic);
    auto local_ptr = CreateLocalInfoFromConfig(config, kad_key_ptr);
    std::shared_ptr<RoutingTable> routing_table_ptr;
    routing_table_ptr.reset(new wrouter::RootRouting(udp_transport_, local_ptr));
    local_ptr->set_service_type(kRoot);
    ASSERT_TRUE(routing_table_ptr->Init());
    routing_table_ptr->bootstrap_cache_helper_->Stop();
    std::set<std::pair<std::string, uint16_t>> public_endpoints_all;
    std::set<std::pair<std::string, uint16_t>> public_endpoints_config;
    std::string public_endpoints;
    ASSERT_TRUE(config.Get("node", "public_endpoints", public_endpoints));
    top::base::ParseEndpoints(public_endpoints, public_endpoints_config);
    base::MergeEndpoints(public_endpoints_config, public_endpoints_all);
    ASSERT_FALSE(public_endpoints_all.empty());
    root_manager->root_routing_map_[kRoot] = routing_table_ptr;
    ASSERT_EQ(routing_table_ptr->MultiJoin(public_endpoints_all), kKadSuccess);
    ASSERT_FALSE(routing_table_ptr->IsDestination("DDD", false));
    ASSERT_FALSE(routing_table_ptr->IsDestination("DDD", true));
    wrouter::SetRootRoutingManager(nullptr);
}

}  // namespace test

}  // namespace kadmlia

}  // namespace top
