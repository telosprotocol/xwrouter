// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "xpbase/base/top_config.h"
#include "xpbase/base/top_utils.h"
#include "xkad/routing_table/routing_table.h"
#include "xtransport/transport.h"
#include "xwrouter/root/root_message_handler.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"
#include "xwrouter/wrouter_utils/wrouter_base_routing.h"

namespace top {

namespace kadmlia {
class RoutingTable;
typedef std::shared_ptr<RoutingTable> RoutingTablePtr;
};

namespace wrouter {

enum RootMessageType {
    kGetNodesRequest = 1,
    kGetNodesResponse = 2,
};


class RootRouting : public wrouter::WrouterBaseRouting {
public:
    RootRouting(std::shared_ptr<transport::Transport>, kadmlia::LocalNodeInfoPtr);
    virtual ~RootRouting() override;
    virtual bool Init() override;
    virtual bool UnInit() override;
    virtual void HandleMessage(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet) override;
    virtual int AddNode(kadmlia::NodeInfoPtr node) override;
    virtual int DropNode(kadmlia::NodeInfoPtr node) override;
    virtual void SetFreqMessage(transport::protobuf::RoutingMessage& message) override;
    int GetRootNodes(uint64_t sevice_type, std::vector<kadmlia::NodeInfoPtr>& root_nodes);
    int GetRootNodes(const std::string& des_id, std::vector<kadmlia::NodeInfoPtr>& root_nodes);
    void AddNetworkRootId(const std::string& root_id);
    void RemoveNetworkRootId(const std::string& root_id);
    bool ContainRootId(const std::string& id);
    // add target service_type to be cached
    bool SetCacheServiceType(uint64_t service_type);
    // get cache nodes of service_type give
    bool GetCacheServicePublicNodes(
            uint64_t service_type,
            std::set<std::pair<std::string, uint16_t>>& boot_endpoints);
    kadmlia::RoutingTablePtr FindRoutingTable(const std::string& msg_des_node_id);
    bool GetRootNodesFromLocalRootRouting(
            kadmlia::RoutingTablePtr root_routing,
            const std::string& node_id,
            std::vector<kadmlia::NodeInfoPtr>& nodes);
    bool GetRootNodesFromLocal(const std::string& node_id, std::vector<kadmlia::NodeInfoPtr>& nodes);

protected:
    virtual bool NewNodeReplaceOldNode(kadmlia::NodeInfoPtr node, bool remove);

private:
    virtual int Bootstrap(
            const std::string& peer_ip,
            uint16_t peer_port,
            uint64_t des_service_type) override;
    void HandleRootGetNodesRequest(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet);
    void HandleRootGetNodesResponse(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet);
    virtual bool StartBootstrapCacheSaver() override;

    static RootMessageHandler root_message_handler_;
    std::set<std::string> root_id_set_;
    std::mutex root_id_set_mutex_;

    DISALLOW_COPY_AND_ASSIGN(RootRouting);
};

}  // namespace wrouter

}  // namespace top
