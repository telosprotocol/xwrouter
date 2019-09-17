// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <map>
#include <set>
#include <memory>
#include <mutex>

#include "xpbase/base/top_utils.h"
#include "xpbase/base/top_config.h"
#include "xpbase/base/kad_key/kadmlia_key.h"
#include "xkad/routing_table/node_info.h"

namespace top {

namespace kadmlia {
    class RoutingTable;
}

namespace transport {
    class Transport;
}

namespace wrouter {

class RootRoutingManager {
public:
    RootRoutingManager();
    ~RootRoutingManager();
    int AddRoutingTable(
            std::shared_ptr<transport::Transport> transport,
            const base::Config& config,
            base::KadmliaKeyPtr kad_key_ptr,
            bool wait_for_joined = true);
    void RemoveRoutingTable(uint64_t service_type);
    void RemoveAllRoutingTable();
    std::shared_ptr<kadmlia::RoutingTable> GetRoutingTable(uint64_t service_type);
    std::shared_ptr<kadmlia::RoutingTable> GetRoutingTable(const std::string& routing_id);
    int GetRootNodes(uint32_t network_id, std::vector<kadmlia::NodeInfoPtr>& root_nodes);
    int GetRootNodes(
            const std::string& des_id,
            std::vector<kadmlia::NodeInfoPtr>& root_nodes);
    int GetRootBootstrapCache(
            std::set<std::pair<std::string, uint16_t>>& boot_endpoints);
    int GetBootstrapRootNetwork(
            uint64_t service_type,
            std::set<std::pair<std::string, uint16_t>>& boot_endpoints);

    bool GetServiceBootstrapRootNetwork(
            uint64_t service_type,
            std::set<std::pair<std::string, uint16_t>>& boot_endpoints);
    bool SetCacheServiceType(uint64_t service_type);

private:
    int CreateRoutingTable(
            std::shared_ptr<transport::Transport> transport,
            const base::Config& config,
            base::KadmliaKeyPtr kad_key_ptr,
            bool wait_for_joined);

private:
    std::map<uint64_t, std::shared_ptr<kadmlia::RoutingTable>> root_routing_map_;
    std::mutex root_routing_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(RootRoutingManager);
};

}  // namespace wrouter

}  // namespace top
