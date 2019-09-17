// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>
#include <mutex>
#include <map>

#include "xpbase/base/top_config.h"
#include "xpbase/base/top_timer.h"
#include "xkad/routing_table/routing_utils.h"
#include "xkad/routing_table/routing_table.h"
#include "xwrouter/register_routing_table.h"
#include "xkad/proto/kadmlia.pb.h"

namespace top {

namespace wrouter {

class RootRoutingManager;

class MultiRouting {
public:
    static MultiRouting* Instance();
    kadmlia::RoutingTablePtr GetRoutingTable(const uint64_t& type, bool root = false);
    kadmlia::RoutingTablePtr GetRoutingTable(const std::string& routing_id, bool root = false);
private:
    friend void RegisterRoutingTable(
            uint64_t type,
            std::shared_ptr<kadmlia::RoutingTable> routing_table);
    friend void UnregisterRoutingTable(uint64_t type);
    friend void UnregisterAllRoutingTable();
    friend std::shared_ptr<kadmlia::RoutingTable> GetRoutingTable(const uint64_t& type, bool root);
    friend std::shared_ptr<kadmlia::RoutingTable> GetRoutingTable(const std::string& routing_id, bool root);
    friend void SetRootRoutingManager(std::shared_ptr<RootRoutingManager> root_manager_ptr);
    friend void GetAllRegisterType(std::vector<uint64_t>& vec_type);
    friend bool CheckTypeExist(uint64_t type);
    friend std::shared_ptr<kadmlia::RoutingTable> GetSmartRoutingTable(uint64_t type);
    friend uint64_t TryGetSmartRoutingTable(uint64_t type);
    friend bool GetServiceBootstrapRootNetwork(
        uint64_t service_type,
        std::set<std::pair<std::string, uint16_t>>& boot_endpoints);
    friend bool SetCacheServiceType(uint64_t service_type);
    void AddRoutingTable(uint64_t type, kadmlia::RoutingTablePtr routing_table);
    void RemoveRoutingTable(uint64_t type);
    void RemoveAllRoutingTable();
    void SetRootRoutingManager(std::shared_ptr<RootRoutingManager> root_manager_ptr);
    void GetAllRegisterType(std::vector<uint64_t>& vec_type);
    bool CheckTypeExist(uint64_t type);
    kadmlia::RoutingTablePtr GetServiceRoutingTable(const uint64_t& type);
    kadmlia::RoutingTablePtr GetServiceRoutingTable(const std::string& routing_id);
    kadmlia::RoutingTablePtr GetSmartRoutingTable(uint64_t type);
    uint64_t TryGetSmartRoutingTable(uint64_t type);

    bool GetServiceBootstrapRootNetwork(
        uint64_t service_type,
        std::set<std::pair<std::string, uint16_t>>& boot_endpoints);
    bool SetCacheServiceType(uint64_t service_type);

    // be careful, will change message
    void SendToNetwork(transport::protobuf::RoutingMessage& message, bool add_hop = true);
    // be careful, will not change message
    void SendToNetwork(const transport::protobuf::RoutingMessage& message, bool add_hop = true);
    void CheckSingleNodeNetwork();

    MultiRouting();
    ~MultiRouting();

    std::map<uint64_t, kadmlia::RoutingTablePtr> routing_table_map_;
    std::mutex routing_table_map_mutex_;
    std::shared_ptr<RootRoutingManager> root_manager_ptr_;
    base::TimerRepeated timer_{base::TimerManager::Instance(), "MultiRouting"};

    DISALLOW_COPY_AND_ASSIGN(MultiRouting);
};

}  // namespace wrouter

}  // namespace top
