// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "xkad/proto/kadmlia.pb.h"
#include "xkad/routing_table/routing_utils.h"
#include "xbase/xpacket.h"
#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xwrouter/root/root_routing.h"

namespace top {

namespace kadmlia {
class RoutingTable;
class LocalNodeInfo;
class CallbackManager;
struct NodeInfo;
    
typedef std::shared_ptr<NodeInfo> NodeInfoPtr;
}

namespace transport {
class UdpTransport;
}

namespace wrouter {

class RootRoutingManager;

void RegisterRoutingTable(uint64_t type, std::shared_ptr<kadmlia::RoutingTable> routing_table);
void UnregisterRoutingTable(uint64_t type);
void UnregisterAllRoutingTable();
std::shared_ptr<kadmlia::RoutingTable> GetRoutingTable(const uint64_t& type, bool root = false);
std::shared_ptr<kadmlia::RoutingTable> GetRoutingTable(const std::string& routing_id, bool root = false);
void SetRootRoutingManager(std::shared_ptr<RootRoutingManager> root_manager_ptr);
void GetAllRegisterType(std::vector<uint64_t>& vec_type);
bool CheckTypeExist(uint64_t type);
std::shared_ptr<kadmlia::RoutingTable> GetSmartRoutingTable(uint64_t type);
uint64_t TryGetSmartRoutingTable(uint64_t type);
bool SetCacheServiceType(uint64_t service_type);
bool GetServiceBootstrapRootNetwork(
        uint64_t service_type,
        std::set<std::pair<std::string, uint16_t>>& boot_endpoints);

int NetworkExists(
        base::KadmliaKeyPtr& kad_key_ptr,
        std::set<std::pair<std::string, uint16_t>>& endpoints);
int GetSameNetworkPublicEndpoints(
        base::KadmliaKeyPtr& kad_key_ptr,
        std::set<std::pair<std::string, uint16_t>>& boot_endpoints);
int GetSameNetworkNodes(
        base::KadmliaKeyPtr& kad_key_ptr,
        std::vector<kadmlia::NodeInfoPtr>& ret_nodes);

}  // namespace wrouter

}  // namespace top
