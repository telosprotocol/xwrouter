// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/message_handler/xwrouter_handler.h"

#include <algorithm>

#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xpbase/base/xip_parser.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/routing_utils.h"
#include "xwrouter/register_routing_table.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xpbase/base/xip_parser.h"
#include "xpbase/base/top_utils.h"
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
#include "xgossip/gossip_interface.h"
#include "xpbase/base/top_log.h"
#include "xbase/xutl.h"
#include "xtransport/message_manager/message_manager_intf.h"

namespace top {

using namespace kadmlia;
using namespace gossip;

namespace wrouter {

WrouterHandler::WrouterHandler(
        transport::TransportPtr transport_ptr,
        std::shared_ptr<gossip::GossipInterface> bloom_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> layered_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> bloom_layer_gossip_ptr,
        std::shared_ptr<gossip::GossipInterface> set_layer_gossip_ptr)
        : transport_ptr_(transport_ptr),
          bloom_gossip_ptr_(bloom_gossip_ptr),
          layered_gossip_ptr_(layered_gossip_ptr),
          bloom_layer_gossip_ptr_(bloom_layer_gossip_ptr),
          set_layer_gossip_ptr_(set_layer_gossip_ptr) {}
 

WrouterHandler::~WrouterHandler() {
    transport_ptr_ = nullptr;
    bloom_gossip_ptr_ = nullptr;
    layered_gossip_ptr_ = nullptr;
    bloom_layer_gossip_ptr_ = nullptr;
    set_layer_gossip_ptr_ = nullptr;
}

kadmlia::RoutingTablePtr WrouterHandler::FindRoutingTable(
        bool is_root,
        uint64_t service_type,
        bool root_backup,
        const std::string msg_des_node_id) {
    // TODO(smaug) GetSmartRoutingTable 
    RoutingTablePtr routing_table = GetRoutingTable(service_type, is_root);
    if (routing_table) {
        return routing_table;
    }
    if (!root_backup) {
        return nullptr;
    }
    
    // using backup, should choose the right root-routing-table
    std::vector<uint64_t> vec_type;
    GetAllRegisterType(vec_type);
    auto tmp_routing_table1 = GetRoutingTable(kRoot, true);
    auto target_routing_table = tmp_routing_table1;
    if (tmp_routing_table1) {
        std::string tmp_id1 = tmp_routing_table1->get_local_node_info()->id();
        for (auto& tmp_service_type : vec_type) {
            auto tmp_routing_table2 = GetRoutingTable(tmp_service_type, true);
            if (!tmp_routing_table2) {
                TOP_WARN2("GetRoutingTable %llu empty", tmp_service_type);
                continue;
            }
            std::string tmp_id2 = tmp_routing_table2->get_local_node_info()->id();
            if (!CloserToTarget(tmp_id1, tmp_id2, msg_des_node_id)) {
                tmp_id1 = tmp_id2;
                tmp_routing_table1 = tmp_routing_table2;
            }
        } // end for
        target_routing_table = tmp_routing_table1;
    }

    if (target_routing_table) {
        return target_routing_table;
    }

    if (vec_type.empty()) {
        return nullptr;
    }
    // no dest routing_table and no root routing_table, choose anyone(usually this is client)
    return GetRoutingTable(vec_type[0], false);
}

std::vector<kadmlia::NodeInfoPtr> WrouterHandler::GetClosestNodes(
        kadmlia::RoutingTablePtr routing_table,
        const std::string& target_id,
        uint32_t number_to_get,
        bool base_xip) {
    if (!routing_table) {
        return {};
    }
    // TODO(smaug) judge node quality good or not good 
    return routing_table->GetClosestNodes(target_id, number_to_get, base_xip);
}

std::vector<kadmlia::NodeInfoPtr> WrouterHandler::GetRandomNodes (
    std::vector<kadmlia::NodeInfoPtr>& neighbors,
    uint32_t number_to_get) const {
    if(neighbors.size() <= number_to_get) {
        return neighbors;
    }
    std::random_shuffle(neighbors.begin(),neighbors.end());
    return std::vector<kadmlia::NodeInfoPtr> {neighbors.begin(),neighbors.begin() + number_to_get};
}

bool WrouterHandler::CloserToTarget(
    const std::string& id1,
    const std::string& id2,
    const std::string& target_id) {
    for (int i = 0; i < top::kNodeIdSize; ++i) {
        unsigned char result1 = id1[i] ^ target_id[i];
        unsigned char result2 = id2[i] ^ target_id[i];
        if (result1 != result2) {
            return result1 < result2;
        }
    }
    return false;
}

} // namespace wrouter 

} // namespace top
