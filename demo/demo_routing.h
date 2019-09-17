// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "xpbase/base/top_config.h"
#include "xpbase/base/top_utils.h"
#include "xpbase/base/xip_parser.h"
#include "xpbase/base/top_timer.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/node_info.h"
#include "xwrouter/root/root_message_handler.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"
#include "xwrouter/wrouter_utils/wrouter_base_routing.h"

namespace top {

class DemoRouting : public wrouter::WrouterBaseRouting {
public:
    DemoRouting(
            std::shared_ptr<transport::Transport> transport,
            kadmlia::LocalNodeInfoPtr local_node_ptr,
            const uint32_t RoutingMaxNodesSize);
    virtual ~DemoRouting() override;

protected:
    virtual bool NewNodeReplaceOldNode(kadmlia::NodeInfoPtr node, bool remove) override;
    virtual uint32_t GetFindNodesMaxSize() override;
private:
    uint32_t RoutingMaxNodesSize_ {128};
};


DemoRouting::DemoRouting(
        std::shared_ptr<transport::Transport> transport,
        kadmlia::LocalNodeInfoPtr local_node_ptr,
        const uint32_t RoutingMaxNodesSize)
        : RoutingMaxNodesSize_(RoutingMaxNodesSize),
        wrouter::WrouterBaseRouting(transport, kNodeIdSize, local_node_ptr) {}

DemoRouting::~DemoRouting() {}

bool DemoRouting::NewNodeReplaceOldNode(top::kadmlia::NodeInfoPtr node, bool remove) {
    const auto max_count = RoutingMaxNodesSize_;
    // const auto max_count = 16;  // for test
    if (nodes_.size() < max_count) {
        return true;
    }

    std::map<uint32_t, unsigned int> bucket_rank_map;
    unsigned int max_bucket(-1), max_bucket_count(0);
    std::for_each(
            std::begin(nodes_),
            std::end(nodes_),
        [&bucket_rank_map, &max_bucket, &max_bucket_count, node](const top::kadmlia::NodeInfoPtr & node_info) {
            bucket_rank_map[node_info->bucket_index] += 1;

            if (bucket_rank_map[node_info->bucket_index] >= max_bucket_count) {
                max_bucket = node_info->bucket_index;
                max_bucket_count = bucket_rank_map[node_info->bucket_index];
            }
    });

    // not satisfy replacing
    // if (max_bucket_count <= kKadParamK) {
    //     // first node in empty k-bucket, add directly
    //     if (bucket_rank_map[node->bucket_index] < kKadParamK) {
    //         TOP_DEBUG_NAME("");
    //         return true;
    //     }

    //     // no replace
    //     TOP_DEBUG_NAME("");
    //     return false;
    // }

    // dump all nodes
    // {
    //     std::string fmt("all nodes:\n");
    //     for (int i = 0; i < nodes_.size(); ++i) {
    //         // fmt += base::StringUtil::str_fmt("%d: count(%d)\n", kv.first, kv.second);
    //         fmt += base::StringUtil::str_fmt("%3d]: %s, %s:%d, dis(%d)\n", (int)i, HexSubstr(nodes_[i]->node_id).c_str(),
    //                 nodes_[i]->public_ip.c_str(), (int)nodes_[i]->public_port, nodes_[i]->bucket_index);
    //     }
    //     TOP_DEBUG_NAME("%s", fmt.c_str());
    // }

    // replace node
    for (auto it(nodes_.rbegin()); it != nodes_.rend(); ++it) {
        if (static_cast<unsigned int>((*it)->bucket_index) != max_bucket ||
                node->bucket_index == (*it)->bucket_index) {
            continue;
        }

        const bool very_less = bucket_rank_map[node->bucket_index] < bucket_rank_map[(*it)->bucket_index] - 1;
        const bool less_and_closer = bucket_rank_map[node->bucket_index] < bucket_rank_map[(*it)->bucket_index]
                && node->bucket_index < (*it)->bucket_index;
        const bool empty_and_closer = bucket_rank_map[node->bucket_index] == 0
                && node->bucket_index < (*it)->bucket_index;
        if (very_less || less_and_closer || empty_and_closer) {
            if (!remove) {
                return true;
            }
            {
                std::unique_lock<std::mutex> set_lock(node_id_map_mutex_);
                auto id_map_iter = node_id_map_.find((*it)->node_id);
                if (id_map_iter != node_id_map_.end()) {
                    node_id_map_.erase(id_map_iter);
                }
            }
            nodes_.erase(--(it.base()));
            {
                std::unique_lock<std::mutex> lock_hash(node_hash_map_mutex_);
                auto hash_iter = node_hash_map_->find((*it)->hash64);
                if (hash_iter != node_hash_map_->end()) {
                    node_hash_map_->erase(hash_iter);
                }
            }
            return true;
        } // end if (replace...
    } // end for

    return false;

}

uint32_t DemoRouting::GetFindNodesMaxSize() {
    return RoutingMaxNodesSize_;
}
}
