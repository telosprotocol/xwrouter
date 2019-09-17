// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/multi_routing/small_net_cache.h"

#include <cassert>

#include "xpbase/base/top_log.h"
#include "xpbase/base/top_timer.h"
#include "xpbase/base/kad_key/kadmlia_key.h"
#include "xpbase/base/kad_key/get_kadmlia_key.h"
#include "xpbase/base/xip_parser.h"

namespace top {

namespace wrouter {
static const uint32_t kElectNodesExpirePeriod =  20 * 60 * 1000; // 20 min
static const uint64_t kClearPeriod = 5l * 60ll * 1000ll * 1000ll; // 5 min check timer

SmallNetNodes* SmallNetNodes::Instance() {
    static SmallNetNodes ins;
    return &ins;
}

bool SmallNetNodes::Init() {
    clear_timer_ = std::make_shared<base::TimerRepeated>(base::TimerManager::Instance(), "SmallNetNodes::Clear");
    clear_timer_->Start(
            500ll * 1000ll,
            kClearPeriod,
            std::bind(&SmallNetNodes::do_clear_and_reset, this));
    return true;
}

SmallNetNodes::SmallNetNodes() {
}

SmallNetNodes::~SmallNetNodes() {
    clear_timer_->Join();
    clear_timer_ = nullptr;
}

bool SmallNetNodes::FindNode(const std::string& account, NetNode& Fnode) {
    std::unique_lock<std::mutex> lock(net_nodes_cache_map_mutex_);
    for (auto mitem : net_nodes_cache_map_) {
        for (auto& item : mitem.second) {
            if (item.m_account == account) {
                Fnode = item;
                return true;
            }
        }
    }
    TOP_WARN("findnode of account:%s failed", account.c_str());
    return false;
}

bool SmallNetNodes::FindNode(uint32_t index, NetNode& Fnode, uint64_t service_type) {
    std::unique_lock<std::mutex> lock(net_nodes_cache_map_mutex_);
    auto ifind = net_nodes_cache_map_.find(service_type);
    if (ifind == net_nodes_cache_map_.end()) {
        return false;
    }
    auto size = (ifind->second).size();
    if ( size <= index) {
        TOP_WARN("index:%d beyond vector.size:%d", index, size);
        return false;
    }

    Fnode = (ifind->second)[index];
    TOP_DEBUG("findnode of index:%d account:%s", index, Fnode.m_account.c_str());
    return true;
}

bool SmallNetNodes::FindRandomNode(NetNode& Fnode, uint64_t service_type) {
    std::unique_lock<std::mutex> lock(net_nodes_cache_map_mutex_);
    auto ifind = net_nodes_cache_map_.find(service_type);
    if (ifind == net_nodes_cache_map_.end()) {
        return false;
    }

    auto size = (ifind->second).size();
    if (size  == 0) {
        return false;
    }
    uint32_t index = RandomUint32() % size;
    Fnode = ifind->second[index];
    TOP_DEBUG("findnode of index:%d account:%s", index, Fnode.m_account.c_str());
    return true;
}

bool SmallNetNodes::FindAllNode(std::vector<NetNode>& node_vec ,uint64_t service_type) {
    std::unique_lock<std::mutex> lock(net_nodes_cache_map_mutex_);
    auto ifind = net_nodes_cache_map_.find(service_type);
    if (ifind == net_nodes_cache_map_.end()) {
        return false;
    }
    node_vec = ifind->second;
    return true;
}

uint32_t SmallNetNodes::AddNode(NetNode node) {
    std::unique_lock<std::mutex> lock(net_nodes_cache_map_mutex_);
    base::KadmliaKeyPtr kad_key = GetKadmliaKey(node.m_xip);
    uint64_t service_type = kad_key->GetServiceType();
    net_nodes_cache_map_[service_type].push_back(node);
    TOP_DEBUG("addnode account:%s public_key:%s xip:%s",
            node.m_account.c_str(),
            node.m_public_key.c_str(),
            HexEncode(node.m_xip.xip()).c_str());
    return net_nodes_cache_map_[service_type].size();
}

void SmallNetNodes::do_clear_and_reset() {
    std::unique_lock<std::mutex> lock(net_nodes_cache_map_mutex_);
    auto now = std::chrono::steady_clock::now();
    for (auto& mitem: net_nodes_cache_map_) {
        for (auto iter = (mitem.second).begin(); iter != (mitem.second).end(); ) {
            if (now - std::chrono::milliseconds(kElectNodesExpirePeriod) >  (*iter).time_point) {
                // elect nodes expired
                iter = (mitem.second).erase(iter);
                TOP_INFO("elect node:%s expired from SmallNet", (*iter).m_account.c_str());
            } else {
                ++ iter;
            }
        }
    }
}

} // end namespace wrouter

} // end namespace top
