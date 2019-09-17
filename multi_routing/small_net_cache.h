// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <vector>
#include <string>
#include <chrono>
#include <unordered_map>

#include "xpbase/base/xip_parser.h"
#include "xpbase/base/top_timer.h"


namespace top {

namespace wrouter {

typedef struct NetNode {
    std::string m_account;
    std::string m_public_key;
    base::XipParser m_xip;
    std::chrono::steady_clock::time_point time_point;
} NetNode;

class SmallNetNodes {
public:
    static SmallNetNodes* Instance();
    bool Init();

    uint32_t AddNode(NetNode node);
    bool FindNode(const std::string& account, NetNode& Fnode);
    bool FindNode(uint32_t index, NetNode& Fnode, uint64_t service_type);
    bool FindRandomNode(NetNode& Fnode, uint64_t service_type);
    bool FindAllNode(std::vector<NetNode>& node_vec, uint64_t service_type);
    void do_clear_and_reset();

private:
    SmallNetNodes();
    ~SmallNetNodes();

private:
    std::mutex net_nodes_cache_map_mutex_;
    // key is service_type
    std::unordered_map<uint64_t, std::vector<NetNode>> net_nodes_cache_map_;
    std::shared_ptr<base::TimerRepeated> clear_timer_{nullptr};
};

}

}
