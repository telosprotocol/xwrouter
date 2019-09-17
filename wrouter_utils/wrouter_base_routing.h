// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once


#pragma once

#include <vector>
#include <string>
#include <memory>
#include <thread>

#include "xpbase/base/top_utils.h"
#include "xpbase/base/top_config.h"
#include "xkad/routing_table/routing_table.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"

namespace top {

namespace wrouter {

class WrouterBaseRouting : public kadmlia::RoutingTable {
public:
   WrouterBaseRouting(
           std::shared_ptr<transport::Transport> transport,
           uint32_t kad_key_size,
           kadmlia::LocalNodeInfoPtr local_node_ptr)
           : kadmlia::RoutingTable(transport, kad_key_size, local_node_ptr) {}
    virtual ~WrouterBaseRouting() {}

protected:
    DISALLOW_COPY_AND_ASSIGN(WrouterBaseRouting);
};

}  // namespace wrouter

}  // namespace top
