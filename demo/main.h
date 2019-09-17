// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <signal.h>
#include <iostream>
#include <thread>  // NOLINT

#include "xpbase/base/line_parser.h"
#include "xpbase/base/top_utils.h"
#include "xpbase/base/top_timer.h"
#include "xpbase/base/top_log.h"
#include "xpbase/base/args_parser.h"
#include "xpbase/base/top_config.h"
#include "xpbase/base/check_cast.h"
#include "xpbase/base/endpoint_util.h"
#include "xpbase/base/kad_key/platform_kadmlia_key.h"
#include "xpbase/base/redis_client.h"
#include "xtransport/udp_transport/udp_transport.h"
#include "xkad/routing_table/routing_table.h"
#include "xkad/routing_table/routing_utils.h"
#include "commands.h"
#include "xkad/routing_table/local_node_info.h"
#include "xwrouter/register_routing_table.h"
#include "xwrouter/root/root_routing_manager.h"
#include "xwrouter/multi_routing/small_net_cache.h"
#include "xwrouter/root/root_routing.h"
#include "xtransport/message_manager/multi_message_handler.h"
#include "xkad/nat_detect/nat_manager_intf.h"
#include "xwrouter/xwrouter.h"
#include "cpp_redis/core/client.hpp"
#include "xgossip/include/block_sync_manager.h"
#include "xtransport/udp_config.h"
#include "xstobject/xledger_db.h"
#include "xwrouter/multi_routing/small_net_cache.h"
#include "demo_routing.h"

namespace top {

static const std::string kKadmliaKeyDbKey = "KADMLIA_KEY_DB_KEY";

/*
int KadKey_GetFromDb(
        base::KadmliaKeyPtr& kadkey,
        std::shared_ptr<top::ledger::xledger_face_t> db_face,
        const std::string& db_field);

int KadKey_StoreInDb(
        base::KadmliaKeyPtr& kadkey,
        std::shared_ptr<top::ledger::xledger_face_t> db_face,
        const std::string& db_field);
        */

}  // namespace top
