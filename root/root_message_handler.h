// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "xbase/xpacket.h"
#include "xkad/routing_table/routing_utils.h"
#include "xkad/proto/kadmlia.pb.h"
#include "xkad/routing_table/callback_manager.h"

namespace top {

namespace wrouter {

class RootMessageHandler {
public:
    RootMessageHandler();
    ~RootMessageHandler();
    void HandleMessage(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet);

private:

    DISALLOW_COPY_AND_ASSIGN(RootMessageHandler);
};

}  // namespace wrouter

}  // namespace top
