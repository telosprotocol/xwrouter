// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/root/root_message_handler.h"

#include "xpbase/base/top_log.h"
#include "xkad/routing_table/routing_table.h"
#include "xwrouter/register_routing_table.h"
#include "xwrouter/register_message_handler.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"

namespace top {

namespace wrouter {

RootMessageHandler::RootMessageHandler() {
    WrouterRegisterMessageHandler(kRootMessage, [this](
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet) {
        HandleMessage(message, packet);
    });
}

RootMessageHandler::~RootMessageHandler() {
    WrouterUnregisterMessageHandler(kRootMessage);
}

void RootMessageHandler::HandleMessage(
        transport::protobuf::RoutingMessage& message,
        base::xpacket_t& packet) {
    auto routing_table = GetRoutingTable(
            message.des_service_type(),
            message.has_is_root() && message.is_root());
    if (!routing_table) {
        TOP_ERROR("service type[%llu] has not register routing table.",
                message.des_service_type());
        return;
    }
    routing_table->HandleMessage(message, packet);
}

}  // namespace wrouter

}  // namespace top
