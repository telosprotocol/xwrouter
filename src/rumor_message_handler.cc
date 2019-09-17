// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/message_handler/rumor_message_handler.h"

#include "xkad/gossip/rumor_handler.h"
#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xkad/routing_table/local_node_info.h"
#include "xkad/gossip/rumor_def.h"
#include "xtransport/message_manager/message_manager_intf.h"

namespace top {
namespace gossip {

RumorMessageHandler* RumorMessageHandler::Instance() {
    static RumorMessageHandler ins;
    return &ins;
}

void RumorMessageHandler::AddHandle(uint32_t message_type, transport::HandlerProc proc) {
    if (HaveKey(message_type)) {
        TOP_WARN("RumorMessageHandler::AddHandle Failed.Already HaveKey.Message Type:%d", 
            message_type);
        return;
    }
    wrouter::WrouterRegisterMessageHandler(
        message_type,
        std::bind(
            &RumorMessageHandler::HandleMessage,
            this, std::placeholders::_1,
            std::placeholders::_2));
    if (!AddData(message_type, proc)) {
        TOP_WARN("RumorMessageHandler::AddHandle Failed.AddData Failed.Message Type:%d", 
            message_type);
        return;
    }
}

void RumorMessageHandler::RemoveHandle(int32_t message_type) {
    if (!HaveKey(message_type)) {
        TOP_WARN("RumorMessageHandler::RemoveHandle Failed.Do not HaveKey.Message Type:%d",
            message_type);
        return;
    }
    message_manager_->UnRegisterMessageProcessor(message_type);
    DeleteKey(message_type);
}

void RumorMessageHandler::SetMaxHopNum(
    const int32_t hop_num) {
    max_hop_num_ = hop_num;
}

bool RumorMessageHandler::CheckMessage(
        int32_t message_type,
        const transport::protobuf::RoutingMessage& in_message) const {
    transport::protobuf::RoutingMessage message = in_message;
    if (message_type != message.type()) {
        TOP_WARN("RumorMessageHandler::CheckMessage Failed.Message Type Is Not Equal:%d-%d", 
            message_type, message.type());
        return false;
    }
    if (RumorFilter::Instance()->FiltMessage(message)) {
        TOP_WARN("RumorFilter::FiltMessageFailed.Message Type Is :%d", 
            message_type);
        return false;
    }
    int32_t hop_num = message.hop_num();
    if(IsHopExpired(hop_num)) {
        TOP_WARN("Hop[%d] Is Experied.", 
            message.hop_num());
        return false;
    }
    return true;
}

bool RumorMessageHandler::IsHopExpired(
    const int32_t hop_num) const {
    return hop_num > max_hop_num_;
}

void RumorMessageHandler::HandleMessage(
    transport::protobuf::RoutingMessage& message,
    base::xpacket_t& packet) {
    transport::HandlerProc proc;
    if (!FindData(message.type(), proc)) {
        TOP_WARN("RumorMessageHandler::HandleMessage Failed."
            "Message Type[%d] does not has its proc", message.type());
        return;
    }
    std::cout << "RumorMessageHandler::HandleMessage called." << std::endl;

    if (!CheckMessage(message.type(), message)) {
        TOP_WARN("RumorMessageHandler::HandleMessage Failed.Message Type Is %d", message.type());
        return;
    }
    proc(message, packet);
}
}
}
