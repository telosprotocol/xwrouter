// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "xwrouter/register_message_handler.h"

#include "xwrouter/message_handler/wrouter_message_handler.h"
#include "xwrouter/message_handler/rumor_message_handler.h"

namespace top {

namespace wrouter {

void WrouterRegisterMessageHandler(int msg_type, transport::HandlerProc handler_proc) {
    WrouterMessageHandler::Instance()->AddHandler(msg_type, handler_proc);
}

void WrouterUnregisterMessageHandler(int msg_type) {
    WrouterMessageHandler::Instance()->RemoveHandler(msg_type);
}

void WrouterRegisterMessageRequestType(int msg_type, int request_type) {
    WrouterMessageHandler::Instance()->AddRequestType(msg_type, request_type);
}

void WrouterUnregisterMessageRequestType(int msg_type) {
    WrouterMessageHandler::Instance()->RemoveRequestType(msg_type);
}

int WrouterGetRequestType(int msg_type) {
    return WrouterMessageHandler::Instance()->GetRequestType(msg_type);
}

void WrouterSelfHandleMessage(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet) {
    return WrouterMessageHandler::Instance()->HandleMessage(message, packet);
}

}  // namespace wrouter

}  // namespace top
