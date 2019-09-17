// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#include <memory>
#include <atomic>

#include "xwrouter/register_message_handler.h"
#include "xkad/routing_table/routing_utils.h"
#include "xtransport/transport_message_register.h"
#include "xpbase/base/manager_template.h"
#include "xkad/gossip/rumor_def.h"
#include "xkad/gossip/rumor_filter.h"

namespace top {
namespace gossip {

class RumorMessageHandler : public ManagerTemplate<uint32_t, transport::HandlerProc> {
public:
    static RumorMessageHandler* Instance();
    void AddHandle(uint32_t message_type, transport::HandlerProc proc);
    void RemoveHandle(int32_t message_type);
    void SetMaxHopNum(const int32_t);
private:
    RumorMessageHandler() :
        max_hop_num_(kDefautHopCount) {}
    ~RumorMessageHandler() {}
    bool CheckMessage(
        int32_t,
        const transport::protobuf::RoutingMessage&) const;
    bool IsHopExpired(
        const int32_t) const;
    void HandleMessage(
        transport::protobuf::RoutingMessage&,
        base::xpacket_t&);
    std::atomic<int32_t> max_hop_num_;
    transport::MessageManagerIntf* message_manager_{transport::MessageManagerIntf::Instance()};
};
typedef std::shared_ptr<RumorMessageHandler> RumorMessageHandlerSptr;
}
}
