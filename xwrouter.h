// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "xkad/routing_table/callback_manager.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"
#include "xbase/xbase.h"
#include "xbase/xrouter.h"
#include "xgossip/include/broadcast_layered.h"
#include "xgossip/gossip_interface.h"
#include "xwrouter/message_handler/xwrouter_handler.h"

namespace top {

namespace transport {
class MultiThreadHandler;
class Transport;
typedef std::shared_ptr<Transport> TransportPtr;

namespace protobuf {
class RoutingMessage;
};
};

namespace kadmlia {
class RoutingTable;
struct NodeInfo;
typedef std::shared_ptr<RoutingTable> RoutingTablePtr;
typedef std::shared_ptr<NodeInfo> NodeInfoPtr;
};

namespace wrouter {

using Xip2Header = _xip2_header;

using on_receive_own_callback_t =
    std::function<void(transport::protobuf::RoutingMessage& message, base::xpacket_t&)>;

class Wrouter {
public:
    static Wrouter* Instance();
    void Init(
            base::xcontext_t& context,
            const uint32_t thread_id,
            transport::TransportPtr transport_ptr,
            const uint32_t max_broadcast_num);
    int32_t send(base::xpacket_t& packet);
    int32_t send(transport::protobuf::RoutingMessage& message);
    int32_t SendToLocal(transport::protobuf::RoutingMessage& message);
    int32_t SendDirect(
            transport::protobuf::RoutingMessage& message,
            const std::string& ip,
            uint16_t port);
    virtual int32_t recv(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    std::vector<std::string> GetAllLocalIds();
    std::vector<std::string> GetAllLocalXips();
    void SupportRandomPattern();
    void register_on_receive_own_callback(on_receive_own_callback_t callback);
    void unregister_on_receive_own_callback();
    Xip2Header* ParserXip2Header(base::xpacket_t& packet);
    bool BroadcastByMultiRandomKadKey(
            const transport::protobuf::RoutingMessage& message,
            kadmlia::ResponseFunctor call_back,
            int64_t recursive_count = kRecursiveCount);

    int32_t HandleOwnSyncPacket(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet);
private:
    Wrouter();
    ~Wrouter();

    int32_t HandleOwnPacket(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet);
    int32_t HandleOwnPacket(base::xpacket_t& packet);
private:
    std::mutex callback_mutex_;
    on_receive_own_callback_t callback_;
    uint32_t max_broadcast_num_;

    std::shared_ptr<WrouterHandler> wxid_handler_;
    std::shared_ptr<WrouterHandler> wxip_handler_;
    DISALLOW_COPY_AND_ASSIGN(Wrouter);
};

} // namespace wrouter 

} // namespace top
