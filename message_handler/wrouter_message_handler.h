// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <map>
#include <array>

#include "xbase/xlog.h"
#include "xbase/xobject.h"
#include "xbase/xthread.h"
#include "xbase/xtimer.h"
#include "xbase/xdata.h"
#include "xbase/xpacket.h"
#include "xbase/xsocket.h"
#include "xbase/xutl.h"

#include "xkad/proto/kadmlia.pb.h"
#include "xwrouter/wrouter_utils/wrouter_utils.h"
#include "xwrouter/register_message_handler.h"
#include "xtransport/message_manager/message_manager_intf.h"
#include "xkad/nat_detect/nat_manager_intf.h"

namespace top {

namespace kadmlia {
    class RoutingTable;
    class ThreadHandler;
}

namespace wrouter {
class Wrouter;


static const int32_t MsgHandlerMaxSize = 4096;
using ArrayHandlers = std::array<transport::HandlerProc, MsgHandlerMaxSize>;
using MapRequestType = std::map<int, int>;

class WrouterMessageHandler {
private:
    friend class Wrouter;
    friend class ThreadHandler;
    friend void WrouterRegisterMessageHandler(int msg_type, transport::HandlerProc handler_proc);
    friend void WrouterUnregisterMessageHandler(int msg_type);

    friend void WrouterRegisterMessageRequestType(int msg_type, int request_type);
    friend void WrouterUnregisterMessageRequestType(int msg_type);
    friend int WrouterGetRequestType(int msg_type);
    friend void WrouterSelfHandleMessage(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    static WrouterMessageHandler* Instance();
    void HandleMessage(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    void HandleSyncMessage(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void AddHandler(int msg_type, transport::HandlerProc handler_proc);
    void AddRequestType(int msg_type, int request_type);
    //bool FindHandler(int msg_type, HandlerProc& handler_proc) const;
    int GetRequestType(int msg_type);
    void RemoveHandler(int msg_type);
    void RemoveRequestType(int msg_type);
    int SendData(
            const transport::protobuf::RoutingMessage& message,
            const std::string& peer_ip,
            uint16_t peer_port);

    WrouterMessageHandler();
    ~WrouterMessageHandler();
    void AddBaseHandlers();

    void CheckBitVPNClientMessage(transport::protobuf::RoutingMessage& message);
    void CheckNatDetectMessage(transport::protobuf::RoutingMessage& message);
    int HandleClientMessage(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    int HandleMultiRelayMessage(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    bool CheckMultiRelay(transport::protobuf::RoutingMessage& message);
    std::shared_ptr<kadmlia::RoutingTable> MultiRelayGetSmartRoutingTable(
            transport::protobuf::RoutingMessage& message);
    int HandleMultiRelayMessageSpearHead(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    int CheckRelayMsgToNextEdgeNetwork(transport::protobuf::RoutingMessage& message);
    void RelayMsgToNextEdgeNetwork(transport::protobuf::RoutingMessage& message);
    void RelayMsgToNextServiceNetwork(
            transport::protobuf::RoutingMessage& message,
            std::shared_ptr<kadmlia::RoutingTable> routing_table);

    void SendMultiRelayResponse(transport::protobuf::RoutingMessage& message);
    int HandleMultiRelayRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    void CallbackMultiRelayResponse(transport::protobuf::RoutingMessage& message);
    int HandleMultiRelayResponse(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    void PrintRelayHopInfo(transport::protobuf::RoutingMessage& message);
    void PrintTraceRoute(transport::protobuf::RoutingMessage& message);

    void HandleConnectRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleHandshake(transport::protobuf::RoutingMessage& message, base::xpacket_t& packet);
    void HandleBootstrapJoinRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleBootstrapJoinResponse(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleFindNodesRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleFindNodesResponse(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void SendAck(
            transport::protobuf::RoutingMessage& message, 
            base::xpacket_t& packet);
    void HandleHeartbeatRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleHeartbeatResponse(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleNodeQuit(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    // test multi relay message
    void HandleTestMultiRelayRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleTestMultiRelayResponse(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleBroadcastFromMultiChannelRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleBroadcastFromMultiChannelAck(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);
    void HandleSendToFromRandomNeighborsRequest(
            transport::protobuf::RoutingMessage& message,
            base::xpacket_t& packet);

    ArrayHandlers array_handlers_;
    std::mutex map_request_type_mutex_;
    std::map<int, int> map_request_type_;
    transport::MessageManagerIntf* message_manager_{transport::MessageManagerIntf::Instance()};
    kadmlia::NatManagerIntf* nat_manager_{kadmlia::NatManagerIntf::Instance()};
};

typedef std::shared_ptr<WrouterMessageHandler> MessageHandlerPtr;

}  // namespace wrouter

}  // namespace top
