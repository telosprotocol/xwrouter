// Copyright (c) 2017-2019 Telos Foundation & contributors
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"

#include <atomic>

#ifdef USE_REDIS
#undef USE_REDIS
#endif

namespace top {

std::shared_ptr<base::KadmliaKey> global_xid;
uint32_t gloabl_platform_type = kPlatform;
std::string global_node_id = RandomString(256);
std::string global_node_id_hash("");
static const char* kConfigFile = "./conf/demo.conf";
static const std::string kKadmliaKeyField("kad_key_");
std::atomic<uint32_t> global_xnetwork_id(10);  // larger than 1 
static uint32_t global_zone_id = 0;
static std::string global_local_ip;

void SignalCatch(int sig_no) {
    if (SIGTERM == sig_no || SIGINT == sig_no) {
        printf(" click [Enter] to exit.");
        fflush(stdout);
        ::_Exit(0);
        top::TopCommands::Instance()->Destroy();
        TOP_INFO("node now existing!");
        // do not delete ,just for debug can be quick when terminate
    }
}

int ParseParams(int argc, char** argv, top::ArgsParser& args_parser) {  // NOLINT
    args_parser.AddArgType('h', "help", top::kNoValue);
    args_parser.AddArgType('g', "show_cmd", top::kMaybeValue);
    args_parser.AddArgType('p', "peer", top::kMaybeValue);
    args_parser.AddArgType('i', "identity_index", top::kMaybeValue);
    args_parser.AddArgType('l', "local_port", top::kMaybeValue);
    args_parser.AddArgType('a', "local_ip", top::kMaybeValue);
    args_parser.AddArgType('o', "country_code", top::kMaybeValue);
    args_parser.AddArgType('u', "business", top::kMaybeValue);
    args_parser.AddArgType('c', "config_path", top::kMaybeValue);
    args_parser.AddArgType('d', "db_path", top::kMaybeValue);
    args_parser.AddArgType('L', "log_path", top::kMaybeValue);
    args_parser.AddArgType('t', "test", top::kMaybeValue);
    args_parser.AddArgType('s', "service_list", top::kMaybeValue);
    args_parser.AddArgType('v', "version", top::kNoValue);
    args_parser.AddArgType('x', "mod_xid", top::kMaybeValue);

    std::string tmp_params = "";
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i]) == 0) {
            tmp_params += static_cast<char>(31);
        } else {
            tmp_params += argv[i];
        }
        tmp_params += " ";
    }

    std::string err_pos;
    if (args_parser.Parse(tmp_params, err_pos) != top::kadmlia::kKadSuccess) {
        std::cout << "parse params failed!" << std::endl;
        return top::kadmlia::kKadFailed;
    }

    return top::kadmlia::kKadSuccess;
}

int InitLog(const std::string& log_path, bool log_debug, bool log_off) {
    xinit_log(log_path.c_str(), true, true);
    if (log_off) {
        xset_log_level(enum_xlog_level_error);
        return top::kadmlia::kKadSuccess;
    }

    if (log_debug) {
        xset_log_level(enum_xlog_level_debug);
    } else {
        //xset_log_level(enum_xlog_level_info);
        xset_log_level(enum_xlog_level_warn);
    } 
    return top::kadmlia::kKadSuccess;
}


bool SetLocalDefaultKadKey(base::KadmliaKeyPtr kad_key) {
    kad_key->set_xinterface_id(top::base::GetRandomInt64() % std::numeric_limits<uint32_t>::max());
    kad_key->set_xnetwork_version(check_cast<uint8_t>(0));
    // TODO(smaug) set for kRoleService
    kad_key->set_xaddress_domain_xip(enum_xaddress_domain_xip);
    kad_key->set_xip_type(enum_xip_type_static);
    // for edge , processid,router-id,switch-id,local-id is 0,for server is random value
    kad_key->set_process_id(check_cast<uint8_t>(0));
    kad_key->set_router_id(check_cast<uint8_t>(0));
    kad_key->set_switch_id(check_cast<uint8_t>(0));
    kad_key->set_local_id(check_cast<uint8_t>(0));

    struct in_addr addr;
    if (inet_pton(AF_INET, global_local_ip.c_str(), &addr.s_addr) != 1) {
        return false;
    }
    uint32_t ip_32 = addr.s_addr;
    kad_key->set_cluster_id(ip_32 & 0xFF);
    kad_key->set_group_id(ip_32 >> 8 & 0xFF);
    kad_key->set_node_id((ip_32 >> 16 & 0xFFFF) % 255);
    return true;
}

std::shared_ptr<top::wrouter::RootRoutingManager> CreateRootManager(
        top::transport::UdpTransportPtr udp_transport,
        const top::base::Config& config,
        const std::set<std::pair<std::string, uint16_t>>& public_endpoints_config) {
    TOP_INFO("add root_table ...");
    std::shared_ptr<top::wrouter::RootRoutingManager> root_manager_ptr;
    root_manager_ptr.reset(new top::wrouter::RootRoutingManager());
    SetRootRoutingManager(root_manager_ptr);

    base::KadmliaKeyPtr kad_key_ptr = std::make_shared<base::PlatformKadmliaKey>();
    /*
    if (KadKey_GetFromDb(
            kad_key_ptr,
            top::storage::XLedgerDB::Instance()->InstanceFace(),
            kKadmliaKeyField + "root") != 0) {
            */
        SetLocalDefaultKadKey(kad_key_ptr);
        kad_key_ptr->set_xnetwork_id(kRoot);
        kad_key_ptr->set_zone_id(global_zone_id);
        kad_key_ptr->set_network_type(kRoleService);
        /*
        if (KadKey_StoreInDb(
                kad_key_ptr,
                top::storage::XLedgerDB::Instance()->InstanceFace(),
                kKadmliaKeyField + "root") != 0) {
            TOP_FATAL("save kad key root failed!");
            return nullptr;
        }
    }
    */
    if (root_manager_ptr->AddRoutingTable(
            udp_transport,
            config,
            kad_key_ptr) != top::kadmlia::kKadSuccess) {
        TOP_FATAL("add root_table[root] failed!");
        return nullptr;
    }
    return root_manager_ptr;
}

base::KadmliaKeyPtr CreateKadmliaKey(uint32_t network_id) {
    auto kad_key = base::GetKadmliaKey();
    SetLocalDefaultKadKey(kad_key);
    kad_key->set_xnetwork_id(network_id);
    kad_key->set_zone_id(global_zone_id);  // any
    kad_key->set_network_type(static_cast<uint8_t>(top::kRoleEdge));
    return kad_key;
}

bool RoutingTableJoin(
        bool first_node,
        base::KadmliaKeyPtr& kad_key,
        kadmlia::RoutingTablePtr routing_table_ptr) {
    auto check_rt = top::wrouter::GetRoutingTable(kad_key->GetServiceType());
    if (check_rt) {
        TOP_WARN("UnregisterRoutingTable from p2p_network of network_id:%d service_type:%llu, id:%s",
                kad_key->xnetwork_id(),
                kad_key->GetServiceType(),
                HexEncode(check_rt->get_local_node_info()->id()).c_str());
        top::wrouter::UnregisterRoutingTable(kad_key->GetServiceType());
    }
    top::wrouter::RegisterRoutingTable(kad_key->GetServiceType(), routing_table_ptr);
    if (first_node) {
        return true;
    }

    std::set<std::pair<std::string, uint16_t>> join_endpoints;
    auto ret = wrouter::NetworkExists(kad_key, join_endpoints);
    TOP_INFO("NetworkExists ret:(%d) join_endpoints.size(%d)", ret, join_endpoints.size());
    if (ret != kadmlia::kKadSuccess || join_endpoints.empty()) {
        TOP_INFO("NetworkExists ret: this is first_node");
        auto root_routing = wrouter::GetRoutingTable(kRoot, true);
        routing_table_ptr->get_local_node_info()->set_first_node(true);
        routing_table_ptr->get_local_node_info()->set_public_ip(
            root_routing->get_local_node_info()->public_ip());
        routing_table_ptr->get_local_node_info()->set_public_port(
            root_routing->get_local_node_info()->public_port());
        return true;
    }
    TOP_INFO("NetworkExists ret: this is not first_node");

    if (join_endpoints.empty()) {
        TOP_ERROR("no bootstrap endpoint, join failed");
        return false;
    }

    if (routing_table_ptr->MultiJoin(join_endpoints) != top::kadmlia::kKadSuccess) {
        TOP_ERROR("MultiJoin (%d) failed", kad_key->GetServiceType());
        return false;
    }
    TOP_INFO("RoutingTable join p2p_network success of network_id:%d service_type:%llu id:%s",
            kad_key->xnetwork_id(),
            kad_key->GetServiceType(),
            HexEncode(kad_key->Get()).c_str());
    return true;
}

bool CreateRoutingTable(
        uint32_t inetwork,
        std::shared_ptr<top::wrouter::RootRoutingManager> root_manager_ptr,
        top::transport::UdpTransportPtr udp_transport,
        const top::base::Config& config,
        const std::set<std::pair<std::string, uint16_t>>& public_endpoints_config) {
    TOP_INFO("enter CreateRoutingTable");
    
    bool first_node = false;
    config.Get("node", "first_node", first_node);

    // xnetwork_id increase 1 auto
    auto kad_key = CreateKadmliaKey(inetwork);
    if (!kad_key) {
        TOP_FATAL("create kad_key failed");
        return false;
    }
    kadmlia::LocalNodeInfoPtr local_node_ptr = kadmlia::CreateLocalInfoFromConfig(
            config,
            kad_key);
    if (!local_node_ptr) {
        TOP_FATAL("create local_node_ptr for network_id(%d) failed", kad_key->xnetwork_id());
        return false;
    }

    std::shared_ptr<top::kadmlia::RoutingTable> routing_table_ptr = nullptr;
    //routing_table_ptr.reset(new top::wrouter::WrouterBaseRouting(udp_transport, kNodeIdSize, local_node_ptr));
    routing_table_ptr.reset(new top::DemoRouting(udp_transport, local_node_ptr, 128));
    if (!routing_table_ptr->Init()) {
        TOP_ERROR("init RoutingTable network_id[%d] failed", kad_key->xnetwork_id());
        return false;
    }

    if (!RoutingTableJoin(first_node, kad_key, routing_table_ptr)) {
        TOP_FATAL("routing table join failed!");
        top::wrouter::UnregisterRoutingTable(kad_key->GetServiceType());
        return false;
    }

    TOP_INFO("routing table join success");

    if (root_manager_ptr->AddRoutingTable(
            udp_transport,
            config,
            kad_key) != top::kadmlia::kKadSuccess) {
        TOP_FATAL("add root_table[%llu] failed!", kad_key->GetServiceType());
        return false;
    }

    return true;
}

void InitWrouter(
        top::transport::UdpTransportPtr udp_transport,
        uint64_t max_broadcast_number,
        bool support_random_send) {
    base::xiothread_t* io_thread = top::base::xiothread_t::create_thread(
            top::base::xcontext_t::instance(), 0, -1);

    if (io_thread == NULL) {
        TOP_ERROR("create xio thread failed!");
        assert(false);
        return;
    }

    wrouter::Wrouter::Instance()->Init(
            base::xcontext_t::instance(),
            io_thread->get_thread_id(),
            udp_transport,
            max_broadcast_number);
    if(support_random_send) {
        wrouter::Wrouter::Instance()->SupportRandomPattern();
    }
}

void register_callback_for_socket(top::transport::UdpTransportPtr udp_transport) {
    // socket call  MultiThreadHandler->HandleMesage
    return;

    /*
    udp_transport->register_on_receive_callback(std::bind(&wrouter::Wrouter::recv,
            wrouter::Wrouter::Instance(),
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3,
            std::placeholders::_4,
            std::placeholders::_5,
            std::placeholders::_6,
            std::placeholders::_7,
            std::placeholders::_8));
            */
}

void register_callback_for_multi_threadhandler(
        std::shared_ptr<top::transport::MultiThreadHandler> multi_thread_message_handler) {
    multi_thread_message_handler->register_on_dispatch_callback(std::bind(&wrouter::Wrouter::recv,
            wrouter::Wrouter::Instance(),
            std::placeholders::_1,
            std::placeholders::_2));
}

bool InitRoutingTable(const top::base::Config& config) {
    auto multi_thread_message_handler = std::make_shared<top::transport::MultiThreadHandler>();
    multi_thread_message_handler->Init();
    register_callback_for_multi_threadhandler(multi_thread_message_handler);
    top::transport::UdpTransportPtr udp_transport;
    udp_transport.reset(new top::transport::UdpTransport());
    std::string local_ip;
    if (!config.Get("node", "local_ip", local_ip)) {
        TOP_FATAL("get node local_ip from config failed!");
        return false;
    }
    global_local_ip = local_ip;

    uint32_t zone_id = 0;
    if (!kadmlia::GetZoneIdFromConfig(config, zone_id)) {
        TOP_FATAL("get zone id from config failed!");
        return false;
    }
    global_zone_id = zone_id;

    uint16_t local_port = 0;
    config.Get("node", "local_port", local_port);

    uint64_t max_broadcast_number = top::kadmlia::kRoutingMaxNodesSize;
    config.Get("node","max_broadcast_number",max_broadcast_number);
    bool support_random_send = false;
    config.Get("node", "random_pattern", support_random_send);
    std::cout << "support random pattern?:" << support_random_send  << std::endl;
    InitWrouter(udp_transport, max_broadcast_number,support_random_send);
    register_callback_for_socket(udp_transport);

    if (udp_transport->Start(
            global_local_ip,
            local_port,
            multi_thread_message_handler.get()) != top::kadmlia::kKadSuccess) {
        TOP_FATAL("start local udp transport failed!");
        return false;
    }
    udp_transport->RegisterOfflineCallback(kadmlia::HeartbeatManagerIntf::OnHeartbeatCallback);


    std::set<std::pair<std::string, uint16_t>> public_endpoints_config;
    top::kadmlia::GetPublicEndpointsConfig(config, public_endpoints_config);

    bool first_node = false;
    config.Get("node", "first_node", first_node);

    top::transport::UdpTransportPtr nat_transport;
    nat_transport.reset(new top::transport::UdpTransport());
    if (nat_transport->Start(
            global_local_ip,
            0,
            multi_thread_message_handler.get()) != top::kadmlia::kKadSuccess) {
        TOP_FATAL("start local udp transport failed!");
        return false;
    }
    register_callback_for_socket(nat_transport);

    if (!top::kadmlia::NatManagerIntf::Instance()->Start(
            first_node,
            public_endpoints_config,
            multi_thread_message_handler.get(),
            udp_transport.get(),
            nat_transport.get())) {
        TOP_FATAL("blue nat nat manager start failed");
        return false;
    }

    auto root_manager_ptr = CreateRootManager(udp_transport, config, public_endpoints_config);
    if (!root_manager_ptr) {
        TOP_FATAL("create root manager failed!");
        return false;
    }

    std::set<std::pair<std::string, uint16_t>> boot_endpoints_all;
    root_manager_ptr->GetRootBootstrapCache(boot_endpoints_all);
    top::base::MergeEndpoints(public_endpoints_config, boot_endpoints_all);

    std::string network;
    config.Get("elect", "network", network);
    top::base::LineParser line_split(network.c_str(), ',', network.size());
    std::vector<uint32_t> inetwork_vec;
    for (uint32_t i = 0; i < line_split.Count(); ++i) {
        uint32_t inetwork = check_cast<uint32_t>(line_split[i]);
        TOP_INFO("read network:%d from config", inetwork);
        inetwork_vec.push_back(inetwork);
    }
    if (inetwork_vec.empty()) {
        TOP_WARN("no network load from config");
        return true;
    }

    // start all elect RoutingTable
    for (const auto& inetwork : inetwork_vec) {
        if (!CreateRoutingTable(
                inetwork,
                root_manager_ptr,
                udp_transport,
                config,
                public_endpoints_config)) {
            TOP_FATAL("create some routing table failed!");
            return false;
        }
    }

    // check timer take turns for elect
    // std::shared_ptr<base::TimerRepeated> test_timer_ {nullptr};
    std::vector<std::shared_ptr<base::TimerRepeated>> timer_vec;
    for (const auto& ii : inetwork_vec) {
        std::string config_filed = std::to_string(ii);
        uint32_t replace_time = 0; // seconds
        config.Get(config_filed, "replace_time", replace_time);
        if (replace_time == 0) {
            continue;
        }

        auto callback = [&ii, root_manager_ptr, udp_transport, &config, &public_endpoints_config] () {
            if (CreateRoutingTable(
                    ii,
                    root_manager_ptr,
                    udp_transport,
                    config,
                    public_endpoints_config)) {
                TOP_INFO("elect take turns of p2p_network:%d success", ii);
            } else {
                TOP_INFO("elect take turns of p2p_network:%d failed", ii);
            }
        };
        auto timer = std::make_shared<base::TimerRepeated>(base::TimerManager::Instance(), "elect_network::" + config_filed);
        timer->Start(
                15ll * 1000ll * 1000ll,   // after 15s start this timer
                replace_time * 1000ll * 1000ll, // us
                callback);
        timer_vec.push_back(timer);
    }

    bool show_cmd = true;
    config.Get("node", "show_cmd", show_cmd);
    top::TopCommands* command = top::TopCommands::Instance();
    if (!command->Init(first_node, show_cmd)) {
        TOP_FATAL("init command failed!");
        return false;
    }

#ifdef USE_REDIS
    auto redis_cli = base::RedisClient::Instance()->redis_cli();
    if (redis_cli->is_connected()) {
        redis_cli->incrby("bloomfilter_all_node_count", 1);
        redis_cli->commit();
    }
#endif

    // will be stuck here
    command->Run();


    wrouter::SetRootRoutingManager(nullptr);
    root_manager_ptr.reset();
    top::kadmlia::CallbackManager::Instance()->Join();
    top::wrouter::UnregisterAllRoutingTable();
    udp_transport->Stop();
    TOP_FATAL("all exited.");
    return true;
}

bool ResetEdgeConfig(top::ArgsParser& args_parser, top::base::Config& edge_config) {
    std::string db_path;
    if (args_parser.GetParam("d", db_path) == top::kadmlia::kKadSuccess) {
        if (!edge_config.Set("db", "path", db_path)) {
            TOP_ERROR("set config failed [db][path][%s]", db_path.c_str());
            return false;
        }
    }
    std::string country;
    args_parser.GetParam("o", country);
    if (!country.empty()) {
        if (!edge_config.Set("node", "country", country)) {
            TOP_ERROR("set config failed [node][country][%s]", country.c_str());
            return false;
        }
    }

    std::string local_ip;
    args_parser.GetParam("a", local_ip);
    if (!local_ip.empty()) {
        if (!edge_config.Set("node", "local_ip", local_ip)) {
            TOP_ERROR("set config failed [node][local_ip][%s]", local_ip.c_str());
            return false;
        }
    }
    uint16_t local_port = 0;
    if (args_parser.GetParam("l", local_port) == top::kadmlia::kKadSuccess) {
        if (!edge_config.Set("node", "local_port", local_port)) {
            TOP_ERROR("set config failed [node][local_port][%d]", local_port);
            return false;
        }
    }

    std::string local_xid;
    if (args_parser.GetParam("x", local_xid) == top::kadmlia::kKadSuccess) {
        std::cout << local_xid.size() << std::endl;
        if (!local_xid.empty()) {
            if (!edge_config.Set("node", "local_xid", local_xid)) {
                TOP_ERROR("set config failed [node][local_xid][%s]", local_xid.c_str());
                return false;
            }
        }
    }

    int identity_index = 1;
    if (args_parser.GetParam("i", identity_index) == top::kadmlia::kKadSuccess) {
        bool first_node = false;
        if (identity_index == 0) {
            first_node = true;
        }
        if (!edge_config.Set("node", "first_node", first_node)) {
            TOP_ERROR("set config failed [node][first_node][%d]", first_node);
            return false;
        }
    }

    std::string business;
    if (args_parser.GetParam("u", business) != top::kadmlia::kKadSuccess) {
        business = "EDGE";
    }

    if (!edge_config.Set("node", "business", business)) {
        TOP_ERROR("set config failed [node][business][%s]", business.c_str());
        return false;
    }

    std::string peer;
    args_parser.GetParam("p", peer);
    if (!peer.empty()) {
        if (!edge_config.Set("node", "public_endpoints", peer)) {
            TOP_ERROR("set config failed [node][public_endpoints][%s]", peer.c_str());
            return false;
        }
    }

    int show_cmd = 1;
    if (args_parser.GetParam("g", show_cmd) == top::kadmlia::kKadSuccess) {
        if (!edge_config.Set("node", "show_cmd", show_cmd == 1)) {
            TOP_ERROR("set config failed [node][show_cmd][%d]", show_cmd);
            return false;
        }
    }

    std::string log_path;
    if (args_parser.GetParam("L", log_path) != top::kadmlia::kKadSuccess) {
        log_path = "log/bitvpn.log";
    }

    if (!edge_config.Set("log", "path", log_path)) {
        TOP_ERROR("set config failed [log][log_path][%s]", log_path.c_str());
        return false;
    }

    int32_t http_test = 0;
    if (args_parser.GetParam("t", http_test) == top::kadmlia::kKadSuccess) {
        std::cout<< "=== ttt " << std::endl;
        if (!edge_config.Set("test", "http_test", http_test)) {
            std::cout<< "=== ttt fail" << std::endl;
            TOP_ERROR("set config failed [test][http_test][%d]", http_test);
            return false;
        }
    }

    int32_t is_open;
    if (edge_config.Get("test", "http_test", is_open) == top::kadmlia::kKadSuccess) {
        std::cout<<"=== get === http test" << std::endl;
    }

    std::string service_list;
    if (args_parser.GetParam("s", service_list) == top::kadmlia::kKadSuccess) {
        if (!edge_config.Set("role", "service_list", service_list)) {
            TOP_ERROR("set config failed [edge][service_list][%s]", service_list.c_str());
            return false;
        }
        TOP_INFO("<blueshi> using param('s'): %s", service_list.c_str());
    }

    return true;
}

int HandleParamsAndConfig(int argc, char** argv, top::base::Config& edge_config) {
    top::ArgsParser args_parser;
    if (ParseParams(argc, argv, args_parser) != top::kadmlia::kKadSuccess) {
        TOP_FATAL("parse params failed!");
        return 1;
    }

    if (args_parser.HasParam("h")) {
        std::cout << "Allowed options:" << std::endl;
        std::cout << "\t-h [help]            print help info" << std::endl;
        std::cout << "\t-p [peer]            bootstrap peer[ip:port]" << std::endl;
        std::cout << "\t-i [identity_index]  only first node need" << std::endl;
        std::cout << "\t-l [local_port]      local udp port" << std::endl;
        std::cout << "\t-a [local_ip]        local ip " << std::endl;
        std::cout << "\t-o [country_code]    local country code" << std::endl;
        std::cout << "\t-u [business]        business node provide" << std::endl;
        std::cout << "\t-c [config_path]     config path" << std::endl;
        std::cout << "\t-d [db_path]         db path" << std::endl;
        std::cout << "\t-L [log_path]        log path" << std::endl;
        exit(0);
    }

    std::string config_path;
    args_parser.GetParam("c", config_path);
    if (config_path.empty()) {
        config_path = kConfigFile;
    }
    if (!edge_config.Init(config_path.c_str())) {
        TOP_FATAL("init config file failed: %s", config_path.c_str());
        return 1;
    }

    if (!ResetEdgeConfig(args_parser, edge_config)) {
        TOP_FATAL("reset edge config with arg parser failed!");
        return 1;
    }
    return 0;
}

int InitDb(const base::Config& config) {
    std::string db_path;
    if (!config.Get("db", "path", db_path)) {
        TOP_FATAL("get db path from conf failed[%s]", kConfigFile);
        return 1;
    }

    if (top::storage::XLedgerDB::Instance()->Init(db_path) == top::kadmlia::kKadFailed) {
        TOP_FATAL("ERROR init XLedgerDB.");
        return 1;
    }

    return 0;
}

int MainEdge(const top::base::Config& edge_config) {
    std::string log_path;
    if (!edge_config.Get("log", "path", log_path)) {
        TOP_FATAL("get log path failed!");
        return 1;
    }

    bool log_debug = true;
    edge_config.Get("log", "debug", log_debug);
    bool log_off = false;
    edge_config.Get("log", "off", log_off);

    if (InitLog(log_path, log_debug, log_off) != top::kadmlia::kKadSuccess) {
        TOP_FATAL("log init failed!");
        return 1;
    }

    std::string local_ip;
    if (!edge_config.Get("node", "local_ip", local_ip)) {
        TOP_FATAL("get node local_ip from config failed!");
        return 1;
    }
    top::storage::XLedgerDB::Instance()->map_set(
        top::kadmlia::LOCAL_EDGE_DB_KEY,
        "ip",
        local_ip);

    std::string country;
    if (!edge_config.Get("node", "country", country)) {
        TOP_FATAL("get node country from conf failed[%s]", kConfigFile);
        return 1;
    }
    top::storage::XLedgerDB::Instance()->map_set(
        top::kadmlia::LOCAL_COUNTRY_DB_KEY,
        "code",
        country);
    gossip::BlockSyncManager::Instance()->SetLeagerFace(
            top::storage::XLedgerDB::Instance()->InstanceFace());

    bool use_xudp = false;
    if (edge_config.Get("node", "use_xudp", use_xudp)) {
        transport::UdpConfig::Instance()->UseXudp(use_xudp);
    }

    if (!InitRoutingTable(edge_config)) {
        TOP_FATAL("init InitRoutingTable failed!");
        return 1;
    }
    TOP_INFO("Node stopped successfully.");
    return 0;
}

}  // namespace top

// for unit test
#ifndef TOP_UNITTEST
int main(int argc, char** argv) {
#ifdef _WIN32
    // register signal
    if (signal(SIGTERM, top::SignalCatch) == SIG_ERR ||
            signal(SIGINT, top::SignalCatch) == SIG_ERR) {
        TOP_FATAL("signal failed");
        return 1;
    }
#else
    // register signal
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
            signal(SIGTERM, top::SignalCatch) == SIG_ERR ||
            signal(SIGINT, top::SignalCatch) == SIG_ERR) {
        TOP_FATAL("signal failed");
        return 1;
    }
#endif
    top::base::Config config;
    if (top::HandleParamsAndConfig(argc, argv, config) != 0) {
        TOP_FATAL("handle params and config failed!");
        return 1;
    }

    if (top::InitDb(config) != 0) {
        TOP_FATAL("init db failed!");
        return 1;
    }

    if (!top::kadmlia::CreateGlobalXid(config)) {
        TOP_FATAL("create global xid failed");
        return 1;
    }
    top::kadmlia::CallbackManager::Instance();
    top::wrouter::SmallNetNodes::Instance();
    top::wrouter::SmallNetNodes::Instance()->Init();

#ifdef USE_REDIS
    std::string redis_ip;
    config.Get("redis", "ip", redis_ip);
    uint16_t redis_port;
    config.Get("redis", "port", redis_port);
    std::cout << "now connect redis: " << redis_ip << ":" << redis_port << std::endl;
    try {
        if (!top::base::RedisClient::Instance()->Start(redis_ip, redis_port)) {
            std::cout << "start redis failed!" << std::endl;
            return 1;
        }
    } catch (...) {}
#endif

    int res = top::MainEdge(config);
    TOP_FATAL("main exit: %d", res);
    return res;
}
#endif
