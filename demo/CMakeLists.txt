aux_source_directory(./ xwrouter_demo_dir)
add_executable(xwrouter_demo ${xwrouter_demo_dir})

add_definitions(
    -DUSE_REDIS
)

add_dependencies(xwrouter_demo xgossip xkad xxbase xpbase)

target_link_libraries(xwrouter_demo
    xwrouter
    xgossip
    xkad 
    xstobject
    xtransport
    xpbase
    xcrypto
    xutility
    xxbase
    xledger
    protobuf
    -lgtest
    -lgmock
    -lpthread -ldl
    -lrt
)

