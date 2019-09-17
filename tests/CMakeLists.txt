aux_source_directory(./ xwrouter_test_dir)

add_executable(xwrouter_test ${xwrouter_test_dir})

add_dependencies(xwrouter_test xwrouter xxbase)

target_link_libraries(xwrouter_test
    xwrouter 
    xkad
    xtransport
    xpbase
    xledger
    xcrypto
    xutility
    xxbase
    common
    protobuf
    -lgtest
    -lgmock
    -lpthread -ldl
    -lrt
)

