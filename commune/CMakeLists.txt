# CMake basics
# Note that the Pytorch 1.6 must use C++ 14
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(commune)
set(CMAKE_CXX_STANDARD 14)

# Add library src
aux_source_directory(. DIR_LIB_SRCS)
add_library (${PROJECT_NAME} ${DIR_LIB_SRCS})

# 4. Link pytorch lib 
target_link_libraries(${PROJECT_NAME} "${TORCH_LIBRARIES}")

# 3. Link Pcapplusplus static dependencies
target_link_libraries(${PROJECT_NAME} 
    libPcap++.a
    libPacket++.a
    libCommon++.a
)

# 2. Link DPDK libraries
target_link_libraries(${PROJECT_NAME}
    rte_node
    rte_graph
    rte_flow_classify
    rte_pipeline
    rte_table
    rte_pdump
    rte_port
    rte_fib
    rte_ipsec
    rte_vhost
    rte_stack
    rte_security
    rte_sched
    rte_reorder
    rte_rib
    rte_dmadev
    rte_regexdev
    rte_rawdev
    rte_power
    rte_pcapng
    rte_member
    rte_lpm
    rte_latencystats
    rte_kni
    rte_jobstats
    rte_ip_frag
    rte_gso
    rte_gro
    rte_gpudev
    rte_eventdev
    rte_efd
    rte_distributor
    rte_cryptodev
    rte_compressdev
    rte_cfgfile
    rte_bpf
    rte_bitratestats
    rte_bbdev
    rte_acl
    rte_timer
    rte_hash
    rte_metrics
    rte_cmdline
    rte_pci
    rte_ethdev
    rte_meter
    rte_net
    rte_mbuf
    rte_mempool
    rte_rcu
    rte_ring
    rte_eal
    rte_telemetry
    rte_kvargs
    -Wl,--no-whole-archive
)

# 1. Link Basic System Libraries
target_link_libraries(${PROJECT_NAME} 
    pthread
    rt
    dl
    m
    numa
    pcap
)

# 0. Link Basic System Libraries
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(${PROJECT_NAME} OpenMP::OpenMP_CXX)
endif()

target_link_libraries(${PROJECT_NAME}
    armadillo
    mlpack
)