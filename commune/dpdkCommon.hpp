#pragma once

#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include <sys/stat.h>
#include <netinet/in.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PacketUtils.h>
#include <pcapplusplus/DpdkDevice.h>
#include <pcapplusplus/DpdkDeviceList.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/Logger.h>

#include <pcapplusplus/DpdkDevice.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/TablePrinter.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/Logger.h>

#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/GeneralUtils.h>

#include <pcapplusplus/PeregrineLayer.h>

#include "../common.hpp"

using namespace std;
using namespace pcpp;

namespace Whisper {

using nic_queue_id_t = uint16_t;
using nic_port_id_t = uint16_t;
using cpu_core_id_t = uint16_t;
using mem_pool_size_t = uint16_t;
using parser_queue_assign_t = map<DpdkDevice *, vector<nic_queue_id_t> > ;

struct DpdkConfig final {

	cpu_core_id_t core_id;

    parser_queue_assign_t nic_queue_list;

	DpdkConfig() : core_id(MAX_NUM_OF_CORES + 1) {}
    virtual ~DpdkConfig() {}
    DpdkConfig & operator=(const DpdkConfig &) = delete;
    DpdkConfig(const DpdkConfig &) = delete;

    void add_nic_queue(parser_queue_assign_t::key_type k, parser_queue_assign_t::mapped_type v) {
        nic_queue_list.emplace(k, v);
    }

    void add_nic_queue(parser_queue_assign_t::value_type p) {
        nic_queue_list.insert(p);
    }
};

struct PktMetadata final {

	uint32_t ip_src;
	uint16_t proto;
	uint16_t length;
	double ts;

	PktMetadata() {};

	explicit PktMetadata(uint32_t a, uint16_t p, uint16_t l, double t):
	        ip_src(a), proto(p), length(l), ts(t) {}

	virtual ~PktMetadata() {};
    PktMetadata & operator=(const PktMetadata &) = default;
    PktMetadata(const PktMetadata &) = default;
};

}
