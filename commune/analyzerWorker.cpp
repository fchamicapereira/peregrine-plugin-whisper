#include "analyzerWorker.hpp"

using namespace Whisper;

static inline auto __get_double_ts() -> double_t {
    struct timeval ts;
    gettimeofday(&ts, nullptr);
    return ts.tv_sec + ts.tv_usec*(1e-6);
}

void AnalyzerWorkerThread::stop() {
    LOGF("Analyzer on core # %2d stop.", getCoreId());
    m_stop = true;
    sum_analysis_pkt_num += analysis_pkt_num;
    sum_analysis_pkt_len += analysis_pkt_len;

    analysis_end_ts = __get_double_ts();
    if (p_analyzer_conf->save_to_file) {
        save_res_json();
    }

    if (true) {
        printf("Analyzer on core # %2d: Runtime: %5.2lfs,\
                Performance Statisic: [ %4.2lf Mpps / %4.2lf Gbps ]\n",
                getCoreId(),
                (analysis_end_ts - analysis_start_ts),
                (sum_analysis_pkt_num /  (analysis_end_ts - analysis_start_ts)) / 1e6,
                ((sum_analysis_pkt_len * 8.0) /  (analysis_end_ts - analysis_start_ts)) / 1e9);
    }
}

bool AnalyzerWorkerThread::run(uint32_t coreId) {
    if (p_analyzer_conf == nullptr) {
        WARN("None analyzer config found.");
        return false;
    }
    if (p_learner == nullptr) {
        WARN("None learner thread bind.");
        return false;
    }
    if (p_parser.size() == 0) {
        WARN("None parser thread bind.");
        return false;
    }

    meta_pkt_arr = shared_ptr<PktMetadata[]>(new PktMetadata[meta_pkt_arr_size](),
												std::default_delete<PktMetadata[]>());
    if (meta_pkt_arr == nullptr) {
        WARN("Meta packet array: bad allocation");
        return false;
    }

    flow_records = shared_ptr<FlowRecord[]>(new FlowRecord[result_buffer_size](),
											std::default_delete<FlowRecord[]>());

    if (flow_records == nullptr) {
        WARN("Result buffer: bad allocation");
        return false;
    }

    if (p_analyzer_conf->init_verbose) {
        LOGF("Analyzer on core # %2d start.", coreId);
    }

    m_core_id = coreId;
    m_stop = false;

    centers = torch::zeros({(long) p_learner->get_K(),
                            (long) (p_analyzer_conf->n_fft / 2) + 1});

    analysis_pkt_num = 0;
    analysis_pkt_len = 0;
    double_t __s = __get_double_ts();

    while(!m_stop) {
        // pause and wait data from ParserWorkers
        usleep(pause_time);

        // for performance statistic
        double_t __t = __get_double_ts();
        double_t __deta = (__t - __s);
        if (__deta > p_analyzer_conf->verbose_interval) {
            if (p_analyzer_conf->speed_verbose && ! m_is_train) {
                LOGF("Analyzer on core # %2d: [ %4.2lf Mpps / %4.2lf Gbps ]",
                     getCoreId(),
                     (((double_t) analysis_pkt_num) / __deta) / 1e6,
                     (((double_t) analysis_pkt_len) * 8.0) / __deta / 1e9);
            }

            if (! m_is_train) {
                sum_analysis_pkt_num += analysis_pkt_num;
                sum_analysis_pkt_len += analysis_pkt_len;
            }

            analysis_pkt_num = 0;
            analysis_pkt_len = 0;
            __s = __t;

            #ifdef DETAIL_TIME_ANALYZE
                if (true) {
                    LOGF("Analyzer on core # %2d: [Encoding: %4.2lf, Transfrom: %4.2lf,\
                         Distance: %4.2lf, Aggregate: %4.2lf].",
                         getCoreId(),
                         sum_weight_time, sum_transform_time, sum_dist_time, sum_aggregate_time);

                    #ifdef __DETAIL_TIME_ANALYZE
                        LOGF("Analyzer on core # %2d: Averaged analysis time: %4.2lfs / call\
                            (%ld calls).",
                            getCoreId(),
                            (sum_weight_time + sum_transform_time + sum_dist_time +
                            sum_aggregate_time) / analyze_entrance, analyze_entrance);
                        analyze_entrance = 0;
                    #endif
                    sum_weight_time = 0;
                    sum_dist_time = 0;
                    sum_transform_time = 0;
                    sum_aggregate_time = 0;
                }
            #endif
        }

        // fetch pper-packets properties form ParserWorkers
        size_t sum_fetch = 0;
        for (const auto _p : p_parser) {
            _p->acquire_semaphore();
            sum_fetch += fetch_from_parser(_p);
            _p->release_semaphore();
        }

        if (sum_fetch == 0) {
            continue;
        }

        // analyze action
        double start = __get_double_ts();
        wave_analyze();
        double end = __get_double_ts();
        analysis_pkt_num += sum_fetch;
    }

    return true;
}

auto AnalyzerWorkerThread::fetch_from_parser(const shared_ptr<ParserWorkerThread> pt)
        const -> size_t {
    size_t copy_len = 0;
    size_t new_index = 0;

    if (pt->meta_index < 50) {
        return 0;
    }

    if (pt->meta_index + m_index < meta_pkt_arr_size) {
        copy_len = pt->meta_index > max_fetch ? max_fetch : pt->meta_index;
        LOGF("copied len: %lu", copy_len);
    } else {
        copy_len = min(meta_pkt_arr_size - m_index - 1, max_fetch);
        WARNF("Analyzer on core # %2d: queue reach max.\n", getCoreId());
    }
    new_index = pt->meta_index - copy_len;

    // memory copy from registed ParserWorker and reset the buffer
    memcpy(meta_pkt_arr.get() + m_index, pt->meta_pkt_arr.get(), copy_len * sizeof(PktMetadata));
    m_index += copy_len;
    pt->meta_index = new_index;

    return copy_len;
}

void AnalyzerWorkerThread::wave_analyze() {
    const auto cur_len = m_index;
    const auto raw_data = meta_pkt_arr.get();
    static const double_t min_interval_time = 1e-5;

    #ifdef DETAIL_TIME_ANALYZE
        double_t s = __get_double_ts();
        #ifdef __DETAIL_TIME_ANALYZE
            ++ analyze_entrance;
        #endif
    #endif

    for (size_t i = 0; i < cur_len; i++) {
        // the tag for aggregate
        uint32_t ip_src = (ntohl(raw_data[i].ip_src));
        analysis_pkt_len += raw_data[i].length;
        if(mp.find(ip_src) == mp.end()){
            mp.insert(pair<uint32_t, vector<size_t> >(
                ip_src, vector<size_t>())
            );
        }
        mp[ip_src].push_back(i);
    }

    #ifdef DETAIL_TIME_ANALYZE
        sum_aggregate_time +=  __get_double_ts() - s;
    #endif

    /* // clear the buffer */
    m_index = 0;

    LOGF("cur len: %lu", cur_len);
    received_num += cur_len;
    LOGF("Received num: %d", received_num);

    decltype(mp)::const_iterator iter_mp;
    for (iter_mp = mp.cbegin(); iter_mp != mp.cend();) {
        const auto & _ve = iter_mp->second;
        /* LOGF("ip src: %u", iter_mp->first); */
        /* LOGF("mp.size: %lu", mp.size()); */
        /* LOGF("ve.size: %lu", _ve.size()); */
        /* LOGF("n_fft: %lu", p_analyzer_conf->n_fft); */
        if(_ve.size() < 2 * p_analyzer_conf->n_fft) {
            /* LOGF("TEST 4"); */
            ++iter_mp;
            continue;
        }

        // packet encoding
        #ifdef DETAIL_TIME_ANALYZE
            double_t _s0 = __get_double_ts();
        #endif

        torch::Tensor ten = torch::zeros(_ve.size());
        for (int i = 0; i < _ve.size(); i++) {
            ten[i] = weight_transform(raw_data[_ve[i]]);
        }

        #ifdef DETAIL_TIME_ANALYZE
            sum_weight_time += __get_double_ts() - _s0;
        #endif

        // frequency domain analysis
        #ifdef DETAIL_TIME_ANALYZE
            double_t _s1 = __get_double_ts();
        #endif

        // DFT on flow vector
        LOGF("DFT on flow vector");
        torch::Tensor ten_fft = torch::stft(ten, p_analyzer_conf->n_fft);

        // calculate the power
        LOGF("Calculate the power");
        torch::Tensor ten_power = ten_fft.permute({2, 0, 1})[0] * ten_fft.permute({2, 0, 1})[0] +
                                  ten_fft.permute({2, 0, 1})[1] * ten_fft.permute({2, 0, 1})[1];
        ten_power = ten_power.squeeze();

        // log linear transformation
        LOGF("Log linear transformation");
        torch::Tensor ten_res = ((ten_power + 1).log2()).permute({1, 0});

        // erase the inf and nan
        LOGF("Erase the inf and nan");
        ten_res = torch::where(torch::isnan(ten_res), torch::full_like(ten_res, 0), ten_res);
        ten_res = torch::where(torch::isinf(ten_res), torch::full_like(ten_res, 0), ten_res);

        #ifdef DETAIL_TIME_ANALYZE
            sum_transform_time += __get_double_ts() - _s1;
        #endif

        if (m_is_train) {
            LOGF("Enter train");
            /* LOGF("Current packets: %ld", _ve.size()); */
            // feed data to learner
            torch::Tensor ten_temp;
            if (ten_res.size(0) > p_analyzer_conf->mean_win_train + 1
                    /* && !p_learner->reach_learn_records()) { */
                    && !p_learner->reach_learn_packets()) {
                vector<vector<double_t> > data_to_add;
                for (size_t i = 0; i < p_analyzer_conf->num_train_sample; i ++) {
                    size_t start_index = rand()
                        % (ten_res.size(0) - 1 - p_analyzer_conf->mean_win_train);
                    ten_temp = ten_res.slice(
                        0, start_index,
                        start_index + p_analyzer_conf->mean_win_train).mean(0);

                    vector<double_t> _dt;
                    for(size_t j = 0; j < ten_temp.size(0); j ++) {
                        _dt.push_back((double_t) ten_temp[j].item<double_t>());
                    }
                    data_to_add.push_back(_dt);
                }

                /* LOGF("IF"); */
                /* LOGF("Received packets: %lu", ten_res.size(0)); */
                p_learner->acquire_semaphore_data();
                p_learner->add_train_data(data_to_add, cur_len);
                p_learner->release_semaphore_data();
            } else {
                /* LOGF("ELSE"); */
                /* LOGF("Received packets: %lu", ten_res.size(0)); */
                ten_temp =  ten_res.mean(0);
                vector<double_t> data_to_add;

                for(size_t j = 0; j < ten_temp.size(0); j ++) {
                    data_to_add.push_back((double_t) ten_temp[j].item<double_t>());
                }

                p_learner->acquire_semaphore_data();
                p_learner->add_train_data(data_to_add, cur_len);
                p_learner->release_semaphore_data();
            }

            // can start train, but none start train
            p_learner->acquire_semaphore_learn();

            /* if (p_learner->reach_learn_records() && !p_learner->start_learn) { */
            if (p_learner->reach_learn_packets() && !p_learner->start_learn) {
                if (p_analyzer_conf->mode_verbose) {
                    LOGF("Analyer on core %2d: trigger the training of learner.", getCoreId());
                }
                p_learner->start_train();
                LOGF("release semaphore learn: begin");
                p_learner->release_semaphore_learn();
                LOGF("release semaphore learn: end");
            } else {
                p_learner->release_semaphore_learn();
            }

            // train is finished, but still train
            if (p_learner->finish_learn && m_is_train) {
                LOGF("additional training: start");

                m_is_train = false;
                analysis_start_ts = __get_double_ts();

                // clear the counter
                analysis_pkt_len = 0;
                analysis_pkt_num = 0;

                // copy training results from learner (clustering centers)
                const auto & train_res = p_learner->train_result;

                if(p_analyzer_conf->mode_verbose) {
                    LOGF("Analyer on core %2d: enter execution mode.", getCoreId());
                }

                if(getCoreId() == p_analyzer_conf->verbose_center_core &&
                    p_analyzer_conf->center_verbose) {
                }
            }
            usleep(50000);
            return;
        }

        // In testing phase, calculate the min distance of the cluster centers
        #ifdef DETAIL_TIME_ANALYZE
            double_t _s2 = __get_double_ts();
        #endif

        double min_dist = max_cluster_dist;
        if (ten_res.size(0) > p_analyzer_conf->mean_win_test) {
            double_t _max_dist = 0;

            for (size_t i = 0; i + p_analyzer_conf->mean_win_test < ten_res.size(0);
                        i += p_analyzer_conf->mean_win_test) {
                torch::Tensor tt =  ten_res.slice(
                        0, i, i + p_analyzer_conf->mean_win_test).mean(0);
                double_t _min_dist = max_cluster_dist;

                for (size_t j = 0; j < centers.size(0); j ++) {
                    double_t d = torch::norm(tt - centers[j]).item<double_t>();
                    _min_dist = min(_min_dist, d);
                }
                _max_dist = max(_max_dist, _min_dist);
            }
            min_dist = _max_dist;
        } else {
            torch::Tensor tt = ten_res.mean(0);

            for (size_t j = 0; j < centers.size(0); j ++) {
                double d = torch::norm(tt - centers[j]).item<double_t>();
                min_dist = min(min_dist, d);
            }
        }

        #ifdef DETAIL_TIME_ANALYZE
            sum_dist_time += __get_double_ts() - _s2;
        #endif

        if (p_analyzer_conf->ip_verbose) {
            if (p_analyzer_conf->verbose_ip_target.length() != 0 &&
                pcpp::IPv4Address(htonl(iter_mp->first)) == pcpp::IPv4Address(
                    p_analyzer_conf->verbose_ip_target)) {
                LOGF("Analyzer on core # %2d: %6ld abnormal packets, with loss: %6.3lf",
                getCoreId(),
                iter_mp->second.size(),
                min_dist);
            }
        }

        if (p_analyzer_conf->save_to_file) {
            auto & buf_loc = flow_records[flow_record_size % result_buffer_size];
            buf_loc = {.address = iter_mp->first,
                       .distence = min_dist,
                       .packet_num = iter_mp->second.size()};
            ++ flow_record_size;
        }

        // Delete flow from mp
        iter_mp = mp.erase(iter_mp);
    }
}

// 2020.12.8
auto inline AnalyzerWorkerThread::weight_transform(const PktMetadata & info) -> double_t {
     return info.length * 10 + info.proto / 10 + -log2(info.ts) * 15.68;
}

auto AnalyzerWorkerThread::get_overall_performance() const -> pair<double_t, double_t> {
    if (!m_stop) {
		WARN("Parsing not finish, do not collect result.");
		return {0, 0};
	}
	return {
        (((double_t) sum_analysis_pkt_num) / (analysis_end_ts - analysis_start_ts)) / 1e6,
        ((((double_t) sum_analysis_pkt_len) * 8.0) / (analysis_end_ts - analysis_start_ts)) / 1e9
    };
}

auto AnalyzerWorkerThread::save_res_json() const -> bool {
	if (access(p_analyzer_conf->save_dir.c_str(), 0) == -1) {
        system(("mkdir " + p_analyzer_conf->save_dir).c_str());
    }

    ostringstream oss;
    oss << p_analyzer_conf->save_dir << p_analyzer_conf->save_file_prefix
        << '_' << (int) getCoreId() << ".json";

    string file_name = oss.str();

    json j_array;

    for(size_t i = 0; i < min(result_buffer_size, flow_record_size); i ++) {
        json _j;
        _j.push_back(flow_records[i].address);
        _j.push_back(flow_records[i].distence);
        _j.push_back(flow_records[i].packet_num);
        j_array.push_back(_j);
    }

    json j_res;
    j_res["Results"] = j_array;
    ofstream of(file_name);
    if (of) {
        of << j_res;
        of.close();
        printf("Analyzer on core # %d: save result to %s.\n",
               (int) getCoreId(),
               file_name.c_str());
        return true;
    } else {
        return false;
    }
}

// Config form json file
auto AnalyzerWorkerThread::configure_via_json(const json & jin) -> bool {
    if (p_analyzer_conf != nullptr) {
        WARN("Analyzer configuration overlap.");
        return false;
    }

    p_analyzer_conf = make_shared<AnalyzerConfigParam>();
    if (p_analyzer_conf == nullptr) {
        WARNF("Analyzer configuration paramerter bad allocation.");
        return false;
    }

    try {
        // parameters for frequency domain representations
        if (jin.count("n_fft")) {
            p_analyzer_conf->n_fft =
                static_cast<decltype(p_analyzer_conf->n_fft)>(jin["n_fft"]);
        }

        // machine learning
        if (jin.count("mean_win_train")) {
            p_analyzer_conf->mean_win_train =
                static_cast<decltype(p_analyzer_conf->mean_win_train)>(jin["mean_win_train"]);
        }
        if (jin.count("mean_win_test")) {
            p_analyzer_conf->mean_win_test =
                static_cast<decltype(p_analyzer_conf->mean_win_test)>(jin["mean_win_test"]);
        }
        if (jin.count("num_train_sample")) {
            p_analyzer_conf->num_train_sample =
                static_cast<decltype(p_analyzer_conf->num_train_sample)>(jin["num_train_sample"]);
        }

        // verbose parameters
        if (jin.count("mode_verbose")) {
            p_analyzer_conf->mode_verbose =
                static_cast<decltype(p_analyzer_conf->mode_verbose)>(jin["mode_verbose"]);
        }
        if (jin.count("init_verbose")) {
            p_analyzer_conf->init_verbose =
                static_cast<decltype(p_analyzer_conf->init_verbose)>(jin["init_verbose"]);
        }
        if (jin.count("center_verbose")) {
            p_analyzer_conf->center_verbose =
                static_cast<decltype(p_analyzer_conf->center_verbose)>(jin["center_verbose"]);
        }
        if (jin.count("ip_verbose")) {
            p_analyzer_conf->ip_verbose =
                static_cast<decltype(p_analyzer_conf->ip_verbose)>(jin["ip_verbose"]);
        }
        if (jin.count("speed_verbose")) {
            p_analyzer_conf->speed_verbose =
                static_cast<decltype(p_analyzer_conf->speed_verbose)>(jin["speed_verbose"]);
        }
        if (jin.count("speed_verbose")) {
            p_analyzer_conf->speed_verbose =
                static_cast<decltype(p_analyzer_conf->speed_verbose)>(jin["speed_verbose"]);
        }
        if (jin.count("verbose_interval")) {
            p_analyzer_conf->verbose_interval =
                static_cast<decltype(p_analyzer_conf->verbose_interval)>(jin["verbose_interval"]);
            if (p_analyzer_conf->verbose_interval < 0) {
                WARNF("Invalid verbose time interval.");
                throw logic_error("Parse error Json tag: verbose_interval\n");
            }
        }
        if (jin.count("verbose_ip_target")) {
            p_analyzer_conf->verbose_ip_target =
                static_cast<decltype(p_analyzer_conf->verbose_ip_target)>(
                        jin["verbose_ip_target"]);
            if (!IPv4Address(p_analyzer_conf->verbose_ip_target).isValid()) {
                p_analyzer_conf->ip_verbose = false;
                WARNF("Invalid target verbose IP address.");
                throw logic_error("Parse error Json tag: verbose_ip_target\n");
            }
        } else {
            p_analyzer_conf->ip_verbose = false;
        }
        if (jin.count("verbose_center_core")) {
            p_analyzer_conf->verbose_center_core =
                static_cast<decltype(p_analyzer_conf->verbose_center_core)>(
                    jin["verbose_center_core"]);
        }

        // save to file
        if (jin.count("save_to_file")) {
            p_analyzer_conf->save_to_file =
                static_cast<decltype(p_analyzer_conf->save_to_file)>(jin["save_to_file"]);
        }
        if (jin.count("save_dir")) {
            p_analyzer_conf->save_dir =
                static_cast<decltype(p_analyzer_conf->save_dir)>(jin["save_dir"]);
        }
        if (jin.count("save_file_prefix")) {
            p_analyzer_conf->save_file_prefix =
                static_cast<decltype(p_analyzer_conf->save_file_prefix)>(jin["save_file_prefix"]);
        }

        //basic behavior parameters
        if (jin.count("pause_time")) {
            pause_time = static_cast<decltype(pause_time)>(jin["pause_time"]);
        }

        /////////////////////////////////////////// Critical Parameters

        // for memory allocation
        if (jin.count("meta_pkt_arr_size")) {
            meta_pkt_arr_size =
                static_cast<decltype(meta_pkt_arr_size)>(jin["meta_pkt_arr_size"]);
            if (meta_pkt_arr_size > MAX_META_PKT_ARR_SIZE) {
                FATAL_ERROR("Packet metadata buffer size exceed.");
            }
        } else {
            WARNF("Critical tag not found: meta_pkt_arr_size, use default.");
        }
        if (jin.count("result_buffer_size")) {
            result_buffer_size =
                static_cast<decltype(result_buffer_size)>(jin["result_buffer_size"]);
            if (result_buffer_size > MAX_RES_BUF_SIZE) {
                FATAL_ERROR("Result buffer size exceed.");
            }
        } else {
            WARNF("Critical tag not found: result_buffer_size, use default.");
        }

    } catch (exception & e) {
        WARN(e.what());
        return false;
    }

    return true;
}
