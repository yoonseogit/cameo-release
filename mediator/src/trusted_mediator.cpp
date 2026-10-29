#include <fastdds/rtps/RTPSDomain.h>
#include <fastdds/rtps/attributes/HistoryAttributes.h>
#include <fastdds/rtps/attributes/ReaderAttributes.h>
#include <fastdds/rtps/attributes/RTPSParticipantAttributes.h>
#include <fastdds/rtps/attributes/WriterAttributes.h>
#include <fastdds/rtps/builtin/data/WriterProxyData.h>
#include <fastdds/rtps/common/CacheChange.h>
#include <fastdds/rtps/history/ReaderHistory.h>
#include <fastdds/rtps/history/WriterHistory.h>
#include <fastdds/rtps/participant/RTPSParticipant.h>
#include <fastdds/rtps/participant/RTPSParticipantListener.h>
#include <fastdds/rtps/reader/ReaderListener.h>
#include <fastdds/rtps/reader/RTPSReader.h>
#include <fastdds/rtps/writer/RTPSWriter.h>
#include <fastdds/rtps/writer/WriterDiscoveryInfo.h>

#include <fastrtps/attributes/TopicAttributes.h>
#include <fastrtps/qos/ReaderQos.h>
#include <fastrtps/qos/WriterQos.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <linux/bpf.h>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/syscall.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <unistd.h>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace rtps = eprosima::fastrtps::rtps;
namespace fastrtps = eprosima::fastrtps;
namespace dds = eprosima::fastdds::dds;

static constexpr uint32_t INTERNAL_DOMAIN_ID = 10;
static constexpr uint32_t EXTERNAL_DOMAIN_ID = 20;
static constexpr uint32_t MIN_INITIAL_PAYLOAD_SIZE = 64u * 1024u;
static constexpr int32_t INITIAL_HISTORY_CACHES = 32;

static constexpr const char* SAMPLE_PROVENANCE_PIN =
    "/sys/fs/bpf/ros2_security/sample_provenance";

struct SampleIdentityKey
{
    uint8_t writer_guid[16];
    int32_t seq_high;
    uint32_t seq_low;
};

struct SampleProvenanceValue
{
    uint32_t callback_instance_id;
    uint32_t topic_id;
};

static_assert(sizeof(SampleIdentityKey) == 24, "BPF provenance key layout mismatch");
static_assert(sizeof(SampleProvenanceValue) == 8, "BPF provenance value layout mismatch");

static int bpf_obj_get_fd(const char* path)
{
    union bpf_attr attr = {};
    attr.pathname = reinterpret_cast<uint64_t>(path);
    return static_cast<int>(::syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr)));
}

static int bpf_map_lookup_fd(
        int fd,
        const void* key,
        void* value)
{
    union bpf_attr attr = {};
    attr.map_fd = static_cast<uint32_t>(fd);
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.value = reinterpret_cast<uint64_t>(value);
    return static_cast<int>(::syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)));
}

static int bpf_map_delete_fd(
        int fd,
        const void* key)
{
    union bpf_attr attr = {};
    attr.map_fd = static_cast<uint32_t>(fd);
    attr.key = reinterpret_cast<uint64_t>(key);
    return static_cast<int>(::syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)));
}

static std::string normalize_ros_topic(std::string topic)
{
    const auto first = topic.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
    {
        return {};
    }

    const auto last = topic.find_last_not_of(" \t\r\n");
    topic = topic.substr(first, last - first + 1);

    if (!topic.empty() && topic.front() != '/')
    {
        topic.insert(topic.begin(), '/');
    }

    return topic;
}

class PinnedProvenanceMap
{
public:
    ~PinnedProvenanceMap()
    {
        close_map();
    }

    bool open_map()
    {
        fd_ = bpf_obj_get_fd(SAMPLE_PROVENANCE_PIN);
        if (fd_ < 0)
        {
            std::cerr
                << "[BPF_MAP_ERROR] open " << SAMPLE_PROVENANCE_PIN
                << " failed errno=" << errno
                << " (" << std::strerror(errno) << ")\n";
            return false;
        }

        std::cout
            << "[BPF_MAP] provenance opened: " << SAMPLE_PROVENANCE_PIN << '\n';
        return true;
    }

    bool lookup(
            const SampleIdentityKey& key,
            SampleProvenanceValue& value) const
    {
        return bpf_map_lookup_fd(fd_, &key, &value) == 0;
    }

    void consume(const SampleIdentityKey& key) const
    {
        if (fd_ < 0)
        {
            return;
        }

        if (bpf_map_delete_fd(fd_, &key) != 0 && errno != ENOENT)
        {
            std::cerr
                << "[BPF_MAP_WARN] provenance delete failed errno=" << errno
                << " (" << std::strerror(errno) << ")\n";
        }
    }

private:
    void close_map()
    {
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_{-1};
};

class CompiledPolicyBundle
{
public:
    bool load(const std::string& manifest_path, const std::string& policy_path)
    {
        YAML::Node manifest;
        YAML::Node policy;
        try
        {
            manifest = YAML::LoadFile(manifest_path);
            policy = YAML::LoadFile(policy_path);
        }
        catch (const std::exception& e)
        {
            std::cerr << "[POLICY_ERROR] failed to parse runtime artifacts: "
                      << e.what() << '\n';
            return false;
        }

        if (!manifest["version"] || manifest["version"].as<int>() != 1 ||
                !manifest["artifact"] ||
                manifest["artifact"].as<std::string>() != "runtime_manifest")
        {
            std::cerr << "[POLICY_ERROR] invalid runtime manifest header\n";
            return false;
        }
        if (!policy["version"] || policy["version"].as<int>() != 1 ||
                !policy["artifact"] ||
                policy["artifact"].as<std::string>() != "enforcement_policy" ||
                !policy["policy_mode"] ||
                policy["policy_mode"].as<std::string>() != "allowlist")
        {
            std::cerr << "[POLICY_ERROR] invalid enforcement policy header\n";
            return false;
        }
        if (!manifest["manifest_id"] || !policy["manifest_id"] ||
                manifest["manifest_id"].as<std::string>().empty() ||
                manifest["manifest_id"].as<std::string>() !=
                    policy["manifest_id"].as<std::string>())
        {
            std::cerr << "[POLICY_ERROR] runtime manifest and enforcement policy "
                      << "manifest_id mismatch\n";
            return false;
        }

        const YAML::Node callbacks = manifest["callback_instances"];
        if (!callbacks || !callbacks.IsSequence() || callbacks.size() == 0)
        {
            std::cerr << "[POLICY_ERROR] callback_instances must be a non-empty sequence\n";
            return false;
        }

        allow_keys_.clear();
        callback_descriptions_.clear();
        topic_names_.clear();
        topic_dds_names_.clear();
        topic_ids_by_ros_name_.clear();
        topic_ids_by_dds_name_.clear();
        callback_ids_.clear();
        target_topic_id_ = 0;
        target_ros_topic_.clear();
        target_dds_topic_.clear();

        for (std::size_t i = 0; i < callbacks.size(); ++i)
        {
            const YAML::Node callback = callbacks[i];
            const YAML::Node selector = callback["selector"];
            if (!callback["callback_instance_id"] || !selector ||
                    !selector["input_topic"] || !selector["instance"])
            {
                std::cerr << "[POLICY_ERROR] callback_instances[" << i
                          << "] is incomplete\n";
                return false;
            }

            const uint32_t callback_instance_id =
                callback["callback_instance_id"].as<uint32_t>();
            const std::string input_topic =
                normalize_ros_topic(selector["input_topic"].as<std::string>());
            const uint32_t instance = selector["instance"].as<uint32_t>();
            const std::string callback_hint = callback["callback_hint"]
                ? callback["callback_hint"].as<std::string>()
                : std::string{};

            if (input_topic.empty())
            {
                std::cerr << "[POLICY_ERROR] callback_instances[" << i
                          << "] input topic is empty\n";
                return false;
            }
            if (callback_instance_id == 0 || !callback_ids_.insert(callback_instance_id).second)
            {
                std::cerr << "[POLICY_ERROR] duplicate or zero callback_instance_id="
                          << callback_instance_id << '\n';
                return false;
            }

            callback_descriptions_.push_back(
                {callback_instance_id, input_topic, instance, callback_hint});

        }

        const YAML::Node topics = manifest["topics"];
        if (!topics || !topics.IsSequence() || topics.size() == 0)
        {
            std::cerr << "[POLICY_ERROR] topics must be a non-empty sequence\n";
            return false;
        }
        for (std::size_t i = 0; i < topics.size(); ++i)
        {
            const YAML::Node topic = topics[i];
            if (!topic["topic_id"] || !topic["ros_name"] || !topic["dds_name"])
            {
                std::cerr << "[POLICY_ERROR] topics[" << i << "] is incomplete\n";
                return false;
            }
            const uint32_t topic_id = topic["topic_id"].as<uint32_t>();
            const std::string ros_name = normalize_ros_topic(topic["ros_name"].as<std::string>());
            const std::string dds_name = topic["dds_name"].as<std::string>();
            if (topic_id == 0 || ros_name.empty() || dds_name.empty() ||
                    !topic_names_.emplace(topic_id, ros_name).second ||
                    !topic_dds_names_.emplace(topic_id, dds_name).second ||
                    !topic_ids_by_ros_name_.emplace(ros_name, topic_id).second ||
                    !topic_ids_by_dds_name_.emplace(dds_name, topic_id).second)
            {
                std::cerr << "[POLICY_ERROR] duplicate or invalid topic identity\n";
                return false;
            }
        }

        const YAML::Node allow = policy["allow"];
        if (!allow || !allow.IsSequence())
        {
            std::cerr << "[POLICY_ERROR] allow must be a sequence\n";
            return false;
        }
        for (std::size_t i = 0; i < allow.size(); ++i)
        {
            if (!allow[i]["callback_instance_id"] || !allow[i]["topic_id"])
            {
                std::cerr << "[POLICY_ERROR] allow[" << i << "] is incomplete\n";
                return false;
            }
            const uint32_t callback_id = allow[i]["callback_instance_id"].as<uint32_t>();
            const uint32_t topic_id = allow[i]["topic_id"].as<uint32_t>();
            if (callback_ids_.count(callback_id) == 0 || topic_names_.count(topic_id) == 0)
            {
                std::cerr << "[POLICY_ERROR] allow[" << i
                          << "] references an unknown runtime identity\n";
                return false;
            }
            allow_keys_.insert(make_key(callback_id, topic_id));
        }

        std::cout
            << "[MANIFEST_LOAD] path=" << manifest_path << '\n'
            << "[POLICY_LOAD] path=" << policy_path << '\n'
            << "[POLICY_LOAD] mode=allowlist callbacks="
            << callback_descriptions_.size() << '\n';

        for (const auto& callback : callback_descriptions_)
        {
            std::cout
                << "[POLICY_CALLBACK] id=" << callback.callback_instance_id
                << " selector=(" << callback.input_topic
                << "," << callback.instance << ")";
            if (!callback.callback_hint.empty())
            {
                std::cout << " hint=" << callback.callback_hint;
            }
            std::cout << '\n';
        }

        for (const uint64_t packed : allow_keys_)
        {
            const uint32_t callback_instance_id =
                static_cast<uint32_t>(packed >> 32u);
            const uint32_t topic_id = static_cast<uint32_t>(packed);
            std::cout
                << "[POLICY_ALLOW] cb=" << callback_instance_id
                << " topic_id=" << topic_id
                << " topic=" << topic_name(topic_id) << '\n';
        }

        return true;
    }

    bool is_allowed(uint32_t callback_instance_id, uint32_t topic_id) const
    {
        return allow_keys_.find(make_key(callback_instance_id, topic_id))
            != allow_keys_.end();
    }

    bool select_target_topic(const std::string& raw_ros_topic)
    {
        const std::string ros_topic = normalize_ros_topic(raw_ros_topic);
        const auto id_it = topic_ids_by_ros_name_.find(ros_topic);
        if (ros_topic.empty() || id_it == topic_ids_by_ros_name_.end())
        {
            std::cerr << "[POLICY_ERROR] requested target topic " << raw_ros_topic
                      << " is absent from runtime manifest\n";
            return false;
        }

        const auto dds_it = topic_dds_names_.find(id_it->second);
        if (dds_it == topic_dds_names_.end())
        {
            std::cerr << "[POLICY_ERROR] target topic has no DDS identity\n";
            return false;
        }

        target_topic_id_ = id_it->second;
        target_ros_topic_ = ros_topic;
        target_dds_topic_ = dds_it->second;
        return true;
    }

    uint32_t target_topic_id() const { return target_topic_id_; }
    const std::string& target_ros_topic() const { return target_ros_topic_; }
    const std::string& target_dds_topic() const { return target_dds_topic_; }

    std::string topic_name(uint32_t topic_id) const
    {
        const auto it = topic_names_.find(topic_id);
        return it == topic_names_.end() ? std::string("<unknown>") : it->second;
    }

private:
    struct CallbackDescription
    {
        uint32_t callback_instance_id;
        std::string input_topic;
        uint32_t instance;
        std::string callback_hint;
    };

    static uint64_t make_key(uint32_t callback_instance_id, uint32_t topic_id)
    {
        return (static_cast<uint64_t>(callback_instance_id) << 32u) | topic_id;
    }

private:
    std::unordered_set<uint64_t> allow_keys_;
    std::unordered_set<uint32_t> callback_ids_;
    std::unordered_map<uint32_t, std::string> topic_names_;
    std::unordered_map<uint32_t, std::string> topic_dds_names_;
    std::unordered_map<std::string, uint32_t> topic_ids_by_ros_name_;
    std::unordered_map<std::string, uint32_t> topic_ids_by_dds_name_;
    std::vector<CallbackDescription> callback_descriptions_;
    uint32_t target_topic_id_{0};
    std::string target_ros_topic_;
    std::string target_dds_topic_;
};

static std::atomic_bool g_stop_requested{false};

static void signal_handler(int)
{
    g_stop_requested.store(true);
}

struct TargetWriterMetadata
{
    std::string topic_name;
    std::string type_name;
    rtps::GUID_t writer_guid{};
    rtps::TopicKind_t topic_kind{rtps::NO_KEY};
    uint32_t type_max_serialized{0};
};

class TrustedMediator;

class InternalReaderListener final : public rtps::ReaderListener
{
public:
    explicit InternalReaderListener(TrustedMediator* owner)
        : owner_(owner)
    {
    }
    void onReaderMatched(
        rtps::RTPSReader* reader,
        rtps::MatchingInfo& info) override
    {
        static_cast<void>(reader);

        if (info.status == rtps::MATCHED_MATCHING)
        {
            std::cout
                << "[INTERNAL_READER_MATCHED]\n"
                << "  remote_writer_guid="
                << info.remoteEndpointGuid << '\n';
        }
        else if (info.status == rtps::REMOVED_MATCHING)
        {
            std::cout
                << "[INTERNAL_READER_UNMATCHED]\n"
                << "  remote_writer_guid="
                << info.remoteEndpointGuid << '\n';
        }
    }

    void onNewCacheChangeAdded(
            rtps::RTPSReader* reader,
            const rtps::CacheChange_t* const change) override;

private:
    TrustedMediator* owner_{nullptr};
};

class InternalParticipantListener final : public rtps::RTPSParticipantListener
{
public:
    explicit InternalParticipantListener(TrustedMediator* owner)
        : owner_(owner)
    {
    }

    void onWriterDiscovery(
            rtps::RTPSParticipant* participant,
            rtps::WriterDiscoveryInfo&& info) override;

private:
    TrustedMediator* owner_{nullptr};
};

class TrustedMediator
{
public:
    TrustedMediator(
            std::string manifest_path,
            std::string policy_path,
            std::string target_topic)
        : manifest_path_(std::move(manifest_path))
        , policy_path_(std::move(policy_path))
        , requested_target_topic_(std::move(target_topic))
        , participant_listener_(this)
        , reader_listener_(this)
    {
    }

    ~TrustedMediator()
    {
        cleanup();
    }

    bool init()
    {
        if (!policy_bundle_.load(manifest_path_, policy_path_))
        {
            std::cerr << "[INIT_ERROR] compiled policy bundle load failed\n";
            return false;
        }

        if (!policy_bundle_.select_target_topic(requested_target_topic_))
        {
            std::cerr << "[INIT_ERROR] target topic selection failed\n";
            return false;
        }

        std::cout
            << "========================================\n"
            << "Trusted DDS/RTPS Mediator\n"
            << "Opaque Serialized-Payload Republish\n"
            << "========================================\n"
            << "Internal Domain : " << INTERNAL_DOMAIN_ID << '\n'
            << "External Domain : " << EXTERNAL_DOMAIN_ID << '\n'
            << "Target ROS Topic: " << policy_bundle_.target_ros_topic() << '\n'
            << "Target DDS Topic: " << policy_bundle_.target_dds_topic() << '\n'
            << "Target Topic ID : " << policy_bundle_.target_topic_id() << '\n'
            << "QoS             : RELIABLE (fixed)\n"
            << "Payload         : OPAQUE COPY (no deserialize)\n"
            << "Policy          : FROZEN YAML ALLOWLIST (fail-closed)\n"
            << "Provenance Map  : " << SAMPLE_PROVENANCE_PIN << '\n'
            << "========================================\n";

        if (!provenance_map_.open_map())
        {
            std::cerr
                << "[INIT_ERROR] provenance map unavailable. "
                << "Start provenance_tracker first and run mediator with sufficient privileges.\n";
            return false;
        }

        rtps::RTPSParticipantAttributes external_attrs;
        external_attrs.setName("trusted_mediator_external");

        external_participant_ = rtps::RTPSDomain::createParticipant(
            EXTERNAL_DOMAIN_ID,
            external_attrs,
            nullptr);

        if (external_participant_ == nullptr)
        {
            std::cerr << "[INIT_ERROR] failed to create external RTPSParticipant\n";
            return false;
        }

        std::cout << "[INIT] External RTPSParticipant created\n";

        rtps::RTPSParticipantAttributes internal_attrs;
        internal_attrs.setName("trusted_mediator_internal");

        internal_participant_ = rtps::RTPSDomain::createParticipant(
            INTERNAL_DOMAIN_ID,
            internal_attrs,
            &participant_listener_);

        if (internal_participant_ == nullptr)
        {
            std::cerr << "[INIT_ERROR] failed to create internal RTPSParticipant\n";
            return false;
        }

        std::cout << "[INIT] Internal RTPSParticipant created\n\n";
        std::cout << "[READY] Waiting for target ROS 2 DDS Writer discovery...\n";
        std::cout << "[READY] Domain " << INTERNAL_DOMAIN_ID
                  << " topic=" << policy_bundle_.target_dds_topic() << "\n\n";

        return true;
    }

    void run()
    {
        while (!g_stop_requested.load())
        {
            maybe_create_bridge();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void handle_writer_discovery(const rtps::WriterDiscoveryInfo& info)
    {
        const auto& writer = info.info;
        const std::string topic_name = writer.topicName().c_str();

        if (info.status == rtps::WriterDiscoveryInfo::REMOVED_WRITER)
        {
            std::lock_guard<std::mutex> lock(metadata_mutex_);
            if (target_writer_selected_ && writer.guid() == target_writer_.writer_guid)
            {
                std::cout << "[TARGET_WRITER_REMOVED] guid=" << writer.guid() << '\n';
            }
            return;
        }

        if (info.status != rtps::WriterDiscoveryInfo::DISCOVERED_WRITER &&
                info.status != rtps::WriterDiscoveryInfo::CHANGED_QOS_WRITER)
        {
            return;
        }

        if (topic_name != policy_bundle_.target_dds_topic())
        {
            return;
        }

        const std::string type_name = writer.typeName().c_str();

        std::cout
            << "[TARGET_WRITER_DISCOVERY]\n"
            << "  topic=" << topic_name << '\n'
            << "  type=" << type_name << '\n'
            << "  guid=" << writer.guid() << '\n'
            << "  type_max_serialized=" << writer.typeMaxSerialized() << '\n'
            << "  topic_kind=" << (writer.topicKind() == rtps::WITH_KEY ? "WITH_KEY" : "NO_KEY") << '\n'
            << "  type_metadata=NOT_REQUIRED\n";

        std::lock_guard<std::mutex> lock(metadata_mutex_);

        if (bridge_ready_.load())
        {
            if (writer.guid() != target_writer_.writer_guid)
            {
                std::cout << "[TARGET_WRITER_IGNORED] bridge already bound to first target writer\n";
            }
            return;
        }

        if (!target_writer_selected_)
        {
            target_writer_.topic_name = topic_name;
            target_writer_.type_name = type_name;
            target_writer_.writer_guid = writer.guid();
            target_writer_.topic_kind = writer.topicKind();
            target_writer_.type_max_serialized = writer.typeMaxSerialized();
            target_writer_selected_ = true;
            bridge_request_pending_ = true;
        }
    }

    void handle_new_change(
            rtps::RTPSReader* reader,
            const rtps::CacheChange_t* change)
    {
        if (reader == nullptr || change == nullptr)
        {
            return;
        }

        const bool from_target = is_target_writer(change->writerGUID);

        if (!from_target)
        {
            std::cout
                << "[RX_SKIP]\n"
                << "  reason=non_target_writer\n"
                << "  writer_guid=" << change->writerGUID << '\n'
                << "  sequence=" << change->sequenceNumber.to64long() << '\n';

            remove_incoming_change(reader, change);
            return;
        }

        const uint64_t rx_count = ++received_samples_;

        std::cout
            << "[MEDIATOR_RX]\n"
            << "  count=" << rx_count << '\n'
            << "  writer_guid=" << change->writerGUID << '\n'
            << "  sequence=" << change->sequenceNumber.to64long() << '\n'
            << "  payload_length=" << change->serializedPayload.length << '\n'
            << "  action=PROVENANCE_KEY_READY\n";

        const bool allow = evaluate_policy(*change);

        if (!allow)
        {
            ++denied_samples_;
            std::cout << "[MEDIATOR_DENY] sample dropped\n";
            remove_incoming_change(reader, change);
            return;
        }

        if (!republish_opaque_payload(*change))
        {
            ++republish_failures_;
            std::cerr << "[MEDIATOR_TX_ERROR] opaque-payload republish failed\n";
            remove_incoming_change(reader, change);
            return;
        }

        remove_incoming_change(reader, change);
    }

private:
    SampleIdentityKey make_sample_identity(const rtps::CacheChange_t& change) const
    {
        SampleIdentityKey key = {};

        std::copy_n(
            change.writerGUID.guidPrefix.value,
            12,
            key.writer_guid);

        std::copy_n(
            change.writerGUID.entityId.value,
            4,
            key.writer_guid + 12);

        key.seq_high = change.sequenceNumber.high;
        key.seq_low = change.sequenceNumber.low;

        return key;
    }

    bool evaluate_policy(const rtps::CacheChange_t& change)
    {
        const SampleIdentityKey identity = make_sample_identity(change);
        SampleProvenanceValue provenance = {};

        errno = 0;
        if (!provenance_map_.lookup(identity, provenance))
        {
            const int lookup_errno = errno;

            std::cout
                << "[PROVENANCE_MISS]\n"
                << "  writer_guid=" << change.writerGUID << '\n'
                << "  sequence=" << change.sequenceNumber.to64long() << '\n'
                << "  result=DENY\n"
                << "  reason="
                << (lookup_errno == ENOENT
                    ? "NO_PROVENANCE"
                    : "PROVENANCE_LOOKUP_ERROR")
                << '\n';

            if (lookup_errno != ENOENT)
            {
                std::cerr
                    << "  errno=" << lookup_errno
                    << " (" << std::strerror(lookup_errno) << ")\n";
            }

            return false;
        }

        std::cout
            << "[PROVENANCE_HIT]\n"
            << "  callback_instance_id=" << provenance.callback_instance_id << '\n'
            << "  topic_id=" << provenance.topic_id << '\n'
            << "  topic=" << policy_bundle_.topic_name(provenance.topic_id) << '\n';

        // One-shot handoff. A duplicate/replayed incoming sample will fail closed.
        provenance_map_.consume(identity);

        if (provenance.topic_id != policy_bundle_.target_topic_id())
        {
            std::cout
                << "[MEDIATOR_POLICY]\n"
                << "  callback_instance_id=" << provenance.callback_instance_id << '\n'
                << "  topic_id=" << provenance.topic_id << '\n'
                << "  result=DENY\n"
                << "  reason=PROVENANCE_TOPIC_MISMATCH\n";
            return false;
        }

        const bool allowed = policy_bundle_.is_allowed(
            provenance.callback_instance_id,
            provenance.topic_id);

        std::cout
            << "[MEDIATOR_POLICY]\n"
            << "  callback_instance_id=" << provenance.callback_instance_id << '\n'
            << "  topic_id=" << provenance.topic_id << '\n'
            << "  topic=" << policy_bundle_.topic_name(provenance.topic_id) << '\n'
            << "  result=" << (allowed ? "ALLOW" : "DENY") << '\n'
            << "  reason=" << (allowed ? "ALLOWLIST_HIT" : "NOT_IN_ALLOWLIST") << '\n';

        return allowed;
    }

    bool is_target_writer(const rtps::GUID_t& guid)
    {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        return target_writer_selected_ && guid == target_writer_.writer_guid;
    }

    void maybe_create_bridge()
    {
        if (bridge_ready_.load())
        {
            return;
        }

        TargetWriterMetadata metadata;

        {
            std::lock_guard<std::mutex> lock(metadata_mutex_);
            if (!bridge_request_pending_ || !target_writer_selected_)
            {
                return;
            }

            metadata = target_writer_;
            bridge_request_pending_ = false;
        }

        if (!create_bridge(metadata))
        {
            std::lock_guard<std::mutex> lock(metadata_mutex_);
            bridge_request_pending_ = true;
        }
    }

    bool create_bridge(const TargetWriterMetadata& metadata)
    {
        std::lock_guard<std::mutex> lock(bridge_mutex_);

        if (bridge_ready_.load())
        {
            return true;
        }

        std::cout
            << "\n========================================\n"
            << "[BRIDGE_SETUP]\n"
            << "  topic=" << metadata.topic_name << '\n'
            << "  type=" << metadata.type_name << '\n'
            << "  source_writer_guid=" << metadata.writer_guid << '\n'
            << "  mode=OPAQUE_SERIALIZED_PAYLOAD\n"
            << "========================================\n";

        const uint32_t initial_payload_size = std::max(
            MIN_INITIAL_PAYLOAD_SIZE,
            metadata.type_max_serialized);

        rtps::HistoryAttributes writer_history_attrs;
        writer_history_attrs.payloadMaxSize = initial_payload_size;
        writer_history_attrs.initialReservedCaches = INITIAL_HISTORY_CACHES;
        writer_history_attrs.maximumReservedCaches = 0;

        external_writer_history_ = std::make_unique<rtps::WriterHistory>(
            writer_history_attrs);

        rtps::WriterAttributes writer_attrs;
        writer_attrs.endpoint.reliabilityKind = rtps::RELIABLE;
        writer_attrs.endpoint.durabilityKind = rtps::VOLATILE;
        writer_attrs.endpoint.topicKind = metadata.topic_kind;
        writer_attrs.mode = rtps::ASYNCHRONOUS_WRITER;

        external_writer_ = rtps::RTPSDomain::createRTPSWriter(
            external_participant_,
            writer_attrs,
            external_writer_history_.get(),
            nullptr);

        if (external_writer_ == nullptr)
        {
            std::cerr << "[BRIDGE_ERROR] createRTPSWriter failed\n";
            external_writer_history_.reset();
            return false;
        }

        fastrtps::TopicAttributes external_topic(
            metadata.topic_name.c_str(),
            metadata.type_name.c_str(),
            metadata.topic_kind);
        external_topic.auto_fill_type_object = false;
        external_topic.auto_fill_type_information = false;

        fastrtps::WriterQos writer_qos;
        writer_qos.m_reliability.kind = dds::RELIABLE_RELIABILITY_QOS;
        writer_qos.m_durability.kind = dds::VOLATILE_DURABILITY_QOS;

        if (!external_participant_->registerWriter(
                external_writer_,
                external_topic,
                writer_qos))
        {
            std::cerr << "[BRIDGE_ERROR] registerWriter failed\n";
            rtps::RTPSDomain::removeRTPSWriter(external_writer_);
            external_writer_ = nullptr;
            external_writer_history_.reset();
            return false;
        }

        std::cout
            << "[BRIDGE] External Reliable RTPSWriter created\n"
            << "  new_writer_guid=" << external_writer_->getGuid() << '\n';

        rtps::HistoryAttributes reader_history_attrs;
        reader_history_attrs.payloadMaxSize = initial_payload_size;
        reader_history_attrs.initialReservedCaches = INITIAL_HISTORY_CACHES;
        reader_history_attrs.maximumReservedCaches = 0;

        internal_reader_history_ = std::make_unique<rtps::ReaderHistory>(
            reader_history_attrs);

        rtps::ReaderAttributes reader_attrs;
        reader_attrs.endpoint.reliabilityKind = rtps::RELIABLE;
        reader_attrs.endpoint.durabilityKind = rtps::VOLATILE;
        reader_attrs.endpoint.topicKind = metadata.topic_kind;

        internal_reader_ = rtps::RTPSDomain::createRTPSReader(
            internal_participant_,
            reader_attrs,
            internal_reader_history_.get(),
            &reader_listener_);

        if (internal_reader_ == nullptr)
        {
            std::cerr << "[BRIDGE_ERROR] createRTPSReader failed\n";
            return false;
        }

        fastrtps::TopicAttributes internal_topic(
            metadata.topic_name.c_str(),
            metadata.type_name.c_str(),
            metadata.topic_kind);
        internal_topic.auto_fill_type_object = false;
        internal_topic.auto_fill_type_information = false;

        fastrtps::ReaderQos reader_qos;
        reader_qos.m_reliability.kind = dds::RELIABLE_RELIABILITY_QOS;
        reader_qos.m_durability.kind = dds::VOLATILE_DURABILITY_QOS;

        if (!internal_participant_->registerReader(
                internal_reader_,
                internal_topic,
                reader_qos))
        {
            std::cerr << "[BRIDGE_ERROR] registerReader failed\n";
            rtps::RTPSDomain::removeRTPSReader(internal_reader_);
            internal_reader_ = nullptr;
            internal_reader_history_.reset();
            return false;
        }

        bridge_ready_.store(true);

        std::cout
            << "[BRIDGE] Internal Reliable RTPSReader created\n"
            << "  reader_guid=" << internal_reader_->getGuid() << '\n'
            << "\n========================================\n"
            << "[MEDIATOR_READY]\n"
            << "Internal Domain " << INTERNAL_DOMAIN_ID << '\n'
            << "  RX opaque CacheChange_t\n"
            << "  provenance key = (Writer GUID, Sequence Number)\n"
            << "  policy = frozen YAML allowlist / fail-closed\n"
            << "  copy serializedPayload only\n"
            << "  create NEW CacheChange_t / NEW sequence\n"
            << "External Domain " << EXTERNAL_DOMAIN_ID << '\n'
            << "========================================\n\n";

        return true;
    }

    bool republish_opaque_payload(const rtps::CacheChange_t& incoming)
    {
        if (!bridge_ready_.load() ||
                external_writer_ == nullptr ||
                external_writer_history_ == nullptr)
        {
            return false;
        }

        const uint32_t payload_length = incoming.serializedPayload.length;
        const std::function<uint32_t()> size_provider = [payload_length]()
                {
                    return payload_length;
                };

        rtps::CacheChange_t* outgoing = external_writer_->new_change(
            size_provider,
            incoming.kind,
            incoming.instanceHandle);

        if (outgoing == nullptr)
        {
            std::cerr << "[MEDIATOR_TX_ERROR] new_change returned nullptr\n";
            return false;
        }

        // Important: only the serialized application payload is copied.
        // writerGUID / sequenceNumber are intentionally NOT copied.
        // The external writer/history assigns a new identity for the new Reliable stream.
        if (!outgoing->serializedPayload.copy(
                &incoming.serializedPayload,
                true))
        {
            std::cerr
                << "[MEDIATOR_TX_ERROR] serializedPayload.copy failed"
                << " incoming_length=" << payload_length
                << " outgoing_capacity=" << outgoing->serializedPayload.max_size
                << '\n';

            external_writer_->release_change(outgoing);
            return false;
        }

        if (!external_writer_history_->add_change(outgoing))
        {
            std::cerr << "[MEDIATOR_TX_ERROR] WriterHistory::add_change failed\n";
            external_writer_->release_change(outgoing);
            return false;
        }

        const uint64_t tx_count = ++forwarded_samples_;

        std::cout
            << "[MEDIATOR_TX]\n"
            << "  count=" << tx_count << '\n'
            << "  original_writer_guid=" << incoming.writerGUID << '\n'
            << "  original_sequence=" << incoming.sequenceNumber.to64long() << '\n'
            << "  new_writer_guid=" << outgoing->writerGUID << '\n'
            << "  new_sequence=" << outgoing->sequenceNumber.to64long() << '\n'
            << "  payload_length=" << outgoing->serializedPayload.length << '\n'
            << "  decision=ALLOW\n"
            << "  action=OPAQUE_REPUBLISH\n";

        return true;
    }

    void remove_incoming_change(
            rtps::RTPSReader* reader,
            const rtps::CacheChange_t* change)
    {
        if (reader == nullptr || change == nullptr)
        {
            return;
        }

        auto* mutable_change = const_cast<rtps::CacheChange_t*>(change);

        if (!reader->getHistory()->remove_change(mutable_change))
        {
            std::cerr
                << "[RX_CLEANUP_WARN] ReaderHistory::remove_change failed"
                << " writer=" << change->writerGUID
                << " seq=" << change->sequenceNumber.to64long()
                << '\n';
        }
    }

    void cleanup()
    {
        bool expected = false;
        if (!cleanup_started_.compare_exchange_strong(expected, true))
        {
            return;
        }

        std::cout
            << "\n[CLEANUP] stopping RTPS mediator"
            << " rx=" << received_samples_.load()
            << " tx=" << forwarded_samples_.load()
            << " deny=" << denied_samples_.load()
            << " tx_fail=" << republish_failures_.load()
            << '\n';

        // This mediator owns all RTPS entities in this standalone process.
        // stopAll() invalidates the participant/reader/writer pointers.
        rtps::RTPSDomain::stopAll();

        internal_reader_ = nullptr;
        external_writer_ = nullptr;
        internal_participant_ = nullptr;
        external_participant_ = nullptr;

        internal_reader_history_.reset();
        external_writer_history_.reset();

        std::cout << "[CLEANUP] done\n";
    }

private:
    std::string manifest_path_;
    std::string policy_path_;
    std::string requested_target_topic_;
    CompiledPolicyBundle policy_bundle_;
    PinnedProvenanceMap provenance_map_;

    rtps::RTPSParticipant* internal_participant_{nullptr};
    rtps::RTPSParticipant* external_participant_{nullptr};

    rtps::RTPSReader* internal_reader_{nullptr};
    rtps::RTPSWriter* external_writer_{nullptr};

    std::unique_ptr<rtps::ReaderHistory> internal_reader_history_;
    std::unique_ptr<rtps::WriterHistory> external_writer_history_;

    InternalParticipantListener participant_listener_;
    InternalReaderListener reader_listener_;

    std::mutex metadata_mutex_;
    TargetWriterMetadata target_writer_;
    bool target_writer_selected_{false};
    bool bridge_request_pending_{false};

    std::mutex bridge_mutex_;
    std::atomic_bool bridge_ready_{false};
    std::atomic_bool cleanup_started_{false};

    std::atomic_uint64_t received_samples_{0};
    std::atomic_uint64_t forwarded_samples_{0};
    std::atomic_uint64_t denied_samples_{0};
    std::atomic_uint64_t republish_failures_{0};
};

void InternalReaderListener::onNewCacheChangeAdded(
        rtps::RTPSReader* reader,
        const rtps::CacheChange_t* const change)
{
    if (owner_ != nullptr)
    {
        owner_->handle_new_change(reader, change);
    }
}

void InternalParticipantListener::onWriterDiscovery(
        rtps::RTPSParticipant* participant,
        rtps::WriterDiscoveryInfo&& info)
{
    static_cast<void>(participant);

    if (owner_ != nullptr)
    {
        owner_->handle_writer_discovery(info);
    }
}

int main(int argc, char** argv)
{
    if (argc != 5 || std::string(argv[3]) != "--target-topic")
    {
        std::cerr
            << "Usage: " << argv[0]
            << " <runtime_manifest.yaml> <enforcement_policy.yaml>"
            << " --target-topic <ros-topic>\n";
        return 2;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    TrustedMediator mediator(argv[1], argv[2], argv[4]);

    if (!mediator.init())
    {
        std::cerr << "[FATAL] mediator initialization failed\n";
        return 1;
    }

    mediator.run();

    std::cout << "\n[STOP] signal received\n";
    return 0;
}
