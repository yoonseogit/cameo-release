#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

using namespace std::chrono_literals;

class MediatorTestNode : public rclcpp::Node
{
public:
    MediatorTestNode()
        : Node("mediator_test_node")
    {
        /*
         * Reliable + Volatile
         *
         * 이번 STEP에서는 단순히:
         *
         * ROS 2 Node
         *      ↓
         * Trusted Mediator
         *      ↓
         * External Subscriber
         *
         * 통신이 되는지만 검증한다.
         */
        rclcpp::QoS qos(
            rclcpp::KeepLast(10)
        );

        qos.reliable();
        qos.durability_volatile();

        publisher_ =
            this->create_publisher<std_msgs::msg::String>(
                "/validated_msg",
                qos
            );

        timer_ =
            this->create_wall_timer(
                1s,
                std::bind(
                    &MediatorTestNode::publish_message,
                    this
                )
            );

        RCLCPP_INFO(
            this->get_logger(),
            "mediator_test_node started"
        );

        RCLCPP_INFO(
            this->get_logger(),
            "topic=/validated_msg QoS=RELIABLE"
        );
    }

private:
    void publish_message()
    {
        std_msgs::msg::String message;

        message.data =
            "MTEST-" +
            std::to_string(sequence_);

        RCLCPP_INFO(
            this->get_logger(),
            "PUB %s",
            message.data.c_str()
        );

        publisher_->publish(message);

        ++sequence_;
    }

private:
    std::uint64_t sequence_{1};

    rclcpp::Publisher<
        std_msgs::msg::String
    >::SharedPtr publisher_;

    rclcpp::TimerBase::SharedPtr timer_;
};

int main(
    int argc,
    char* argv[])
{
    rclcpp::init(
        argc,
        argv
    );

    auto node =
        std::make_shared<MediatorTestNode>();

    rclcpp::spin(node);

    rclcpp::shutdown();

    return 0;
}