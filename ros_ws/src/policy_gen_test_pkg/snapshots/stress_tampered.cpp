#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

using std::placeholders::_1;

class PolicyTestNode : public rclcpp::Node
{
public:
    PolicyTestNode()
    : Node("policy_test_node")
    {
        burst_count_ = this->declare_parameter<int>("burst_count", 20);
        inter_publish_us_ = this->declare_parameter<int>("inter_publish_us", 0);

        if (burst_count_ < 1) {
            burst_count_ = 1;
        }
        if (inter_publish_us_ < 0) {
            inter_publish_us_ = 0;
        }

        diagnostics_pub_ =
            this->create_publisher<std_msgs::msg::String>(
                "/diagnostics",
                rclcpp::QoS(100).reliable());

        validated_pub_ =
            this->create_publisher<std_msgs::msg::String>(
                "/validated_msg",
                rclcpp::QoS(100).reliable());

        callback_group_a_ =
            this->create_callback_group(
                rclcpp::CallbackGroupType::MutuallyExclusive);

        callback_group_b_ =
            this->create_callback_group(
                rclcpp::CallbackGroupType::MutuallyExclusive);

        rclcpp::SubscriptionOptions options_a;
        options_a.callback_group = callback_group_a_;

        rclcpp::SubscriptionOptions options_b;
        options_b.callback_group = callback_group_b_;

        input_a_sub_ =
            this->create_subscription<std_msgs::msg::String>(
                "/input_A",
                rclcpp::QoS(100).reliable(),
                std::bind(
                    &PolicyTestNode::callback_a,
                    this,
                    _1),
                options_a);

        input_b_sub_ =
            this->create_subscription<std_msgs::msg::String>(
                "/input_B",
                rclcpp::QoS(100).reliable(),
                std::bind(
                    &PolicyTestNode::callback_b,
                    this,
                    _1),
                options_b);

        RCLCPP_INFO(
            this->get_logger(),
            "stress tampered policy_test_node started "
            "(burst_count=%d, inter_publish_us=%d)",
            burst_count_,
            inter_publish_us_);
    }

private:
    void maybe_sleep() const
    {
        if (inter_publish_us_ > 0) {
            std::this_thread::sleep_for(
                std::chrono::microseconds(inter_publish_us_));
        }
    }

    void callback_a(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_WARN(
            this->get_logger(),
            "callback_A START tid=%zu input=%s burst=%d",
            std::hash<std::thread::id>{}(std::this_thread::get_id()),
            msg->data.c_str(),
            burst_count_);

        for (int i = 0; i < burst_count_; ++i) {
            // Baseline-allowed behavior: callback_a -> /diagnostics
            std_msgs::msg::String diagnostic_msg;
            diagnostic_msg.data =
                "diagnostic:A:" + std::to_string(i) + ":" + msg->data;
            diagnostics_pub_->publish(diagnostic_msg);

            maybe_sleep();

            // Tampered behavior: callback_a -> /validated_msg
            // This relation does NOT exist in the frozen benign baseline.
            std_msgs::msg::String unauthorized_msg;
            unauthorized_msg.data =
                "tampered:A:" + std::to_string(i) + ":" + msg->data;
            validated_pub_->publish(unauthorized_msg);

            maybe_sleep();
        }

        RCLCPP_WARN(
            this->get_logger(),
            "callback_A END tid=%zu attempted_unauthorized=%d",
            std::hash<std::thread::id>{}(std::this_thread::get_id()),
            burst_count_);
    }

    void callback_b(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "callback_B START tid=%zu input=%s burst=%d",
            std::hash<std::thread::id>{}(std::this_thread::get_id()),
            msg->data.c_str(),
            burst_count_);

        for (int i = 0; i < burst_count_; ++i) {
            // Baseline-allowed behavior: callback_b -> /validated_msg
            std_msgs::msg::String out;
            out.data =
                "validated:B:" + std::to_string(i) + ":" + msg->data;
            validated_pub_->publish(out);

            maybe_sleep();
        }

        RCLCPP_INFO(
            this->get_logger(),
            "callback_B END tid=%zu published_allowed=%d",
            std::hash<std::thread::id>{}(std::this_thread::get_id()),
            burst_count_);
    }

    int burst_count_{20};
    int inter_publish_us_{0};

    rclcpp::CallbackGroup::SharedPtr callback_group_a_;
    rclcpp::CallbackGroup::SharedPtr callback_group_b_;

    rclcpp::Publisher<
        std_msgs::msg::String>::SharedPtr diagnostics_pub_;

    rclcpp::Publisher<
        std_msgs::msg::String>::SharedPtr validated_pub_;

    rclcpp::Subscription<
        std_msgs::msg::String>::SharedPtr input_a_sub_;

    rclcpp::Subscription<
        std_msgs::msg::String>::SharedPtr input_b_sub_;
};

int main(int argc, char** argv)
{
    rclcpp::init(argc, argv);

    auto node =
        std::make_shared<PolicyTestNode>();

    rclcpp::executors::MultiThreadedExecutor executor(
        rclcpp::ExecutorOptions(),
        2);

    executor.add_node(node);
    executor.spin();

    rclcpp::shutdown();
    return 0;
}
