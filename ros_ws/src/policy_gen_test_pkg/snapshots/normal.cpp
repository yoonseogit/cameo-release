#include <functional>
#include <memory>
#include <string>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

using std::placeholders::_1;

class PolicyTestNode : public rclcpp::Node
{
public:
    PolicyTestNode()
    : Node("policy_test_node")
    {
        diagnostics_pub_ =
            this->create_publisher<std_msgs::msg::String>(
                "/diagnostics",
                rclcpp::QoS(10).reliable());

        validated_pub_ =
            this->create_publisher<std_msgs::msg::String>(
                "/validated_msg",
                rclcpp::QoS(10).reliable());

        input_a_sub_ =
            this->create_subscription<std_msgs::msg::String>(
                "/input_A",
                rclcpp::QoS(10).reliable(),
                std::bind(
                    &PolicyTestNode::callback_a,
                    this,
                    _1));

        input_b_sub_ =
            this->create_subscription<std_msgs::msg::String>(
                "/input_B",
                rclcpp::QoS(10).reliable(),
                std::bind(
                    &PolicyTestNode::callback_b,
                    this,
                    _1));

        RCLCPP_INFO(
            this->get_logger(),
            "policy_test_node started");
    }

private:
    void callback_a(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "callback_A received: %s",
            msg->data.c_str());

        std_msgs::msg::String out;
        out.data = "diagnostic:" + msg->data;

        diagnostics_pub_->publish(out);

        RCLCPP_INFO(
            this->get_logger(),
            "callback_A published /diagnostics");
    }

    void callback_b(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "callback_B received: %s",
            msg->data.c_str());

        std_msgs::msg::String out;
        out.data = "validated:" + msg->data;

        validated_pub_->publish(out);

        RCLCPP_INFO(
            this->get_logger(),
            "callback_B published /validated_msg");
    }

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

    rclcpp::spin(node);

    rclcpp::shutdown();

    return 0;
}