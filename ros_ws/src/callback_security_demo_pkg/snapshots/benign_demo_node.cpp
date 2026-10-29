#include <functional>
#include <memory>
#include <string>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

using std::placeholders::_1;

class CallbackSecurityDemoNode : public rclcpp::Node
{
public:
    CallbackSecurityDemoNode()
        : Node("callback_security_demo_node")
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
                    &CallbackSecurityDemoNode::callback_a,
                    this,
                    _1));

        input_b_sub_ =
            this->create_subscription<std_msgs::msg::String>(
                "/input_B",
                rclcpp::QoS(10).reliable(),
                std::bind(
                    &CallbackSecurityDemoNode::callback_b,
                    this,
                    _1));

        RCLCPP_INFO(
            this->get_logger(),
            "BENIGN demo node ready: A->/diagnostics, B->/validated_msg");
    }

private:
    void callback_a(const std_msgs::msg::String::SharedPtr msg)
    {
        std_msgs::msg::String out;
        out.data = "diagnostic:A:" + msg->data;

        diagnostics_pub_->publish(out);

        RCLCPP_INFO(
            this->get_logger(),
            "CALLBACK_A allowed publish -> /diagnostics payload=%s",
            out.data.c_str());
    }

    void callback_b(const std_msgs::msg::String::SharedPtr msg)
    {
        std_msgs::msg::String out;
        out.data = "validated:B:" + msg->data;

        validated_pub_->publish(out);

        RCLCPP_INFO(
            this->get_logger(),
            "CALLBACK_B allowed publish -> /validated_msg payload=%s",
            out.data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr diagnostics_pub_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr validated_pub_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr input_a_sub_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr input_b_sub_;
};

int main(int argc, char** argv)
{
    rclcpp::init(argc, argv);
    rclcpp::spin(std::make_shared<CallbackSecurityDemoNode>());
    rclcpp::shutdown();
    return 0;
}
