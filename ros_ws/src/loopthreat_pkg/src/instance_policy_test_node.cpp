#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>

#include <functional>
#include <memory>
#include <string>

class InstancePolicyTestNode : public rclcpp::Node
{
public:
    InstancePolicyTestNode()
        : Node("instance_policy_test_node")
    {
        // 두 Subscription이 공통으로 publish할 output topic
        publisher_output =
        this->create_publisher<std_msgs::msg::String>(
            "/validated_msg",
            10
        );

        // Subscription A
        subscription_A =
            this->create_subscription<std_msgs::msg::String>(
                "/instance_A",
                10,
                std::bind(
                    &InstancePolicyTestNode::common_callback,
                    this,
                    std::placeholders::_1
                )
            );

        // Subscription B
        subscription_B =
            this->create_subscription<std_msgs::msg::String>(
                "/instance_B",
                10,
                std::bind(
                    &InstancePolicyTestNode::common_callback,
                    this,
                    std::placeholders::_1
                )
            );

        // Runtime Subscription pointer 확인용
        RCLCPP_INFO(
            this->get_logger(),
            "INSTANCE_TEST_REGISTER A topic=/instance_A sub=%p",
            static_cast<void *>(subscription_A.get())
        );

        RCLCPP_INFO(
            this->get_logger(),
            "INSTANCE_TEST_REGISTER B topic=/instance_B sub=%p",
            static_cast<void *>(subscription_B.get())
        );

        RCLCPP_INFO(
            this->get_logger(),
            "instance_policy_test_node started"
        );
    }

private:
    /*
     * 핵심:
     * Subscription A와 B가 정확히 같은 callback 함수를 사용한다.
     *
     * callback 내부에서는 어느 Subscription에서 호출되었는지
     * 구분하지 않는다.
     *
     * 즉 application-level 동작은 완전히 동일하고,
     * CallbackInstanceID framework가 Subscription instance를
     * 구분해야 한다.
     */
    __attribute__((noinline))
    void common_callback(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "common_callback received: %s",
            msg->data.c_str()
        );

        std_msgs::msg::String output_msg;
        output_msg.data = "[common_callback] " + msg->data;

        publisher_output->publish(output_msg);

        RCLCPP_INFO(
            this->get_logger(),
            "common_callback attempted to publish /validated_msg: %s",
            output_msg.data.c_str()
        );
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr
        publisher_output;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscription_A;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscription_B;
};


int main(int argc, char * argv[])
{
    rclcpp::init(argc, argv);

    auto node =
        std::make_shared<InstancePolicyTestNode>();

    rclcpp::spin(node);

    rclcpp::shutdown();

    return 0;
}