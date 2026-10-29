#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <memory>
#include <functional>
#include <string>

class FeedbackloopNode : public rclcpp::Node
{
public:
    FeedbackloopNode() : Node("loop_node")
    {
        /*
         * ============================================================
         * 기존 baseline
         * ============================================================
         */

        publish_validated =
            this->create_publisher<std_msgs::msg::String>(
                "/validated_msg",
                10
            );

        subscribe_validated =
            this->create_subscription<std_msgs::msg::String>(
                "/validated_msg",
                10,
                std::bind(
                    &FeedbackloopNode::callback_A,
                    this,
                    std::placeholders::_1
                )
            );

        subscribe_input =
            this->create_subscription<std_msgs::msg::String>(
                "/input_msg",
                10,
                std::bind(
                    &FeedbackloopNode::callback_B,
                    this,
                    std::placeholders::_1
                )
            );


        /*
         * ============================================================
         * STEP 3-D diagnostic subscriptions
         *
         * 서로 다른 두 Subscription instance가
         * 정확히 동일한 common_callback()을 사용한다.
         * ============================================================
         */

        subscribe_instance_test_a =
            this->create_subscription<std_msgs::msg::String>(
                "/instance_test_A",
                10,
                std::bind(
                    &FeedbackloopNode::common_callback,
                    this,
                    std::placeholders::_1
                )
            );

        subscribe_instance_test_b =
            this->create_subscription<std_msgs::msg::String>(
                "/instance_test_B",
                10,
                std::bind(
                    &FeedbackloopNode::common_callback,
                    this,
                    std::placeholders::_1
                )
            );


        /*
         * execute_subscription()에서 얻는 것은
         * SubscriptionBase*이므로,
         *
         * 비교용 ground truth 역시 컴파일러가 정상적인
         * derived -> base pointer conversion을 수행하도록 한다.
         *
         * 객체 layout을 수동으로 가정하지 않는다.
         */
        rclcpp::SubscriptionBase *test_a_base =
            static_cast<rclcpp::SubscriptionBase *>(
                subscribe_instance_test_a.get()
            );

        rclcpp::SubscriptionBase *test_b_base =
            static_cast<rclcpp::SubscriptionBase *>(
                subscribe_instance_test_b.get()
            );

        RCLCPP_INFO(
            this->get_logger(),
            "INSTANCE_TEST_REGISTER A topic=/instance_test_A sub=%p",
            static_cast<void *>(test_a_base)
        );

        RCLCPP_INFO(
            this->get_logger(),
            "INSTANCE_TEST_REGISTER B topic=/instance_test_B sub=%p",
            static_cast<void *>(test_b_base)
        );


        RCLCPP_INFO(
            get_logger(),
            "loop_node started"
        );
    }


private:

    /*
     * ============================================================
     * 기존 callback A
     * ============================================================
     */

    __attribute__((noinline))
    void callback_A(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "Callback A received validated_msg : %s",
            msg->data.c_str()
        );

        // 조작된 동작 : 받은 메시지를 다시 publish
        loop_count++;

        if (loop_count > 10)
        {
            RCLCPP_WARN(
                this->get_logger(),
                "Feedback loop stopped after 10 iterations"
            );

            return;
        }

        std_msgs::msg::String new_msg;

        new_msg.data =
            "[" +
            std::to_string(loop_count) +
            "]" +
            msg->data;

        publish_validated->publish(new_msg);

        RCLCPP_WARN(
            this->get_logger(),
            "Callback A attempted to republish validated_msg : %s",
            new_msg.data.c_str()
        );
    }


    /*
     * ============================================================
     * 기존 callback B
     * ============================================================
     */

    __attribute__((noinline))
    void callback_B(
        const std_msgs::msg::String::SharedPtr msg)
    {
        loop_count = 0;

        RCLCPP_INFO(
            this->get_logger(),
            "Callback B received input_msg : %s",
            msg->data.c_str()
        );

        std_msgs::msg::String input_msg;

        input_msg.data =
            "[Validated] " + msg->data;

        publish_validated->publish(input_msg);

        RCLCPP_INFO(
            this->get_logger(),
            "Callback B attempted to publish validated_msg"
        );
    }


    /*
     * ============================================================
     * STEP 3-D
     *
     * /instance_test_A와 /instance_test_B가
     * 모두 정확히 이 하나의 callback function을 사용한다.
     *
     * publish는 하지 않는다.
     * 기존 provenance/enforcement 실험에 영향을 주지 않는다.
     * ============================================================
     */

    __attribute__((noinline))
    void common_callback(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "COMMON_CALLBACK received : %s",
            msg->data.c_str()
        );
    }


    int loop_count = 0;

    /*
     * 기존 baseline entities
     */
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr
        publish_validated;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscribe_validated;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscribe_input;


    /*
     * STEP 3-D diagnostic entities
     *
     * 서로 다른 객체지만 동일한 common_callback을 사용한다.
     */
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscribe_instance_test_a;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscribe_instance_test_b;
};


int main(int argc, char *argv[])
{
    rclcpp::init(argc, argv);

    auto node =
        std::make_shared<FeedbackloopNode>();

    rclcpp::spin(node);

    rclcpp::shutdown();

    return 0;
}