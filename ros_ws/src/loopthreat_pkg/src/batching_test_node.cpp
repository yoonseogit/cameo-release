#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

class BatchingTestNode : public rclcpp::Node
{
public:
    BatchingTestNode()
        : Node("batching_test_node")
    {
        /*
         * Default QoS:
         *   KeepLast(100)
         *   Reliable
         *
         * qos_overriding_options를 활성화해서
         * 실행 시 reliability/depth/history를 바꿀 수 있게 한다.
         */
        rclcpp::PublisherOptions publisher_options;

        publisher_options.qos_overriding_options =
            rclcpp::QosOverridingOptions::with_default_policies();

        publisher_ =
            this->create_publisher<std_msgs::msg::String>(
                "/validated_msg",
                rclcpp::QoS(100),
                publisher_options
            );

        /*
         * A/B callback을 서로 다른 callback group에 배치.
         * MultiThreadedExecutor에서 동시에 실행 가능하게 한다.
         */
        callback_group_A_ =
            this->create_callback_group(
                rclcpp::CallbackGroupType::MutuallyExclusive
            );

        callback_group_B_ =
            this->create_callback_group(
                rclcpp::CallbackGroupType::MutuallyExclusive
            );

        rclcpp::SubscriptionOptions options_A;
        options_A.callback_group = callback_group_A_;

        rclcpp::SubscriptionOptions options_B;
        options_B.callback_group = callback_group_B_;

        subscription_A_ =
            this->create_subscription<std_msgs::msg::String>(
                "/batch_A",
                10,
                std::bind(
                    &BatchingTestNode::callback_A,
                    this,
                    std::placeholders::_1
                ),
                options_A
            );

        subscription_B_ =
            this->create_subscription<std_msgs::msg::String>(
                "/batch_B",
                10,
                std::bind(
                    &BatchingTestNode::callback_B,
                    this,
                    std::placeholders::_1
                ),
                options_B
            );

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_TEST_REGISTER A topic=/batch_A sub=%p",
            static_cast<void *>(subscription_A_.get())
        );

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_TEST_REGISTER B topic=/batch_B sub=%p",
            static_cast<void *>(subscription_B_.get())
        );

        RCLCPP_INFO(
            this->get_logger(),
            "batching_test_node started"
        );
    }

private:
    static constexpr int BURST_COUNT = 200;

    /*
     * 두 callback이 모두 준비될 때까지 기다렸다가
     * 동시에 burst publish를 시작하기 위한 barrier.
     */
    void wait_for_both_callbacks(const char * name)
    {
        const int ready =
            ready_count_.fetch_add(1) + 1;

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_%s_READY ready_count=%d",
            name,
            ready
        );

        if (ready == 2)
        {
            RCLCPP_INFO(
                this->get_logger(),
                "BATCH_BARRIER_RELEASE"
            );

            start_burst_.store(
                true,
                std::memory_order_release
            );
        }
        else
        {
            while (!start_burst_.load(
                std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    }

    __attribute__((noinline))
    void callback_A(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_A_ENTER input=%s",
            msg->data.c_str()
        );

        wait_for_both_callbacks("A");

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_A_START count=%d",
            BURST_COUNT
        );

        for (int i = 0; i < BURST_COUNT; ++i)
        {
            std_msgs::msg::String output;

            output.data =
                "A-" +
                std::to_string(i) +
                "-" +
                msg->data;

            publisher_->publish(output);

            /*
             * 다른 callback thread가 publish할 기회를 주어
             * A/B Change가 Fast DDS sender 쪽에서 섞일 가능성을 높임.
             */
            if ((i % 4) == 0)
            {
                std::this_thread::yield();
            }
        }

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_A_END"
        );
    }

    __attribute__((noinline))
    void callback_B(
        const std_msgs::msg::String::SharedPtr msg)
    {
        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_B_ENTER input=%s",
            msg->data.c_str()
        );

        wait_for_both_callbacks("B");

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_B_START count=%d",
            BURST_COUNT
        );

        for (int i = 0; i < BURST_COUNT; ++i)
        {
            std_msgs::msg::String output;

            output.data =
                "B-" +
                std::to_string(i) +
                "-" +
                msg->data;

            publisher_->publish(output);

            if ((i % 4) == 0)
            {
                std::this_thread::yield();
            }
        }

        RCLCPP_INFO(
            this->get_logger(),
            "BATCH_B_END"
        );
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr
        publisher_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscription_A_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
        subscription_B_;

    rclcpp::CallbackGroup::SharedPtr
        callback_group_A_;

    rclcpp::CallbackGroup::SharedPtr
        callback_group_B_;

    std::atomic<int> ready_count_{0};
    std::atomic<bool> start_burst_{false};
};


int main(int argc, char * argv[])
{
    rclcpp::init(argc, argv);

    auto node =
        std::make_shared<BatchingTestNode>();

    /*
     * A/B callback이 서로 다른 worker thread에서
     * 동시에 실행될 수 있도록 2-thread executor 사용.
     */
    rclcpp::executors::MultiThreadedExecutor executor(
        rclcpp::ExecutorOptions(),
        2
    );

    executor.add_node(node);
    executor.spin();

    rclcpp::shutdown();

    return 0;
}