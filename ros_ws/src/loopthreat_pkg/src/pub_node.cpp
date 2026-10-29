#include <chrono> //CMakeLists.txt에 별도 의존성 추가 불필요
#include <functional> //CMakeLists.txt에 별도 의존성 추가 불필요

#include <iostream>
#include <memory>
#include <string>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

class PubNode : public rclcpp::Node
{
public:
  explicit PubNode(const rclcpp::NodeOptions & options = rclcpp::NodeOptions()):Node("pub_node", options)
  {
    publisher_ = create_publisher<std_msgs::msg::String>("/input_msg", 10);
    input_timer_ = create_wall_timer(
      std::chrono::milliseconds(500),
      std::bind(&PubNode::input_callback, this));

    //RCLCPP_INFO(get_logger(), "pub_node started");
    //DDS 이벤트를 줄이기 위해 주석 처리
    diagnostics_subscription_ = create_subscription<std_msgs::msg::String>(
      "/diagnostics",
      10,
      std::bind(
        &PubNode::diagnostics_callback,
        this,
        std::placeholders::_1
      )
    );
  }
private:
  /*사용자 입력을 처리하는 callback noinline: 컴파일러가 이 함수를 다른 함수 안으로 합치지 못하도록 함.
  독립적인 함수 심볼을 유지하여 uprobe를 붙이기 쉽게 함*/
  __attribute__((noinline)) void input_callback()
  {
    std::string input;

    std::cout << "msg: " << std::flush;
    
    if (!std::getline(std::cin, input)) {
      rclcpp::shutdown();
      return;
    }

    if (input.empty()) {
      return;
    }

    std_msgs::msg::String msg;
    msg.data = input;
    
    //publisher_->publish(msg); 추적용 wrapper 함수를 호출
    monitored_publish(msg); //추적용 wrapper 함수
    
    
    //RCLCPP_INFO(get_logger(), "published msg: %s", input.c_str());
    // /input_msg DataWriter를 정확히 식별하기 위해 publish 뒤의 로그를 주석 처리
  }
  void diagnostics_callback(const std_msgs::msg::String::SharedPtr msg)
  {
    std::cout << "\n[diagnostics received] " << msg->data << std::endl;
  }
  __attribute__((noinline)) //__attribute__((noinline)) : 컴파일러에게 이 함수를 다른 함수 안으로 인라인하지 말고 독립된 함수로 유지하라고 지시하는 GCC/Clang 확장 문법
  void monitored_publish(const std_msgs::msg::String & msg)
  {
    publisher_->publish(msg);
  }
  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr
    publisher_;
  rclcpp::Subscription<std_msgs::msg::String>::SharedPtr
    diagnostics_subscription_;
  rclcpp::TimerBase::SharedPtr
    input_timer_;
};

int main(int argc, char * argv[])
{
  rclcpp::init(argc, argv);
  auto options = rclcpp::NodeOptions()
    .use_intra_process_comms(false);
  
  //rclcpp::spin(std::make_shared<PubNode>()); 아래 두 줄과 같은 기능이지만 아래는 node라는 PubNode 객체를 생성하여 재사용 가능
  auto node = std::make_shared<PubNode>(options);
  rclcpp::spin(node);

  rclcpp::shutdown();
  return 0;
}
