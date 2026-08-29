// Source-derived local slice of AGIBOT DcuDriverModule::JointCmdCallback.
// It preserves the command-field, state, transform, and sink-call decisions while
// replacing AimRT/ROS transport and actuator interfaces with bounded local fakes.
#include <iostream>
#include <string>
#include <vector>

struct JointCommand {
  std::vector<std::string> name;
  std::vector<double> position;
  std::vector<double> velocity;
  std::vector<double> effort;
  std::vector<double> stiffness;
  std::vector<double> damping;
};

struct CommandState {
  double position = 0;
  double velocity = 0;
  double effort = 0;
  double kp = 0;
  double kd = 0;
};

class FakeTransmissionManager {
 public:
  void TransformJointToActuator() { ++transform_count; }
  int transform_count = 0;
};

class FakeXyberController {
 public:
  void SetMitCmd(const std::string&, double, double, double, double, double) { ++publish_count; }
  int publish_count = 0;
};

class JointCmdCallbackSlice {
 public:
  int Handle(const JointCommand& msg) {
    if (!HasParallelLengths(msg)) {
      return -1;
    }

    // Derived from the production callback's command assignment and sink loop.
    for (size_t i = 0; i < msg.name.size(); ++i) {
      CommandState data;
      data.effort = msg.effort[i];
      data.velocity = msg.velocity[i];
      data.position = msg.position[i];
      data.kp = msg.stiffness[i];
      data.kd = msg.damping[i];
      states.push_back(data);
    }

    transmission.TransformJointToActuator();
    for (size_t i = 0; i < msg.name.size(); ++i) {
      const auto& data = states[i];
      controller.SetMitCmd(msg.name[i], data.position, data.velocity, data.effort, data.kp, data.kd);
    }
    return 0;
  }

  static bool HasParallelLengths(const JointCommand& msg) {
    const size_t n = msg.name.size();
    return msg.position.size() == n && msg.velocity.size() == n && msg.effort.size() == n &&
           msg.stiffness.size() == n && msg.damping.size() == n;
  }

  FakeTransmissionManager transmission;
  FakeXyberController controller;
  std::vector<CommandState> states;
};

JointCommand Malformed() {
  JointCommand msg;
  msg.name = {"left_hip", "right_hip"};
  msg.position = {0.1};
  msg.velocity = {0.0, 0.0};
  msg.effort = {0.0, 0.0};
  msg.stiffness = {10.0, 10.0};
  msg.damping = {1.0, 1.0};
  return msg;
}

JointCommand Benign() {
  JointCommand msg;
  msg.name = {"left_hip", "right_hip"};
  msg.position = {0.1, -0.1};
  msg.velocity = {0.0, 0.0};
  msg.effort = {0.0, 0.0};
  msg.stiffness = {10.0, 10.0};
  msg.damping = {1.0, 1.0};
  return msg;
}

int main(int argc, char** argv) {
  if (argc != 2 || (std::string(argv[1]) != "malformed" && std::string(argv[1]) != "benign")) {
    std::cerr << "usage: agibot_jointcmd_callback_slice <malformed|benign>\n";
    return 2;
  }
  JointCmdCallbackSlice callback;
  const bool malformed = std::string(argv[1]) == "malformed";
  const int ret = callback.Handle(malformed ? Malformed() : Benign());
  std::cout << "ret=" << ret << " state_count=" << callback.states.size()
            << " transform_count=" << callback.transmission.transform_count
            << " fake_publish_count=" << callback.controller.publish_count << "\n";
  return ret == 0 ? 0 : 1;
}
