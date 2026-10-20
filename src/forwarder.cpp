#include "packetforge/cli.hpp"
// Historical name only: policy simulation observes packets and never forwards/blocks.
int main(int argc, char** argv) { return packetforge::run_cli(argc, argv, true, true); }
