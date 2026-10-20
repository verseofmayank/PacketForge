#include "packetforge/cli.hpp"
// Preserve the original teaching entry point using the safe, shared pipeline.
int main(int argc, char** argv) { return packetforge::run_cli(argc, argv, true); }
