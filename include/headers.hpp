#pragma once
// Compatibility include. PacketForge now decodes bounded bytes into host-order values.
// The original on-wire struct layouts remain in Git history at 8fd6286.
#include "packetforge/packet.hpp"
