#pragma once

#include <cstdint>


enum class PacketType : uint8_t {
    HANDSHAKE       = 0x01,
    KEEPALIVE       = 0x02,
    KEEPALIVE_ACK   = 0x03,

    NICK_REQUEST    = 0x10,
    NICK_ACK        = 0x11,
    NICK_NOTIFY     = 0x12,
    JOIN_REQUEST    = 0x13,
    JOIN_ACK        = 0x14,
    JOIN_NOTIFY     = 0x15,
    LEAVE_NOTIFY    = 0x16,

    CHAT_MSG        = 0x20,
    SYSTEM_MSG      = 0x21,
    DM_REQUEST      = 0x22,
    DM_MSG          = 0x23,
    IMAGE_MSG       = 0x24,

    DISCONNECT      = 0x30,
    KICK            = 0x31,
    BAN             = 0x32
};