#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>


enum SystemMessage : uint16_t {
    MSG_WELCOME              = 1,
    MSG_NICK_EMPTY           = 2,
    MSG_NICK_TOO_LONG        = 3,
    MSG_NICK_INVALID_CHARS   = 4,
    MSG_NICK_SAME            = 5,
    MSG_NICK_BANNED          = 6,
    MSG_NICK_TAKEN           = 7,
    MSG_JOIN_ALREADY         = 8,
    MSG_JOIN_NAME_TAKEN      = 9,
    MSG_DM_TARGET_NOT_FOUND  = 10,
    MSG_IMAGE_UNSUPPORTED    = 11,
    MSG_VERSION_MISMATCH     = 12,
};


inline std::string getSystemMessage(int id) {
    switch (id) {
        case MSG_WELCOME: return "welcome %s, you're in %s.";
        case MSG_NICK_EMPTY: return "nick cannot be empty!";
        case MSG_NICK_TOO_LONG: return "nick too long! maximum of %d characters.";
        case MSG_NICK_INVALID_CHARS: return "nick can only contain letters, numbers, dash and underscore.";
        case MSG_NICK_SAME: return "you already have that nick!";
        case MSG_NICK_BANNED: return "that nick is banned!";
        case MSG_NICK_TAKEN: return "that nick is already taken in this room!";
        case MSG_JOIN_ALREADY: return "you're already in that room!";
        case MSG_JOIN_NAME_TAKEN: return "your nick is taken in that room.";
        case MSG_DM_TARGET_NOT_FOUND: return "user \"%s\" not found";
        case MSG_IMAGE_UNSUPPORTED: return "image type unsupported: %s";
        case MSG_VERSION_MISMATCH: return "protocol version mismatch - server: %s; client: %s - try updating";
        default: return "system message: {allparams}";
    }
}


inline std::string formatSystemMessage(int code, const std::vector<std::string>& params) {
    std::string fmt = getSystemMessage(code);
    
    const std::string placeholder = "{all params}";
    size_t pos = fmt.find(placeholder);
    if (pos != std::string::npos) {
        std::ostringstream oss;
        for (size_t i = 0; i < params.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << params[i];
        }
        fmt.replace(pos, placeholder.length(), oss.str());
        return fmt;
    }
    
    std::string result;
    size_t param_idx = 0;
    size_t i = 0;
    
    while (i < fmt.size() && param_idx < params.size()) {
        if (fmt[i] == '%' && i + 1 < fmt.size() && 
            (fmt[i + 1] == 's' || fmt[i + 1] == 'd')) {
            result += params[param_idx++];
            i += 2;
        } else {
            result += fmt[i++];
        }
    }
    
    if (i < fmt.size()) {
        result += fmt.substr(i);
    }
    
    return result;
}