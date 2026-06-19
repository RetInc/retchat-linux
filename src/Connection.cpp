#include "Connection.hpp"

#include "PacketTypes.hpp"
#include "SystemMessages.hpp"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <random>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>
#include <fstream>

constexpr int PROTOCOL_VERSION = 1;

constexpr int KEEPALIVE_INTERVAL_SEC = 30;
constexpr int KEEPALIVE_TIMEOUT_SEC  = 10;
constexpr size_t KEY_LEN = 32;
constexpr size_t MAX_MSG_LEN = 2 * 1024 * 1024;  // 2 MB

static const char* DH_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

Connection::Connection(MessageListener& listener)
    : listener(listener)
{
    dhPrime = BN_new();
    if (!dhPrime || BN_hex2bn(&dhPrime, DH_PRIME_HEX) == 0) {
        std::cerr << "invalid DH prime" << std::endl;
        exit(1);
    }
    dhGenerator = BN_new();
    BN_set_word(dhGenerator, 2);
}

Connection::~Connection() {
    disconnect();
    if (dhPrime) BN_free(dhPrime);
    if (dhGenerator) BN_free(dhGenerator);
}

BIGNUM* Connection::generatePrivateKey() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    uint8_t bytes[32];
    for (size_t i = 0; i < 32; ++i)
        bytes[i] = dis(gen) & 0xFF;
    return BN_bin2bn(bytes, 32, nullptr);
}

BIGNUM* Connection::computePublicKey(const BIGNUM* priv) const {
    BIGNUM* pub = BN_new();
    if (!pub) return nullptr;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(pub);
        return nullptr;
    }
    if (BN_mod_exp(pub, dhGenerator, priv, dhPrime, ctx) != 1) {
        BN_free(pub);
        BN_CTX_free(ctx);
        return nullptr;
    }
    BN_CTX_free(ctx);
    return pub;
}

BIGNUM* Connection::computeSharedSecret(const BIGNUM* peerPub, const BIGNUM* priv) const {
    BIGNUM* secret = BN_new();
    if (!secret) return nullptr;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(secret);
        return nullptr;
    }
    if (BN_mod_exp(secret, peerPub, priv, dhPrime, ctx) != 1) {
        BN_free(secret);
        BN_CTX_free(ctx);
        return nullptr;
    }
    BN_CTX_free(ctx);
    return secret;
}

void Connection::deriveBaseKey(const BIGNUM* sharedSecret, uint8_t* outKey) {
    int len = BN_num_bytes(sharedSecret);
    std::vector<uint8_t> bytes(len);
    BN_bn2bin(sharedSecret, bytes.data());

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes.data(), bytes.size(), hash);
    memcpy(outKey, hash, KEY_LEN);
}

void Connection::deriveKeystream(uint64_t counter, uint8_t* out, size_t neededLen) const {
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, encKey, KEY_LEN, EVP_sha256(), nullptr);

    uint8_t counterBytes[8];
    for (int i = 0; i < 8; ++i)
        counterBytes[i] = (counter >> (i * 8)) & 0xFF;

    uint8_t digest[SHA256_DIGEST_LENGTH];
    HMAC_Update(ctx, counterBytes, 8);
    HMAC_Final(ctx, digest, nullptr);
    HMAC_CTX_free(ctx);

    size_t copied = 0;
    while (copied < neededLen) {
        size_t chunk = std::min(neededLen - copied, sizeof(digest));
        memcpy(out + copied, digest, chunk);
        copied += chunk;
        if (copied < neededLen) {
            HMAC_CTX* ctx2 = HMAC_CTX_new();
            HMAC_Init_ex(ctx2, encKey, KEY_LEN, EVP_sha256(), nullptr);
            HMAC_Update(ctx2, digest, sizeof(digest));
            HMAC_Final(ctx2, digest, nullptr);
            HMAC_CTX_free(ctx2);
        }
    }
}

void Connection::xorCrypt(uint8_t* data, size_t len, uint64_t counter) const {
    std::vector<uint8_t> keystream(len);
    deriveKeystream(counter, keystream.data(), len);
    for (size_t i = 0; i < len; ++i)
        data[i] ^= keystream[i];
}

void Connection::hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* out) const {
    HMAC(EVP_sha256(), key, (int)keyLen, data, dataLen, out, nullptr);
}

// --- connect with handshake ---

void Connection::connect(const std::string& ip, int port) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(ip.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (err) {
        listener.onSystemMessage("failed to resolve host: " + std::string(gai_strerror(err)), true);
        return;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        freeaddrinfo(res);
        listener.onSystemMessage("socket creation failed", true);
        return;
    }

    if (::connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(sockfd);
        sockfd = -1;
        listener.onSystemMessage("connection failed", true);
        return;
    }
    freeaddrinfo(res);

    // --- Diffie‑Hellman handshake ---

    BIGNUM* clientPriv = generatePrivateKey();
    BIGNUM* clientPub = computePublicKey(clientPriv);

    // read server public key length + key
    uint32_t serverPubLen;
    if (recv(sockfd, &serverPubLen, 4, MSG_WAITALL) != 4) {
        listener.onSystemMessage("handshake failed: no server public key", true);
        BN_free(clientPriv); BN_free(clientPub);
        close(sockfd); sockfd = -1;
        return;
    }
    serverPubLen = ntohl(serverPubLen);
    if (serverPubLen > 1024) {
        listener.onSystemMessage("invalid server public key length", true);
        BN_free(clientPriv); BN_free(clientPub);
        close(sockfd); sockfd = -1;
        return;
    }
    std::vector<uint8_t> serverPubBytes(serverPubLen);
    if (recv(sockfd, serverPubBytes.data(), serverPubLen, MSG_WAITALL) != (ssize_t)serverPubLen) {
        listener.onSystemMessage("handshake failed: incomplete server key", true);
        BN_free(clientPriv); BN_free(clientPub);
        close(sockfd); sockfd = -1;
        return;
    }
    BIGNUM* serverPub = BN_bin2bn(serverPubBytes.data(), serverPubLen, nullptr);

    // send client public key
    int clientPubLen = BN_num_bytes(clientPub);
    std::vector<uint8_t> clientPubBytes(clientPubLen);
    BN_bn2bin(clientPub, clientPubBytes.data());
    uint32_t netLen = htonl(clientPubLen);
    send(sockfd, &netLen, 4, 0);
    send(sockfd, clientPubBytes.data(), clientPubLen, 0);

    // compute shared secret and derive key
    BIGNUM* sharedSecret = computeSharedSecret(serverPub, clientPriv);
    deriveBaseKey(sharedSecret, encKey);

    BN_free(sharedSecret);
    BN_free(serverPub);
    BN_free(clientPriv);
    BN_free(clientPub);

    // reset counters
    sendCounter = 0;
    recvCounter = 0;

    // --- version exchange ---

    // receive handshake
    std::vector<uint8_t> plain;
    if (!receiveFrame(plain)) {
        listener.onSystemMessage("handshake: failed to receive server version", true);
        close(sockfd); sockfd = -1;
        return;
    }
    if (plain.empty() || plain[0] != static_cast<uint8_t>(PacketType::HANDSHAKE)) {
        listener.onSystemMessage("handshake: unexpected packet type", true);
        close(sockfd); sockfd = -1;
        return;
    }
    if (plain.size() < 3) {  // type + 2 bytes version
        listener.onSystemMessage("handshake: malformed version packet", true);
        close(sockfd); sockfd = -1;
        return;
    }
    uint16_t serverVersion = (plain[1] << 8) | plain[2];
    if (serverVersion != PROTOCOL_VERSION) {
        listener.onSystemMessage("server version mismatch (expected " + std::to_string(PROTOCOL_VERSION) + ", got " + std::to_string(serverVersion) + ")", true);
        close(sockfd); sockfd = -1;
        return;
    }

    // send handshake
    running.store(true);
    std::vector<uint8_t> verPayload;
    verPayload.push_back((PROTOCOL_VERSION >> 8) & 0xFF);
    verPayload.push_back((PROTOCOL_VERSION     ) & 0xFF);
    sendPacket(PacketType::HANDSHAKE, verPayload);

    // --- connection established ----

    lastReceiveTime = std::chrono::steady_clock::now();
    waitingForAck = false;
    listener.onConnected();

    // start threads
    receiverThread = std::thread(&Connection::receiveLoop, this);
    startKeepAlive();
}

void Connection::disconnect() {
    running.store(false);
    if (sockfd != -1) {
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        sockfd = -1;
    }
    if (receiverThread.joinable())
        receiverThread.join();
    if (keepAliveThread.joinable())
        keepAliveThread.join();
    listener.onDisconnected();
}


// --- frame receive helper ---

bool Connection::receiveFrame(std::vector<uint8_t>& outPlain) {
    // read HMAC
    uint8_t recvHmac[32];
    if (recv(sockfd, recvHmac, 32, MSG_WAITALL) != 32)
        return false;

    // read length
    uint32_t netLen;
    if (recv(sockfd, &netLen, 4, MSG_WAITALL) != 4)
        return false;
    size_t msgLen = ntohl(netLen);
    if (msgLen == 0 || msgLen > MAX_MSG_LEN)
        return false;

    // read ciphertext
    std::vector<uint8_t> ciphertext(msgLen);
    size_t total = 0;
    while (total < msgLen) {
        ssize_t got = recv(sockfd, ciphertext.data() + total, msgLen - total, MSG_WAITALL);
        if (got <= 0) return false;
        total += got;
    }

    // verify HMAC
    uint8_t expectedHmac[32];
    hmacSha256(encKey, KEY_LEN, ciphertext.data(), ciphertext.size(), expectedHmac);
    if (CRYPTO_memcmp(recvHmac, expectedHmac, 32) != 0)
        return false;   // tampered

    // decrypt
    xorCrypt(ciphertext.data(), ciphertext.size(), recvCounter);
    ++recvCounter;

    outPlain.swap(ciphertext);
    return true;
}

// --- sendPacket (UPDATED) ---

void Connection::sendPacket(PacketType type, const std::vector<uint8_t>& payload) {
    if (!running.load()) return;

    std::lock_guard<std::mutex> lock(sendMutex);

    std::vector<uint8_t> plaintext;
    plaintext.reserve(1 + payload.size());
    plaintext.push_back(static_cast<uint8_t>(type));
    plaintext.insert(plaintext.end(), payload.begin(), payload.end());

    // encrypt
    std::vector<uint8_t> ciphertext = plaintext;
    xorCrypt(ciphertext.data(), ciphertext.size(), sendCounter);
    ++sendCounter;

    // HMAC
    uint8_t hmac[32];
    hmacSha256(encKey, KEY_LEN, ciphertext.data(), ciphertext.size(), hmac);

    // length (4 bytes, network order)
    uint32_t len = htonl(static_cast<uint32_t>(ciphertext.size()));

    // send
    if (send(sockfd, hmac, 32, 0) != 32) throw std::runtime_error("send HMAC failed");
    if (send(sockfd, &len, 4, 0) != 4) throw std::runtime_error("send len failed");
    if (send(sockfd, ciphertext.data(), ciphertext.size(), 0) != (ssize_t)ciphertext.size())
        throw std::runtime_error("send ciphertext failed");
}


// --- public API ---

void Connection::sendNick(const std::string& newNick) {
    resetIdleTimer();
    std::vector<uint8_t> payload(newNick.begin(), newNick.end());
    payload.push_back(0);
    sendPacket(PacketType::NICK_REQUEST, payload);
}

void Connection::sendJoin(const std::string& room) {
    resetIdleTimer();
    std::vector<uint8_t> payload(room.begin(), room.end());
    payload.push_back(0);
    sendPacket(PacketType::JOIN_REQUEST, payload);
}

void Connection::sendChat(const std::string& text) {
    resetIdleTimer();
    std::vector<uint8_t> payload(text.begin(), text.end());
    payload.push_back(0);
    sendPacket(PacketType::CHAT_MSG, payload);
}

void Connection::sendDm(const std::string& targetNick, const std::string& text) {
    resetIdleTimer();
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), targetNick.begin(), targetNick.end());
    payload.push_back(0);
    payload.insert(payload.end(), text.begin(), text.end());
    payload.push_back(0);
    sendPacket(PacketType::DM_REQUEST, payload);
}

void Connection::sendImage(const std::string& target, const std::string& filepath) {
    resetIdleTimer();

    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        listener.onSystemMessage("cannot open image file: " + filepath, true);
        return;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> imageData(size);
    if (!file.read(reinterpret_cast<char*>(imageData.data()), size)) {
        listener.onSystemMessage("failed to read image file", true);
        return;
    }

    std::string mimeType = getMimeType(filepath);
    std::string fileName = filepath.substr(filepath.find_last_of("/\\") + 1);

    // build payload: target, mimeType, fileName, imageData (all null-terminated strings except imageData)
    std::vector<uint8_t> payload;
    // target
    payload.insert(payload.end(), target.begin(), target.end());
    payload.push_back(0);
    // mimeType
    payload.insert(payload.end(), mimeType.begin(), mimeType.end());
    payload.push_back(0);
    // fileName
    payload.insert(payload.end(), fileName.begin(), fileName.end());
    payload.push_back(0);
    // imageData
    payload.insert(payload.end(), imageData.begin(), imageData.end());

    sendPacket(PacketType::IMAGE_MSG, payload);
}


// --- receive loop ---

void Connection::receiveLoop() {
    try {
        while (running.load()) {
            std::vector<uint8_t> plain;
            if (!receiveFrame(plain)) break;

            resetIdleTimer();

            if (plain.empty()) continue;
            PacketType type = static_cast<PacketType>(plain[0]);
            std::vector<uint8_t> payload(plain.begin() + 1, plain.end());
            handlePacket(type, payload);
        }
    } catch (const std::exception&) {
        // ignore
    }
    running.store(false);
    listener.onDisconnected();
}


// --- handlePacket ---

void Connection::handlePacket(PacketType type, const std::vector<uint8_t>& payload) {
    size_t offset = 0;
    switch (type) {
        case PacketType::KEEPALIVE: {
            sendPacket(PacketType::KEEPALIVE_ACK, {});
            break;
        }
        case PacketType::KEEPALIVE_ACK: {
            waitingForAck = false;
            break;
        }
        case PacketType::NICK_ACK: {
            std::string nick = readString(payload.data(), offset, payload.size());
            listener.onNickChanged(nick);
            break;
        }
        case PacketType::NICK_NOTIFY: {
            std::string oldNick = readString(payload.data(), offset, payload.size());
            std::string newNick = readString(payload.data(), offset, payload.size());
            listener.onNickNotify(oldNick, newNick);
            break;
        }
        case PacketType::JOIN_ACK: {
            std::string room = readString(payload.data(), offset, payload.size());
            listener.onRoomJoined(room);
            break;
        }
        case PacketType::JOIN_NOTIFY: {
            std::string nick = readString(payload.data(), offset, payload.size());
            listener.onUserJoined(nick);
            break;
        }
        case PacketType::LEAVE_NOTIFY: {
            std::string nick = readString(payload.data(), offset, payload.size());
            listener.onUserLeft(nick);
            break;
        }
        case PacketType::CHAT_MSG: {
            std::string sender = readString(payload.data(), offset, payload.size());
            std::string text = readString(payload.data(), offset, payload.size());
            listener.onChatMessage(sender, text);
            break;
        }
        case PacketType::SYSTEM_MSG: {
            if (offset >= payload.size()) break;
            bool isError = payload[offset++] != 0;
            if (offset + 2 > payload.size()) break;
            uint16_t code = (payload[offset] << 8) | payload[offset + 1];
            offset += 2;
            if (offset >= payload.size()) break;
            uint8_t paramCount = payload[offset++];
            std::vector<std::string> params;
            for (uint8_t i = 0; i < paramCount; ++i) {
                std::string p = readString(payload.data(), offset, payload.size());
                params.push_back(p);
            }
            std::string msg = formatSystemMessage(code, params);
            listener.onSystemMessage(msg, isError);
            break;
        }
        case PacketType::DM_MSG: {
            std::string sender = readString(payload.data(), offset, payload.size());
            std::string text = readString(payload.data(), offset, payload.size());
            listener.onDirectMessage(sender, text);
            break;
        }
        case PacketType::IMAGE_MSG: {
            std::string sender = readString(payload.data(), offset, payload.size());
            std::string target = readString(payload.data(), offset, payload.size());
            std::string mimeType = readString(payload.data(), offset, payload.size());
            std::string fileName = readString(payload.data(), offset, payload.size());
            std::vector<uint8_t> imageData(payload.begin() + offset, payload.end());
            listener.onImageMessage(sender, target, mimeType, fileName, imageData);
            break;
        }
        case PacketType::KICK: {
            std::string reason = readString(payload.data(), offset, payload.size());
            listener.onKicked(reason);
            disconnect();
            break;
        }
        case PacketType::BAN: {
            std::string reason = readString(payload.data(), offset, payload.size());
            listener.onBanned(reason);
            disconnect();
            break;
        }
        case PacketType::DISCONNECT: {
            disconnect();
            break;
        }
        default:
            break;
    }
}


// --- utility ---

std::string Connection::readString(const uint8_t* data, size_t& offset, size_t maxLen) {
    size_t start = offset;
    while (offset < maxLen && data[offset] != 0)
        ++offset;
    std::string s(reinterpret_cast<const char*>(data + start), offset - start);
    if (offset < maxLen) ++offset;  // skip null
    return s;
}

std::string Connection::getMimeType(const std::string& filepath) {
    static const std::unordered_map<std::string, std::string> extMap = {
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".webp", "image/webp"},
        {".avif", "image/avif"},
        {".gif", "image/gif"},
        {".bmp", "image/bmp"}
    };
    size_t dot = filepath.find_last_of('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = filepath.substr(dot);
    auto it = extMap.find(ext);
    if (it != extMap.end()) return it->second;
    return "application/octet-stream";
}


// --- keep‑alive ---

void Connection::startKeepAlive() {
    keepAliveRunning = true;
    keepAliveThread = std::thread([this]() {
        while (running.load() && keepAliveRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(KEEPALIVE_INTERVAL_SEC));
            if (!running.load()) break;

            auto now = std::chrono::steady_clock::now();
            auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastReceiveTime).count();

            if (waitingForAck) {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastKeepAliveSent).count() > KEEPALIVE_TIMEOUT_SEC * 1000LL) {
                    listener.onSystemMessage("keepalive timeout, disconnecting", true);
                    disconnect();
                }
            } else if (idle > KEEPALIVE_INTERVAL_SEC * 1000LL) {
                try {
                    sendKeepAlive();
                } catch (...) {
                    disconnect();
                }
            }
        }
    });
}

void Connection::sendKeepAlive() {
    sendPacket(PacketType::KEEPALIVE, {});
    waitingForAck = true;
    lastKeepAliveSent = std::chrono::steady_clock::now();
}

void Connection::resetIdleTimer() {
    lastReceiveTime = std::chrono::steady_clock::now();
}