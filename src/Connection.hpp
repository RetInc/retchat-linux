#pragma once

#include "PacketTypes.hpp"

#include <cstdint>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <openssl/bn.h>
#include <vector>


class Client;

class MessageListener {
public:
    virtual ~MessageListener() = default;
    virtual void onConnected() = 0;
    virtual void onDisconnected() = 0;
    virtual void onSystemMessage(const std::string& text, bool isError) = 0;
    virtual void onChatMessage(const std::string& sender, const std::string& text) = 0;
    virtual void onNickChanged(const std::string& newNick) = 0;
    virtual void onNickNotify(const std::string& oldNick, const std::string& newNick) = 0;
    virtual void onRoomJoined(const std::string& roomName) = 0;
    virtual void onUserJoined(const std::string& nick) = 0;
    virtual void onUserLeft(const std::string& nick) = 0;
    virtual void onDirectMessage(const std::string& sender, const std::string& text) = 0;
    virtual void onKicked(const std::string& reason) = 0;
    virtual void onBanned(const std::string& reason) = 0;
};

class Connection {
public:
    explicit Connection(MessageListener& listener);
    ~Connection();

    // no copy
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    void connect(const std::string& ip, int port);
    void disconnect();
    bool isRunning() const { return running.load(); }

    void sendNick(const std::string& newNick);
    void sendJoin(const std::string& room);
    void sendChat(const std::string& text);
    void sendDm(const std::string& targetNick, const std::string& text);

private:
    // DH helpers
    BIGNUM* generatePrivateKey() const;
    BIGNUM* computePublicKey(const BIGNUM* priv) const;
    BIGNUM* computeSharedSecret(const BIGNUM* peerPub, const BIGNUM* priv) const;
    void deriveBaseKey(const BIGNUM* sharedSecret, uint8_t* outKey);

    // encryption / integrity
    void deriveKeystream(uint64_t counter, uint8_t* out, size_t neededLen) const;
    void xorCrypt(uint8_t* data, size_t len, uint64_t counter) const;
    void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* out) const;

    // packet I/O
    void sendPacket(PacketType type, const std::vector<uint8_t>& payload);
    void receiveLoop();
    void handlePacket(PacketType type, const std::vector<uint8_t>& payload);

    // keep‑alive
    void startKeepAlive();
    void sendKeepAlive();
    void resetIdleTimer();

    // utility
    static std::string readString(const uint8_t* data, size_t& offset, size_t maxLen);

    MessageListener& listener;

    // socket
    int sockfd = -1;

    // DH
    BIGNUM* dhPrime = nullptr;
    BIGNUM* dhGenerator = nullptr;

    // crypto
    uint8_t encKey[32]{};
    uint64_t sendCounter = 0;
    uint64_t recvCounter = 0;

    // state
    std::atomic<bool> running{false};
    std::chrono::steady_clock::time_point lastReceiveTime;
    std::chrono::steady_clock::time_point lastKeepAliveSent;
    bool waitingForAck = false;
    bool keepAliveRunning = false;

    // threads
    std::thread receiverThread;
    std::thread keepAliveThread;
    mutable std::mutex sendMutex;
};