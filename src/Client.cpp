#include "Connection.hpp"

#include <atomic>
#include <csignal>
#include <getopt.h>
#include <iostream>
#include <string>
#include <thread>


class Client : public MessageListener {
public:
    Client(const std::string& ip, int port, const std::string& nick, const std::string& room)
        : ip(ip), port(port), initialNick(nick), initialRoom(room), conn(*this) {}

    void run() {
        std::thread netThread([this]() { conn.connect(ip, port); });

        std::string line;
        while (running && std::getline(std::cin, line))
            processInput(line);

        conn.disconnect();
        if (netThread.joinable()) netThread.join();
    }

    void stop() {
        running = false;
        conn.disconnect();
    }

private:
    // --- MessageListener callbacks ---

    void onConnected() override {
        print("[INFO] connected");
        if (!initialNick.empty())
            try { conn.sendNick(initialNick); } catch (...) {}
        if (!initialRoom.empty() && initialRoom != "lobby")
            try { conn.sendJoin(initialRoom); } catch (...) {}
    }

    void onDisconnected() override {
        print("[INFO] disconnected");
        running = false;
    }

    void onSystemMessage(const std::string& text, bool isError) override {
        print((isError ? "[ERROR] " : "[INFO] ") + text);
    }

    void onChatMessage(const std::string& sender, const std::string& text) override {
        print("<" + sender + "> " + text);
    }

    void onNickChanged(const std::string& newNick) override {
        currentNick = newNick;
        print("[INFO] you are now known as " + newNick);
    }

    void onNickNotify(const std::string& oldNick, const std::string& newNick) override {
        print("[INFO] " + oldNick + " is now known as " + newNick);
    }

    void onRoomJoined(const std::string& roomName) override {
        currentRoom = roomName;
        print("[INFO] joined " + roomName);
    }

    void onUserJoined(const std::string& nick) override {
        print("[INFO] " + nick + " joined");
    }

    void onUserLeft(const std::string& nick) override {
        print("[INFO] " + nick + " left");
    }

    void onDirectMessage(const std::string& sender, const std::string& text) override {
        print("[DM from " + sender + "] " + text);
    }

    void onKicked(const std::string& reason) override {
        print("[ERROR] you were kicked: " + reason);
        running = false;
    }

    void onBanned(const std::string& reason) override {
        print("[ERROR] you were banned: " + reason);
        running = false;
    }

    // --- input ---

    void processInput(const std::string& line) {
        if (line.empty()) return;

        if (line[0] != '/') {
            try {
                conn.sendChat(line);
                print("<" + (currentNick.empty() ? "you" : currentNick) + "> " + line);
            } catch (const std::exception& e) {
                print("[ERROR] " + std::string(e.what()));
            }
            return;
        }

        size_t sp = line.find(' ');
        std::string cmd = line.substr(1, sp == std::string::npos ? std::string::npos : sp - 1);
        std::string arg = sp == std::string::npos ? "" : line.substr(sp + 1);

        if (cmd == "nick") {
            if (arg.empty()) { print("[ERROR] usage: /nick <nick>"); return; }
            try { conn.sendNick(arg); }
            catch (const std::exception& e) { print("[ERROR] " + std::string(e.what())); }

        } else if (cmd == "join") {
            if (arg.empty()) { print("[ERROR] usage: /join <room>"); return; }
            try { conn.sendJoin(arg); }
            catch (const std::exception& e) { print("[ERROR] " + std::string(e.what())); }

        } else if (cmd == "dm") {
            size_t sp2 = arg.find(' ');
            if (sp2 == std::string::npos) { print("[ERROR] usage: /dm <nick> <message>"); return; }
            std::string target = arg.substr(0, sp2);
            std::string text   = arg.substr(sp2 + 1);
            if (text.empty()) { print("[ERROR] message cannot be empty"); return; }
            try {
                conn.sendDm(target, text);
                print("[DM to " + target + "] " + text);
            } catch (const std::exception& e) { print("[ERROR] " + std::string(e.what())); }

        } else if (cmd == "quit" || cmd == "exit") {
            running = false;
            conn.disconnect();

        } else {
            print("[ERROR] unknown command: /" + cmd);
        }
    }

    void print(const std::string& s) {
        std::cout << s << std::endl;
    }

    int port;
    std::string ip; 
    std::string initialNick; 
    std::string initialRoom;
    std::string currentNick;
    std::string currentRoom = "lobby";
    std::atomic<bool> running{true};
    Connection conn;
};


static Client* client = nullptr;

static void signalHandler(int) {
    if (client) { client->stop(); exit(0); }
}

int main(int argc, char** argv) {
    int port = 6677;
    std::string ip = "retucio.me";
    std::string nick, room = "lobby";

    int opt;
    while ((opt = getopt(argc, argv, "h:p:n:r:")) != -1) {
        switch (opt) {
            case 'h': ip   = optarg; break;
            case 'p': port = std::stoi(optarg); break;
            case 'n': nick = optarg; break;
            case 'r': room = optarg; break;
            default:
                std::cerr << "usage: " << argv[0]
                          << " [-h host] [-p port] [-n nick] [-r room]"
                          << std::endl;
                return 1;
        }
    }

    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);

    std::cout << "connecting to " << ip << ":" << port << "\n";
    Client client(ip, port, nick, room);
    ::client = &client;
    client.run();
    return 0;
}