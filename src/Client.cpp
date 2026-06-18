#include "Connection.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
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

    void onImageMessage(const std::string& sender,
                        const std::string& target,
                        const std::string& mimeType,
                        const std::string& fileName,
                        const std::vector<uint8_t>& imageData) override {
        std::string label = target.empty() ? "room" : "DM from " + sender;
        print("[IMAGE] " + label + " | mime: " + mimeType +
              " | file: " + fileName + " | size: " + std::to_string(imageData.size()) + " bytes");

        // prompt user to save
        std::cout << "save image? (y/n): " << std::flush;
        std::string answer;
        std::getline(std::cin, answer);
        if (answer != "y" && answer != "Y") {
            print("[INFO] image discarded");
            return;
        }

        // generate filename
        std::string saveName = fileName;
        if (saveName.empty()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::string ext;
            if (mimeType == "image/png") ext = ".png";
            else if (mimeType == "image/jpeg") ext = ".jpg";
            else if (mimeType == "image/webp") ext = ".webp";
            else if (mimeType == "image/avif") ext = ".avif";
            else ext = ".bin";
            saveName = "image_" + std::to_string(time_t) + ext;
        } else {
            // avoid overwriting
            std::ifstream test(saveName);
            if (test.good()) {
                test.close();
                int counter = 1;
                std::string base = saveName;
                size_t dot = saveName.find_last_of('.');
                std::string ext = (dot == std::string::npos) ? "" : saveName.substr(dot);
                if (dot != std::string::npos) base = saveName.substr(0, dot);
                while (true) {
                    std::string candidate = base + "_" + std::to_string(counter) + ext;
                    std::ifstream t(candidate);
                    if (!t.good()) { saveName = candidate; break; }
                    ++counter;
                }
            }
        }

        std::ofstream out(saveName, std::ios::binary);
        if (!out) {
            print("[ERROR] could not save image to " + saveName);
            return;
        }
        out.write(reinterpret_cast<const char*>(imageData.data()), imageData.size());
        out.close();
        print("[INFO] image saved to " + saveName);
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

        } else if (cmd == "image") {
            std::string target, filepath;
            size_t sp2 = arg.find(' ');
            if (sp2 == std::string::npos) {
                filepath = arg;
                target.clear();
            } else {
                target = arg.substr(0, sp2);
                filepath = arg.substr(sp2 + 1);
                if (filepath.empty()) {
                    print("[ERROR] usage: /image (target) <filepath>");
                    return;
                }
            }
            try {
                conn.sendImage(target, filepath);
            } catch (const std::exception& e) {
                print("[ERROR] " + std::string(e.what()));
            }

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