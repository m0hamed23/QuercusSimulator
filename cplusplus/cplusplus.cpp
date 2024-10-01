#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

const std::string CAMERA_IP = "10.0.0.110";
const int CAMERA_SEND_PORT = 6051;
const int CAMERA_RECEIVE_PORT = 6050;
const std::string OUTPUT_PATH = "D:\\currentimage.jpg";
const int MAX_UDP_SIZE = 65507;

std::vector<uint8_t> CreateCurrentFrameRequest() {
    std::vector<uint8_t> request(23);

    request[0] = 0x02; // STX

    int32_t unitId = 1;
    int32_t size = 23;
    uint16_t type = 72;
    uint16_t version = 0;
    int32_t id = 10;
    int32_t exposureTime = 16000;

    memcpy(&request[1], &unitId, 4);
    memcpy(&request[5], &size, 4);
    memcpy(&request[9], &type, 2);
    memcpy(&request[11], &version, 2);
    memcpy(&request[13], &id, 4);
    memcpy(&request[17], &exposureTime, 4);

    uint8_t xor_result = 0;
    for (int i = 0; i < 21; i++) {
        xor_result ^= request[i];
    }
    request[21] = xor_result; // BCC
    request[22] = 0x03; // ETX

    return request;
}

std::vector<uint8_t> ReceiveCurrentFrameResponse(SOCKET sock) {
    std::vector<uint8_t> response(MAX_UDP_SIZE);
    sockaddr_in senderAddr;
    int senderAddrSize = sizeof(senderAddr);

    int bytesReceived = recvfrom(sock, reinterpret_cast<char*>(response.data()), MAX_UDP_SIZE, 0,
        reinterpret_cast<sockaddr*>(&senderAddr), &senderAddrSize);

    if (bytesReceived < 21) {
        throw std::runtime_error("Incomplete response received");
    }

    if (response[0] != 0x02) {
        throw std::runtime_error("Invalid STX in response");
    }

    int32_t totalSize;
    uint16_t messageType;
    int32_t imageSize;

    memcpy(&totalSize, &response[5], 4);
    memcpy(&messageType, &response[9], 2);
    memcpy(&imageSize, &response[17], 4);

    if (messageType != 136) {
        throw std::runtime_error("Unexpected message type: " + std::to_string(messageType));
    }

    if (imageSize <= 0 || imageSize > MAX_UDP_SIZE) {
        throw std::runtime_error("Invalid or corrupted image size");
    }

    std::cout << "Total message size: " << totalSize << " bytes" << std::endl;
    std::cout << "Image size: " << imageSize << " bytes" << std::endl;

    if (bytesReceived < totalSize) {
        throw std::runtime_error("Incomplete message received");
    }

    std::vector<uint8_t> imageData(imageSize);
    memcpy(imageData.data(), &response[21], imageSize);

    std::cout << "Total received: " << bytesReceived << " bytes, Image saved." << std::endl;

    return imageData;
}

int main() {
    std::cout << "LPR Camera Image Capture starting..." << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    try {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }

        sockaddr_in localAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_port = htons(CAMERA_RECEIVE_PORT);
        localAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
            throw std::runtime_error("Failed to bind socket");
        }

        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        sockaddr_in remoteAddr;
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_port = htons(CAMERA_SEND_PORT);
        inet_pton(AF_INET, CAMERA_IP.c_str(), &remoteAddr.sin_addr);

        std::cout << "Sending request to camera at " << CAMERA_IP << ":" << CAMERA_SEND_PORT << std::endl;

        std::vector<uint8_t> request = CreateCurrentFrameRequest();

        auto start = std::chrono::high_resolution_clock::now();

        if (sendto(sock, reinterpret_cast<const char*>(request.data()), request.size(), 0,
            reinterpret_cast<sockaddr*>(&remoteAddr), sizeof(remoteAddr)) == SOCKET_ERROR) {
            throw std::runtime_error("Failed to send request to camera");
        }

        std::cout << "Request sent to camera" << std::endl;

        std::vector<uint8_t> imageData = ReceiveCurrentFrameResponse(sock);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << "Received " << imageData.size() << " bytes of image data" << std::endl;
        std::cout << "Image retrieval took " << duration.count() << " ms" << std::endl;

        std::filesystem::create_directories(std::filesystem::path(OUTPUT_PATH).parent_path());
        std::ofstream outFile(OUTPUT_PATH, std::ios::binary);
        outFile.write(reinterpret_cast<const char*>(imageData.data()), imageData.size());
        outFile.close();

        std::cout << "Image saved to " << OUTPUT_PATH << std::endl;

        closesocket(sock);
    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
    }

    WSACleanup();
    return 0;
}