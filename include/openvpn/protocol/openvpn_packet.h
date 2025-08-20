//
// Created by the marooned on 8/16/2025.
//
#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstdint>


namespace OpenVPN {
    namespace Protocol {
        // OpenVPN Protocol Constants
        constexpr uint8_t OPENVPN_VERSION = 1;
        constexpr uint8_t MAX_PACKET_SIZE = 1500;
        constexpr uint8_t MIN_PACKET_SIZE = 14;

        // OpenVPN Opcodes (Control Channel)
        enum class ControlOpcode : uint8_t {
            P_CONTROL_HARD_RESET_CLIENT_V1 = 1,
            P_CONTROL_HARD_RESET_SERVER_V1 = 2,
            P_CONTROL_SOFT_RESET_V1 = 3,
            P_CONTROL_V1 = 4,
            P_ACK_V1 = 5,
            P_DATA_V1 = 6,
            P_CONTROL_HARD_RESET_CLIENT_V2 = 7,
            P_CONTROL_HARD_RESET_SERVER_V2 = 8,
            P_CONTROL_WCK_V1 = 9,
            P_CONTROL_HARD_RESET_CLIENT_V3 = 10
        };

        //openVPN data chanel opcode
        enum class DataOpcode : uint8_t {
            P_DATA_V2 = 9
        };

        // Packet type
        enum class PacketType {
            CONTROL,
            DATA,
            UNKNOWN
        };

        //openVPN packet header structure
#pragma pack(push,1)
        struct PacketHeader {
            uint8_t opcode_key_id; //upper 5 bit opcode, lower 3 bit key id

            //helper methode
            uint8_t getOpcode() const {
                return (opcode_key_id >> 3)&0x1F;
            }
            uint8_t getKeyId() const {
                return opcode_key_id & 0x07;
            }
            void setOpcode(uint8_t opcode) {
                opcode_key_id = (opcode_key_id & 0x07) | ((opcode & 0x1F) << 3);
            }
            void setKeyId (uint8_t keyID) {
                opcode_key_id = (opcode_key_id & 0xF8) | (keyID & 0x07);
            }
        };

        //control chanel structure
        struct ControlPacketHeader {
            PacketHeader header;
            uint64_t session_id;
            uint32_t packet_id;
        };

        //data chanel header
        struct DataPacketHeader {
            PacketHeader header;
            uint32_t packet_id;
        };
#pragma pack(pop);

        //openVPN packet class
        class OpenVPNPacket {
        private:
            PacketType packet_type_;
            uint8_t opcode_;
            uint8_t key_id_;
            uint64_t session_id_;
            uint32_t packet_id_;
            std::vector<uint8_t> payload_;

            //helper methods
            PacketType determinePacketType(uint8_t opcode) const;
            bool validatePacketStructure() const;

        public:
            OpenVPNPacket();
            explicit OpenVPNPacket(const std::vector<uint8_t> raw_data);
            ~OpenVPNPacket() = default;

            //packet creation
            static std::unique_ptr<OpenVPNPacket> createControlPacket(
                ControlOpcode opcode,
                uint8_t key_id,
                uint64_t session_id,
                uint32_t packet_id,
                const std::vector<uint8_t>& payload = {}
                );
            static std::unique_ptr<OpenVPNPacket> createDataPacket(
                uint8_t key_id,
                uint32_t packet_id,
                std::vector<uint8_t>& payload
                );

            //packet parsing
            bool parseFromRawData(const std::vector<uint8_t>& raw_data);
            std::vector<uint8_t> serialize() const;

            //getters
            PacketType getPacketType() const {
                return packet_type_;
            }
            uint8_t getOpcode() const {
                return opcode_;
            }
            uint8_t getKeyId() const {
                return key_id_;
            }
            uint64_t getSessionId() const {
                return session_id_;
            }
            uint32_t getPacketId() const {
                return packet_id_;
            }
           const std::vector<uint8_t>& getPayLoad() const {
                return payload_;
            }
            size_t getPacketSize() const;

            //setters
            void setOpcode(uint8_t opcode) {
                opcode_ = opcode;
            }
            void setKeyId(uint8_t key_id) {
                key_id_ = key_id;
            }
            void setSessionId(uint64_t session_id) {
                session_id_ = session_id;
            }
            void setPacketId(uint32_t packet_id) {
                packet_id_ = packet_id;
            }
            void setPayload(const std::vector<uint8_t>& payload) {
                payload_ = payload;
            }

            //validation
            bool isValid() const;
            bool isControlPacket() const {
                return packet_type_ == PacketType::CONTROL;
            }
            bool isDataPacket() const {
                return packet_type_ == PacketType::DATA;
            }

            // utility methods
            std::string toString() const;
            void clear();
        };

        struct PacketStatincs {
            uint64_t packet_sent = 0;
            uint64_t packet_received = 0;
            uint64_t bytes_sent = 0;
            uint64_t bytes_received = 0;
            uint64_t control_packets = 0;
            uint64_t data_packets = 0;
            uint64_t invalid_packets = 0;

            void reset();
            std::string toString()const;
        };
    }
}
