//
// Created by the marooned on 8/16/2025.
//
#include "../../../include/openvpn/protocol/openvpn_packet.h"
#include "../../../include/utils/logger.h"

#include <sstream>
#include <iomanip>
#include <cstring>

namespace OpenVPN {
    namespace Protocol {
        OpenVPNPacket::OpenVPNPacket():
        packet_type_(PacketType::UNKNOWN),
        opcode_(0),
        key_id_(0),
        session_id_(0),
        packet_id_(0) {
        }
        OpenVPNPacket::OpenVPNPacket(const std::vector<uint8_t>& raw_data) : OpenVPNPacket() {
            parseFromRawData(raw_data);
        }

        std::unique_ptr<OpenVPNPacket> OpenVPNPacket::createControlPacket(PacketOpcode opcode, uint8_t key_id, uint64_t session_id, uint32_t packet_id, const std::vector<uint8_t> &payload) {

            auto packet = std::make_unique<OpenVPNPacket>();
            packet->packet_type_ = PacketType::CONTROL;
            packet->opcode_ = static_cast<uint8_t>(opcode);
            packet->key_id_ = key_id;
            packet->session_id_ = session_id;
            packet->packet_id_ = packet_id;
            packet->payload_ = payload;

            //logging the control packet
            Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG, "===created control packet=== \n opcode : " + std::to_string(packet->opcode_) + " , key id : " + std::to_string(packet->key_id_) + " , session id : " + std::to_string(packet->session_id_) + " , packet id : " + std::to_string(packet->packet_id_));

            return packet;
        }
        std::unique_ptr<OpenVPNPacket> OpenVPNPacket::createDataPacket(uint8_t key_id, uint32_t packet_id, std::vector<uint8_t> &payload) {
            auto packet = std::make_unique<OpenVPNPacket>();
            packet->packet_type_ = PacketType::DATA;
            packet->opcode_ = static_cast<uint8_t>(PacketOpcode::P_DATA_V2);
            packet->key_id_ = key_id;
            packet->packet_id_ = packet_id;
            packet->session_id_ = 0; //Data packet don't have session ID
            packet->payload_ = payload;

            //logging the control packet
            Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG, "=== creating data packet === \n key ID : " + std::to_string(packet->key_id_) + " , packet ID : " + std::to_string(packet->packet_id_) + "payload size : " + std::to_string(payload.size()));

            return packet;
        }

        bool OpenVPNPacket::parseFromRawData(const std::vector<uint8_t> &raw_data) {
            if (raw_data.size()<MIN_PACKET_SIZE) {
                Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "===packeet is to small:" + std::to_string(raw_data.size()) + "bytes===");
                return false;
            }
            try {
                size_t offset = 0;
                //pars header data
                PacketHeader header;
                std::memcpy(&header, raw_data.data()+offset,sizeof(PacketHeader));
                offset += sizeof(PacketHeader);

                opcode_ = header.getOpcode();
                key_id_ = header.getKeyId();
                packet_type_ = determinePacketType(opcode_);

                if (packet_type_ == PacketType::CONTROL) {
                    //pars control packet
                    if (raw_data.size() < sizeof(ControlPacketHeader)) {
                        Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "===control packet to small===");
                        return false;
                    }
                    //pars session ID (8 byte, network byte order)
                    session_id_ = 0;
                    for (int i = 0; i < 8; i++) {
                        session_id_ = (session_id_ << 8) | (raw_data[offset + i]);
                    }
                    offset += 8;
                    //pars packet ID (4 bytes , network byte order)
                    packet_id_ = 0;
                    for (int i = 0; i < 4; i++) {
                        packet_id_ = (packet_id_ << 8) | raw_data[offset + i];
                    }
                    offset += 4;
                } else if (packet_type_ == PacketType::DATA) {
                    //Data packet parsing line
                    if (raw_data.size() < sizeof(DataPacketHeader)) {
                        Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "===data packet is too small===");
                        return false;
                    }
                    session_id_ = 0; // Data packet dosent have session ID

                    //pars packet ID(4 bytes)
                    packet_id_ = 0;
                    for (int i =0; i < 4; i++) {
                        packet_id_ = (packet_id_ << 8) | raw_data[offset + i];
                    }
                    offset += 4;
                } else {
                    Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "===unknown packet type=== \n opcode :" + std::to_string(opcode_));
                    return false;
                }
                //extract payload
                if (offset < raw_data.size()) {
                    payload_.assign(raw_data.begin() + offset, raw_data.end());
                }
                Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG, "===packet parsed === \n " + toString());

                return validatePacketStructure();
            } catch (const std::exception& e) {
                Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "=== parsing failed === \n " + std::string(e.what()));
                return false;
            }
        }

        std::vector<uint8_t> OpenVPNPacket::serialize() const {
            std::vector<uint8_t> data;

            //create header
            PacketHeader header;
            header.setOpcode(opcode_);
            header.setKeyId(key_id_);

            //add header
            data.resize(sizeof(PacketHeader));
            std::memcpy(data.data(), &header, sizeof(PacketHeader));

            if (packet_type_ == PacketType::CONTROL) {
                //add session ID
                for (int i = 7; i >= 0; --i) {
                    data.push_back((session_id_ >> (i * 8)) & 0xFF);
                }
                //add packet ID
                for (int i = 3; i >= 0; --i) {
                    data.push_back((packet_id_ >> (i * 8)) & 0xFF);
                }
            } else if (packet_type_ == PacketType::DATA) {
                //add packet ID
                for (int i = 3; i >= 0; --i) {
                    data.push_back((packet_id_ >> (i * 8)) & 0xFF);
                }
            }
            //add payload
            data.insert(data.end(), payload_.begin(), payload_.end());

            Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG, "===serialized packet === \n" + std::to_string(data.size()) + " bytes");

            return data;
        }

        size_t OpenVPNPacket::getPacketSize() const {
            size_t size = sizeof(PacketHeader);

            if (packet_type_ == PacketType::CONTROL) {
                size += 4 + 8; //packet id & session ID
            } else if (packet_type_ == PacketType::DATA) {
                size += 4; //packet id
            }

            size += payload_.size();

            return size;
        }

        bool OpenVPNPacket::isValid() const {
            return validatePacketStructure();
        }

        std::string OpenVPNPacket::toString() const {
            std::ostringstream oss;

            oss << "openVPN packet [ "<< "type :" << (packet_type_ == PacketType::CONTROL ? "control": packet_type_ == PacketType::DATA? "data": "unknown") <<", opcode : "<<static_cast<int>(opcode_)<<", key id : "<<static_cast<int>(key_id_);

            if (packet_type_ == PacketType::CONTROL) {
                oss << ", session id : 0x"<< std::hex << session_id_ <<std::dec;
            }

            oss<<", packet id : "<<packet_id_<<", payload size : "<< payload_.size()<<", total size : "<<getPacketSize()<<']';

            return oss.str();
        }

        void OpenVPNPacket::clear() {
            packet_type_ = PacketType::UNKNOWN;
            packet_id_ = 0;
            session_id_ = 0;
            opcode_ = 0;
            key_id_ = 0;
            payload_.clear();
        }

        PacketType OpenVPNPacket::determinePacketType(uint8_t opcode) const {
            switch (opcode) {
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V1):
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_HARD_RESET_SERVER_V1):
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_SOFT_RESET_V1):
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_V1):
                case static_cast<uint8_t>(PacketOpcode::P_ACK_V1):
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V2):
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_HARD_RESET_SERVER_V2):
                case static_cast<uint8_t>(PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V3):
                    return PacketType::CONTROL;

                case static_cast<uint8_t>(PacketOpcode::P_DATA_V2): // there will be bug num 1
                case static_cast<uint8_t>(PacketOpcode::P_DATA_V1):
                    return PacketType::DATA;

                default:
                    return PacketType::UNKNOWN;
            }
        }

        bool OpenVPNPacket::validatePacketStructure() const {
            //check packet size limits
            size_t totalsize = getPacketSize();


            if (totalsize > MAX_PACKET_SIZE || totalsize < MIN_PACKET_SIZE) {
                Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "invalid packet size : "+ std::to_string(totalsize));
                return false;;
            }

            //check key id
            if (key_id_ > 7) {
                Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "invalid key id :"+ std::to_string(key_id_));
                return false;
            }

            //check opcode and packet type
            if (packet_type_ == PacketType::UNKNOWN) {
                Utils::Logger::getInstance().log(Utils::LogLevel::UERROR,"Unknown packet type :"+ std::to_string(opcode_));
                return false;
            }

            //check session id
            if (packet_type_ == PacketType::CONTROL && session_id_ == 0) {
                Utils::Logger::getInstance().log(Utils::LogLevel::WARNING, "zero session id for control packet");
            }

            return true;
        }

        //packet statics implementation
        void PacketStatincs::reset() {
            packet_sent = 0;
            packet_received = 0;
            bytes_sent = 0;
            bytes_received = 0;
            control_packets = 0;
            data_packets = 0;
            invalid_packets = 0;
        }

        std::string PacketStatincs::toString() const {
            std::ostringstream oss;
            oss<<"statics of packet"<<"\n";
            oss << "packet sent :" <<packet_sent <<"\n";
            oss << "packet received : "<<packet_received<<"\n";
            oss << "bytes sent : "<<bytes_sent<<"\n";
            oss << "bytes received : "<<bytes_received<<"\n";
            oss << "control packets : "<<control_packets<<"\n";
            oss << "data packets : "<<data_packets<<"\n";
            oss << "invalid packets : "<<invalid_packets<<"\n";

            return  oss.str();
        }

    }
}
