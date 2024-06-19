//
// receiver.cpp
// ~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <chrono>
#include <iomanip>
#include <array>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <inttypes.h>
#include <stdio.h>

constexpr const char* MULTICAST_ADDRESS = "239.255.42.99";
constexpr int PORT_COMMAND = 1510;
constexpr int PORT_DATA = 1511;
constexpr int MAX_PACKETSIZE = 2000;  // max size of packet (actual packet size is dynamic)
constexpr int PACKET_FREQ = 240; // 240 msgs per second
constexpr int MAX_RUNTIME = 10; // 10 seconds

#define NAT_CONNECT                 0
#define NAT_RESPONSE                3
#define NAT_DISCONNECT              9
#define NAT_KEEPALIVE               10

void Unpack(char* pData);
void buildPacket(std::vector<char>& buffer, int command);
void UnpackCommand(char* pData);

using boost::asio::ip::udp;
using boost::asio::ip::address;

class receiver
{
public:
  receiver(boost::asio::io_service& io_service,
          const address& listen_address,
          const address& multicast_address)
    : socket_(io_service)
    , sender_endpoint_()
    , data_(MAX_PACKETSIZE)
    , initialized_(false)
    , io_service_(io_service)
    , work_(io_service)
    , msgCount_(0)
  {
    // Bind socket to the listen address and join multicast group
    udp::endpoint listen_endpoint(listen_address, PORT_DATA);
    socket_.open(listen_endpoint.protocol());
    socket_.set_option(udp::socket::reuse_address(true));
    socket_.bind(listen_endpoint);
    socket_.set_option(boost::asio::ip::multicast::join_group(multicast_address));
  }

  ~receiver()
  {
    close_socket();
  }

  void initialize(const std::string& host)
  {
    try
    {

      boost::asio::io_service io_service_cmd;

      // Resolve command endpoint
      udp::resolver resolver_cmd(io_service_cmd);
      command_endpoint_ = *resolver_cmd.resolve({udp::v4(), host, std::to_string(PORT_COMMAND)});

      // Build and send connect command
      send_packet(NAT_CONNECT);

      // Receive reply
      std::vector<char> reply(MAX_PACKETSIZE);
      udp::endpoint sender_endpoint;
      size_t reply_length = socket_.receive_from(boost::asio::buffer(reply, MAX_PACKETSIZE), sender_endpoint);

      std::cout << "Got reply, unpacking...\n";
      UnpackCommand(reply.data());

      // Build and send connect command
      send_packet(NAT_DISCONNECT);   

      // Set initialization flag
      initialized_ = true;
    }
    catch (std::exception& e)
    {
      std::cerr << "Initialization error: " << e.what() << std::endl;
      throw;  // Propagate exception to caller
    }
  }

  void start_receiving()
  {
    if (!initialized_)
    {
      throw std::runtime_error("Receiver is not initialized. Call initialize() first.");
    }

    // Start receiving multicast packets
    do_receive();
  }

  void close_socket()
  {
    if (socket_.is_open())
    {
      boost::system::error_code ec;
      socket_.close(ec);
      if (ec)
      {
        std::cerr << "Error closing socket: " << ec.message() << std::endl;
      }
    }
  }
private:
  void send_packet(int command)
  {
    std::vector<char> connectCmd;
    buildPacket(connectCmd, command);
    socket_.send_to(boost::asio::buffer(connectCmd.data(), connectCmd.size()), command_endpoint_);
  }

  void unpackHeader(char* ptr, int& messageID, int& nBytes, int& nBytesTotal)
  {
    // First 2 Bytes is message ID
    memcpy( &messageID, ptr, 2 );
    // Second 2 Bytes is the size of the packet
    memcpy( &nBytes, ptr + 2, 2 );
    nBytesTotal = nBytes + 4;
  }

  void do_receive()
  {
    socket_.async_receive_from(
        boost::asio::buffer(data_), sender_endpoint_,
        [this](boost::system::error_code ec, std::size_t length)
        {
          if (!ec)
          {
            // Process received data
            int messageID = 0;
            int nBytes = 0;
            int nBytesTotal = 0;
            unpackHeader(data_.data(), messageID, nBytes, nBytesTotal);

            // Check the message ID
            if (messageID == NAT_RESPONSE)
            {
              std::cout << "Received NAT_RESPONSE. Stopping IO service.\n";
              // Stop the io_service to cease further operations
              io_service_.stop();
              return;
            }

            // Print arrival time and other details
            auto arrival_time = std::chrono::high_resolution_clock::now();
            auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                arrival_time.time_since_epoch()
            );
            auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
                arrival_time.time_since_epoch()
            ) - std::chrono::duration_cast<std::chrono::microseconds>(millis);

            msgCount_++;

            // Format the output
            std::time_t now_c = std::chrono::high_resolution_clock::to_time_t(arrival_time);
            std::cout << "Packet "<< msgCount_ << " received at: " << std::put_time(std::localtime(&now_c), "%F %T")
                      << "." << std::setfill('0') << std::setw(3) << millis.count() % 1000
                      << std::setfill('0') << std::setw(3) << micros.count() % 1000 << " ms\n";

            // Process the data (Unpack and any other necessary actions)
            Unpack(data_.data());

            // Check if the packet limit has been reached
            if (msgCount_ >= PACKET_FREQ * MAX_RUNTIME)
            {
              std::cout << "Packet limit reached, reconnecting...\n";
              msgCount_ = 0;  // Reset packet count
              send_packet(NAT_KEEPALIVE);  // Let the server know to stay alive
            }

            // Continue to receive asynchronously
            do_receive();
          }
          else
          {
            // Handle error
            std::cerr << "async_receive_from error: " << ec.message() << std::endl;
          }
        });
  }


  udp::socket socket_;
  udp::endpoint sender_endpoint_;
  std::vector<char> data_;
  bool initialized_;
  boost::asio::io_service& io_service_;
  boost::asio::io_service::work work_;  // Keep io_service running
  udp::endpoint command_endpoint_;
  int msgCount_;
};

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 2)
    {
      std::cerr << "Usage: program_name <host>\n";
      return 1;
    }

    boost::asio::io_service io_service;
    receiver r(io_service,
               address::from_string("0.0.0.0"),  // Listen on all interfaces
               address::from_string(MULTICAST_ADDRESS));

    // Initialize receiver with handshake
    r.initialize(argv[1]);

    // Start receiving multicast packets
    r.start_receiving();

    // Run the IO service to handle asynchronous operations
    io_service.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << std::endl;
  }

  return 0;
}