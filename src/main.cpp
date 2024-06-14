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
constexpr int MAX_PACKETSIZE = 1000;  // max size of packet (actual packet size is dynamic)

void Unpack(char* pData);
void buildConnectPacket(std::vector<char>& buffer);
void UnpackCommand(char* pData);

using boost::asio::ip::udp;

class receiver
{
public:
  receiver(boost::asio::io_service& io_service,
          const boost::asio::ip::address& listen_address,
          const boost::asio::ip::address& multicast_address)
    : socket_(io_service)
    , sender_endpoint_()
    , data_(MAX_PACKETSIZE)
    , initialized_(false)
    , work_(io_service)
    , msgCount_(0)
  {
    std::cout << "Attempting to bind to: " << listen_address << std::endl;
    // Create the socket so that multiple may be bound to the same address.
    boost::asio::ip::udp::endpoint listen_endpoint(listen_address, PORT_DATA);
    socket_.open(listen_endpoint.protocol());
    socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    socket_.bind(listen_endpoint);
    // Join the multicast group.
    socket_.set_option(boost::asio::ip::multicast::join_group(multicast_address));
  }

  void initialize(const std::string& host)
  {
    try
    {
      boost::asio::io_service io_service_cmd;

      // Resolve command endpoint
      udp::resolver resolver_cmd(io_service_cmd);
      udp::endpoint endpoint_cmd = *resolver_cmd.resolve({udp::v4(), host, std::to_string(PORT_COMMAND)});

      // Build and send connect command
      std::vector<char> connectCmd;
      buildConnectPacket(connectCmd);
      socket_.send_to(boost::asio::buffer(connectCmd.data(), connectCmd.size()), endpoint_cmd);

      // Receive reply
      std::vector<char> reply(MAX_PACKETSIZE);
      udp::endpoint sender_endpoint;
      size_t reply_length = socket_.receive_from(boost::asio::buffer(reply, MAX_PACKETSIZE), sender_endpoint);

      std::cout << "Got reply, unpacking...\n";
      UnpackCommand(reply.data());

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

private:
  void do_receive()
  {
    socket_.async_receive_from(
        boost::asio::buffer(data_), sender_endpoint_,
        [this](boost::system::error_code ec, std::size_t length)
        {
          if (!ec)
          {
            // Print the time of arrival with millisecond and microsecond precision
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

            // Process received data
            //Unpack(data_.data());
            
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

  boost::asio::ip::udp::socket socket_;
  boost::asio::ip::udp::endpoint sender_endpoint_;
  std::vector<char> data_;
  bool initialized_;
  boost::asio::io_service::work work_;  // Keep io_service running
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
               boost::asio::ip::address::from_string("0.0.0.0"),  // Listen on all interfaces
               boost::asio::ip::address::from_string(MULTICAST_ADDRESS));

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