/*
 * Copyright (c) 2012, 2014, 2017-2019, 2021 Arm Limited
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Copyright (c) 2002-2005 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Samuel Thomas, Brown University (2025)
 */

#ifndef __MEM_MAC__
#define __MEM_MAC__

#include <set>

#include "base/statistics.hh"
#include "mem/port.hh"
#include "params/MAC.hh"
#include "sim/sim_object.hh"

#define PAGE_SIZE 4096
#define BLOCK_SIZE 64

namespace gem5::memory {

class MAC : public SimObject
{
    // declare the ports so that we can have them call class functions to
    // handle requests/responses
  private:
    // note: there are also queued ports, we will implement this naively
    class CpuSidePort : public ResponsePort
    {
      private:
        MAC *parent;
        // we can decide if we want to block
        bool blocked;
        // if we receive a request while blocked, we need to notify the
        // requestor when we unblock
        uint64_t need_retry;

        // to store state from responses that we cannot send to the requestor
        // yet because they are blocked
        std::list<PacketPtr> blocked_packets;

      public:
        CpuSidePort(const std::string &name, MAC *parent)
            : ResponsePort(name),
              parent(parent),
              blocked(false),
              need_retry(0)
        {  };

      protected:
        //// Packet functions ////

        // for fast-forwarding
        Tick recvAtomic(PacketPtr pkt) override {
            return parent->mem_port.sendAtomic(pkt);
        };

        // for restoring from checkpoints
        void recvFunctional(PacketPtr pkt) override {
            parent->mem_port.sendFunctional(pkt);
        };

        // for timing (normal case)
        bool recvTimingReq(PacketPtr pkt) override; // defined in source

        void recvRespRetry() override; // defined in source

        //// auxiliary functions ////

        // for gem5 on construction, get addr ranges from memory side
        AddrRangeList getAddrRanges() const override {
            return parent->mem_port.getAddrRanges();
        };

      public:
        // wrapper for sendTimingResp that handles blocking
        void sendPacket(PacketPtr pkt); // defined in source
    };

    // note: there are also queued ports, we will implement this naively
    class MemSidePort : public RequestPort
    {
      private:
        MAC *parent;

        // to store state for requests that we cannot send to the memory device
        // if it is blocked (bandwidth saturated)
        std::list<PacketPtr> blocked_packets;

        // if we block the response (due to full buffer) we need to notify
        // the memory device when we are available
        std::list<PacketPtr> blocked_responses;

      public:
        MemSidePort(const std::string &name,
                    MAC *parent)
            : RequestPort(name),
              parent(parent)
        {  };

        friend class CpuSidePort; // so blocked memory responses have priority

        bool isSnooping() const override { return false; };

      protected:
        //// packet functions ////

        // note, atomic and functional requests do not have responses

        // for timing (normal case)
        bool recvTimingResp(PacketPtr pkt) override; // defined in source file

        // when a memory device tells us it is blocked, it will notify us here
        // if it unblocks
        void recvReqRetry() override; // defined in source file

        //// auxiliary files ////

        // this is a weird gem5-feature, but let's just forward the range to
        // the cpu side... we don't set assertions based on the address range
        void recvRangeChange() override {
            parent->cpu_port.sendRangeChange();
        };

      public:
        // wrapper for sendTimingReq that handles blocking
        void sendPacket(PacketPtr pkt); // defined in source file
    };

    // note: there are also queued ports, we will implement this naively
    class MetadataRequestPort: public RequestPort
    {
      private:
        MAC *parent;

        // to store state for requests that we cannot send to the memory device
        // if it is blocked (bandwidth saturated)
        std::list<PacketPtr> blocked_packets;

        // if we block the response (due to full buffer) we need to notify
        // the memory device when we are available
        std::list<PacketPtr> blocked_responses;

      public:
        MetadataRequestPort(const std::string &name,
                    MAC *parent)
            : RequestPort(name),
              parent(parent)
        {  };

        bool isSnooping() const override { return false; };

      protected:
        //// packet functions ////

        // note, atomic and functional requests do not have responses

        // for timing (normal case)
        bool recvTimingResp(PacketPtr pkt) override; // defined in source file

        // when a memory device tells us it is blocked, it will notify us here
        // if it unblocks
        void recvReqRetry() override; // defined in source file

        //// auxiliary files ////

        // this is a weird gem5-feature, but let's just forward the range to
        // the cpu side... we don't set assertions based on the address range
        void recvRangeChange() override {
            parent->cpu_port.sendRangeChange();
        };

      public:
        // wrapper for sendTimingReq that handles blocking
        void sendPacket(PacketPtr pkt); // defined in source file
    };

    // note: there are also queued ports, we will implement this naively
    class MetadataResponsePort : public ResponsePort
    {
      private:
        MAC *parent;
        // we can decide if we want to block
        bool blocked;
        // if we receive a request while blocked, we need to notify the
        // requestor when we unblock
        uint64_t need_retry;

        // to store state from responses that we cannot send to the requestor
        // yet because they are blocked
        std::list<PacketPtr> blocked_packets;

      public:
        MetadataResponsePort(const std::string &name, MAC *parent)
            : ResponsePort(name),
              parent(parent),
              blocked(false),
              need_retry(0)
        {  };

      protected:
        //// Packet functions ////

        // for fast-forwarding
        Tick recvAtomic(PacketPtr pkt) override {
            return parent->mem_port.sendAtomic(pkt);
        };

        // for restoring from checkpoints
        void recvFunctional(PacketPtr pkt) override {
            parent->mem_port.sendFunctional(pkt);
        };

        // for timing (normal case)
        bool recvTimingReq(PacketPtr pkt) override; // defined in source

        void recvRespRetry() override {  };

        //// auxiliary functions ////

        // for gem5 on construction, get addr ranges from memory side
        AddrRangeList getAddrRanges() const override {
            return parent->mem_port.getAddrRanges();
        };

      public:
        // wrapper for sendTimingResp that handles blocking
        void sendPacket(PacketPtr pkt); // defined in source
    };

    CpuSidePort cpu_port;
    MemSidePort mem_port;
    MetadataRequestPort metadata_request_port; // sends reqs to cache
    MetadataResponsePort metadata_response_port; // sends resps to cache

    // configurable latency to perform encryption/decryption
    uint64_t cipher_latency;
    uint64_t xor_latency;
    uint64_t hash_latency;

    // configurable arity of encryption counters/MACs
    uint64_t counter_arity;
    uint64_t mac_arity;

    // configurable use of metadata cache
    bool use_metadata_cache;
    bool cache_mac;

    // cipher engine is assumed to be pipelined, so additional latency due to
    // being "busy" is negligible, but this queue serves as the input buffer
    const uint64_t max_cipher_size = 1024;
    std::deque<std::pair<PacketPtr, Tick>> cipher_queue;
    std::deque<PacketPtr> ciphered_packets;
    std::deque<std::pair<PacketPtr, Tick>> xor_queue;

    const uint64_t max_mac_size = 1024;
    std::deque<std::pair<PacketPtr, Tick>> hashing_queue;
    std::deque<PacketPtr> hashed_packets;

    // in order to handle parallel authentications with same counter requests
    // we need to maintain a log to map counter requests to data requests
    std::map<Addr, int> pending_reads;
    std::unordered_map<Addr, int> counter_fetched;
    std::unordered_map<Addr, int> mac_fetched;

    // structure to track data requests who returned from memory before counter
    std::set<PacketPtr> awaiting_counter;
    std::set<PacketPtr> awaiting_mac;

    // structure to track when cipher queue is full
    std::deque<PacketPtr> pending_cipher;
    std::deque<PacketPtr> pending_mac;

    bool handleRequest(PacketPtr pkt); //  we will do our work here...
    bool handleResponse(PacketPtr pkt); // and here
    bool processCounterResponse(PacketPtr pkt); // and here
    bool handleCounterResponse(PacketPtr pkt); // and here
    bool handleMacResponse(PacketPtr pkt); // and here

    // this procedure gets called multiple times
    bool initiateCipher(PacketPtr pkt);
    bool initiateMac(PacketPtr pkt);

    // schedule-able function to model encryption/decryption/hashing
    void cipherEngine(); // defined in source
    void macEngine(); // defined in source
    void responseEngine(); // defined in source

    // wrapper so that gem5 can schedule cipher events at the
    // appropriate latency
    EventFunctionWrapper cipherEvent;
    EventFunctionWrapper macEvent;
    EventFunctionWrapper responseEvent;

    // if a read and write for the same address are happening in parallel
    // make sure that the read gets its data from the write req rather than the
    // memory state (coherence)

    // structure to track such reads
    std::deque<PacketPtr> found_reads;

    // function to match reads to pending writes and update the data
    bool parallelReadAndWrite(PacketPtr pkt); // defined in source

    // schedule-able function to respond to parallel reads
    void respondParallelRead(); // defined in source

    // wrapper so that gem5 can schedule responses in different call stack
    // (this is important for the LLC functionality)
    EventFunctionWrapper parallelReadRespondEvent;

    // wrapper to respond to non-read/write requests from the metadata cache
    // (i.e., invalidations, etc) and its associated structures
    std::deque<PacketPtr> metadata_response_queue;
    EventFunctionWrapper metadataRespondEvent;

    // send metadata responses (invalidates, etc) to cache
    void respondMetadataCache(); // defined in source

  public:
    MAC(const MACParams *p);

    // this is important for connecting front-end to back-end
    Port &getPort(const std::string &if_name,
                  PortID idx=InvalidPortID) override;

    bool isMetadata(Addr addr); // defined in source
    bool isCounter(Addr addr); // defined in source
    bool isMac(Addr addr); // defined in source

    // returns the address for MAC, encryption counter for associated data
    Addr calculateMacAddress(Addr data_address); // defined in source
    Addr calculateCounterAddress(Addr data_address); // defined in source

    // for stats, defined in source
    struct MACStats : public statistics::Group
    {
        MACStats(MAC &s);
        void regStats() override;

        const MAC &s;

        statistics::Scalar requests_processed;
        statistics::Scalar responses_processed;
    };

    MACStats stats;
};

};

#endif // __MEM_MAC__
