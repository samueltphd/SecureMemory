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

#include "mem/secure_memory/direct_encryption.hh"

namespace gem5::memory {

DirectEncryption::DirectEncryption(const DirectEncryptionParams *p)
   : SimObject(*p),
     cpu_port(p->name + ".cpu_side", this),
     mem_port(p->name + ".mem_side", this),
     cipher_latency(p->latency * 1000), // accounts for 1GHz CPU clock
     cipherEvent([this] { cipherEngine(); }, name()),
     parallelReadRespondEvent([this] { respondParallelRead(); }, name()),
     stats(*this)
{
}

Port&
DirectEncryption::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "mem_side") {
        return mem_port;
    } else if (if_name == "cpu_side") {
        return cpu_port;
    }

    return SimObject::getPort(if_name, idx);
}

bool
DirectEncryption::handleRequest(PacketPtr pkt)
{
    if (pkt->isWrite()) {
        // need to encrypt the data prior to storage
        if (cipher_queue.size() == max_cipher_size) {
            return false;
        }

        // queue can only process one element per cycle (but pipelined) so
        // ready time is the current time + order in queue + latency
        Tick finish_time;
        if (cipher_queue.size() >= cipher_latency) {
            finish_time = curTick() + cipher_queue.size();
        } else {
            finish_time = curTick() + cipher_latency;
        }

        cipher_queue.push_back(
            std::pair<PacketPtr, Tick>(pkt, finish_time)
        );

        // if something is already in the cipher queue, it will
        // reschedule itself
        if (!cipherEvent.scheduled()) {
            // schedule for when the first item in the queue can cipher
            schedule(cipherEvent, cipher_queue.front().second);
        }
    } else {
        assert(pkt->isRead());

        if (!parallelReadAndWrite(pkt)) {
            // reads are sent to memory and decrypted on response
            mem_port.sendPacket(pkt);
        }
    }

    // stat accounting
    stats.requests_processed++;

    return true;
}

bool
DirectEncryption::handleResponse(PacketPtr pkt)
{
    assert(pkt->isResponse());

    if (pkt->isRead()) {
        // need to decrypt the data prior to sending to processor
        if (cipher_queue.size() == max_cipher_size) {
            return false;
        }

        // queue can only process one element per cycle (but pipelined) so
        // ready time is the current time + order in queue + latency
        Tick finish_time;
        if (cipher_queue.size() >= cipher_latency) {
            finish_time = curTick() + cipher_queue.size();
        } else {
            finish_time = curTick() + cipher_latency;
        }

        cipher_queue.push_back(
            std::pair<PacketPtr, Tick>(pkt, finish_time)
        );

        // if something is already in the cipher queue, it will
        // reschedule itself
        if (!cipherEvent.scheduled()) {
            // schedule for when the first item in the queue can cipher
            schedule(cipherEvent, cipher_queue.front().second);
        }
    } else {
        assert(pkt->isWrite());

        // write responses are just sent to the processor
        cpu_port.sendPacket(pkt);
    }

    // stat accounting
    stats.responses_processed++;

    return true;
}

void
DirectEncryption::cipherEngine()
{
    assert(!cipher_queue.empty());

    PacketPtr pkt = cipher_queue.front().first;
    cipher_queue.pop_front();

    if (pkt->isWrite()) {
        // doo doo doo doo ~*^%*~ the data is now encrypted!
        // send write to memory
        mem_port.sendPacket(pkt);
    } else {
        assert(pkt->isRead() && pkt->isResponse());

        // if a write has come in since we've returned from memory
        // it is now the most up to date version of the data, so use
        // that version... whoops!
        if (!parallelReadAndWrite(pkt)) {
            // doo doo doo doo ~*^%*~ the data is now decrypted!
            // return the data to the processor
            cpu_port.sendPacket(pkt);
        }
    }

    // schedule the next encryption/decryption when it is read to be executed
    if (!cipher_queue.empty() && !cipherEvent.scheduled()) {
        schedule(cipherEvent, cipher_queue.front().second);
    }
}

bool
DirectEncryption::parallelReadAndWrite(PacketPtr pkt)
{
    // check if we are currently trying to write this data to memory
    // if so, get state from pending packet as it is more up-to-date
    // (traverse back to front to get most recent version if multiple
    // pending writes)
    for (auto it = cipher_queue.rbegin();
         it != cipher_queue.rend();
         ++it)
    {
        if (it->first->getAddr() == pkt->getAddr() &&
            it->first->getSize() == pkt->getSize())
        {
            // set data to packet from pending write
            uint8_t data[pkt->getSize()]; // 64B (word size)
            it->first->writeData(data);
            pkt->setData(data);

            if (pkt->needsResponse()) {
                pkt->makeResponse();
                found_reads.push_back(pkt);

                // respond to processor in same clock cycle
                if (!parallelReadRespondEvent.scheduled()) {
                    schedule(parallelReadRespondEvent, curTick());
                }
            }

            return true;
        }
    }

    return false;
}

void
DirectEncryption::respondParallelRead()
{
    assert(!found_reads.empty());

    PacketPtr pkt = found_reads.front();
    found_reads.pop_front();

    cpu_port.sendPacket(pkt);

    if (!found_reads.empty() && !parallelReadRespondEvent.scheduled()) {
        schedule(parallelReadRespondEvent, curTick());
    }
}

// port function definitions
bool
DirectEncryption::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    if (!parent->handleRequest(pkt)) {
        need_retry++;
        return false;
    }

    return true;
}

void
DirectEncryption::CpuSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingResp(pkt)) {
        // this shouldn't happen, if so we need to implement recvRespRetry
        assert(false);

        blocked_packets.push_back(pkt);
    }

    if (!parent->mem_port.blocked_responses.empty()) {
        // serve the memory responses first
        PacketPtr blocked_mem_pkt = parent->mem_port.blocked_responses.front();
        assert(parent->handleResponse(blocked_mem_pkt)); // we should succeed
        parent->mem_port.blocked_responses.pop_front();
    } else if (need_retry) {
        // handle pending requests from processor
        sendRetryReq();
        need_retry--;
    }
}

bool
DirectEncryption::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    if (!parent->handleResponse(pkt)) {
        blocked_responses.push_back(pkt);
    }

    return true;
}

void
DirectEncryption::MemSidePort::recvReqRetry()
{
    assert(!blocked_packets.empty());
    assert(sendTimingReq(blocked_packets.front()));
    blocked_packets.pop_front();

    while (!blocked_packets.empty() &&
           sendTimingReq(blocked_packets.front()))
    {
        blocked_packets.pop_front();
    }
}

void
DirectEncryption::MemSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
    }
}

// stats function definition
DirectEncryption::DirectEncryptionStats::
DirectEncryptionStats(DirectEncryption &s)
    : statistics::Group(&s), s(s),
      ADD_STAT(requests_processed, statistics::units::Count::get(),
               "number of handled requests from the processor side"),
      ADD_STAT(responses_processed, statistics::units::Count::get(),
               "number of memory responses that we've handled")
{
}

void
DirectEncryption::DirectEncryptionStats::regStats()
{
    statistics::Group::regStats();
}

}; // namespace gem5::memory

gem5::memory::DirectEncryption *
gem5::DirectEncryptionParams::create() const
{
    return new gem5::memory::DirectEncryption(this);
}
