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

#include "mem/secure_memory/counter_mode_encryption.hh"

namespace gem5::memory {

CounterModeEncryption::
CounterModeEncryption(const CounterModeEncryptionParams *p)
   : SimObject(*p),
     cpu_port(p->name + ".cpu_side", this),
     mem_port(p->name + ".mem_side", this),
     metadata_request_port(p->name + ".metadata_request_port", this),
     metadata_response_port(p->name + ".metadata_response_port", this),
     cipher_latency(p->latency * 1000), // accounts for 1GHz CPU clock
     xor_latency(1000), // accounts for 1GHz CPU clock
     counter_arity(p->arity),
     use_metadata_cache(p->cache),
     cipherEvent([this] { cipherEngine(); }, name()),
     parallelReadRespondEvent([this] { respondParallelRead(); }, name()),
     metadataRespondEvent([this] { respondMetadataCache(); }, name()),
     stats(*this)
{
}

Port&
CounterModeEncryption::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "mem_side") {
        return mem_port;
    } else if (if_name == "cpu_side") {
        return cpu_port;
    } else if (if_name == "metadata_request_port") {
        return metadata_request_port;
    } else if (if_name == "metadata_response_port") {
        return metadata_response_port;
    }

    return SimObject::getPort(if_name, idx);
}

bool
CounterModeEncryption::isCounter(Addr addr)
{
    assert(mem_port.getAddrRanges().size() == 1);

    return addr >= mem_port.getAddrRanges().front().end();
}

Addr
CounterModeEncryption::calculateCounterAddress(Addr data_address)
{
    // get the memory size from the memory device
    AddrRangeList ranges = mem_port.getAddrRanges();
    assert(ranges.size() == 1);

    Addr start = ranges.front().start();
    Addr end = ranges.front().end();

    uint64_t word_idx = (data_address - start) / BLOCK_SIZE;
    uint64_t counter_idx = word_idx / counter_arity;

    return (counter_idx * BLOCK_SIZE) + end;
}

bool
CounterModeEncryption::handleRequest(PacketPtr pkt)
{
    if (cipher_queue.size() == max_cipher_size) {
        return false;
    }

    // create request for associated metadata
    Addr counter_addr = calculateCounterAddress(pkt->getAddr());
    RequestPtr req = std::make_shared<Request>(counter_addr, BLOCK_SIZE, 0, 0);
    PacketPtr counter_pkt = Packet::createRead(req);

    if (pkt->isWrite()) {
        // need to fetch encryption counter prior to encryption
        awaiting_counter.emplace(pkt);
    } else {
        assert(pkt->isRead());

        if (!parallelReadAndWrite(pkt)) {
            // if the encryption counter comes back first, tell it who we are
            bool success;
            std::tie(std::ignore, success) = pending_reads.emplace(
                pkt->getAddr(), 1
            );

            if (!success) {
                pending_reads[pkt->getAddr()]++;
            }

            // reads are sent to memory and decrypted on response
            mem_port.sendPacket(pkt);
        } else {
            delete counter_pkt;
            return true;
        }
    }

    // send counter request to memory
    counter_pkt->allocate();
    if (use_metadata_cache) {
        metadata_request_port.sendPacket(counter_pkt);
    } else {
        mem_port.sendPacket(counter_pkt);
    }

    // stat accounting
    stats.requests_processed++;

    return true;
}

bool
CounterModeEncryption::handleResponse(PacketPtr pkt)
{
    assert(pkt->isResponse());

    if (pkt->isRead() && !parallelReadAndWrite(pkt)) {
        // check if the counter has returned
        auto found = counter_fetched.find(pkt->getAddr());
        if (found != counter_fetched.end()) {
            // we are all set to start the decryption procedure
            if (!initiateCipher(pkt)) {
                return false;
            }

            // cipher has happened, we don't need to track
            found->second--;
            if (found->second == 0) {
                counter_fetched.erase(pkt->getAddr());
            }
        } else {
            // the counter hasn't returned from memory yet...
            // when the counter returns, tell it to initiate the cipher
            bool success;
            std::tie(std::ignore, success) = awaiting_counter.emplace(pkt);
            assert(success);
        }

        assert(pending_reads.find(pkt->getAddr()) != pending_reads.end());
        pending_reads[pkt->getAddr()]--;

        if (pending_reads[pkt->getAddr()] == 0) {
            pending_reads.erase(pkt->getAddr());
        }
    } else if (pkt->isRead()) {
        // cleanup handled by parallelReadAndWrite... do nothing!
    } else {
        assert(pkt->isWrite());

        // write responses are just sent to the processor
        cpu_port.sendPacket(pkt);
    }

    // stat accounting
    stats.responses_processed++;

    return true;
}

bool
CounterModeEncryption::handleCounterResponse(PacketPtr pkt)
{
    // check for data that uses this counter
    for (auto it = pending_reads.begin();
              it != pending_reads.end();
              ++it)
    {
        if (calculateCounterAddress(it->first) == pkt->getAddr()) {
            // move address and count from pending to fetched
            counter_fetched.emplace(it->first, it->second);
        }
    }

    // check for data that has already returned and is waiting on this counter
    for (auto it = awaiting_counter.begin();
              it != awaiting_counter.end();)
    {
        if (calculateCounterAddress((*it)->getAddr()) == pkt->getAddr()) {
            // something was waiting on this counter to do the cipher
            // try sending it for en/decryption
            if (!initiateCipher(*it)) {
                // the queue was full, move to pending state (with priority)
                pending_cipher.push_back((PacketPtr) *it);
            }

            // we are no longer waiting on this encryption counter to return
            it = awaiting_counter.erase(it);
            continue;
        }

        ++it;
    }

    // we no longer need the encryption counter
    delete pkt;

    return true;
}

bool
CounterModeEncryption::initiateCipher(PacketPtr pkt)
{
    // need to decrypt the data prior to sending to processor
    if (cipher_queue.size() == max_cipher_size) {
        return false;
    }

    // queue can only process one element per cycle (but pipelined) so
    // ready time is the current time + order in queue + latency
    // if this is data then we need to do an xor
    // if this is a counter we need to do a full cipher
    Tick finish_time;
    if (!isCounter(pkt->getAddr())) {
        if ((xor_queue.size() * 1000) >= xor_latency) {
            finish_time = curTick() + (xor_queue.size() * 1000);
        } else {
            finish_time = curTick() + xor_latency;
        }

        xor_queue.push_back(
            std::pair<PacketPtr, Tick>(pkt, finish_time)
        );
    } else {
        if ((cipher_queue.size() * 1000) >= cipher_latency) {
            finish_time = curTick() + (cipher_queue.size() * 1000);
        } else {
            finish_time = curTick() + cipher_latency;
        }

        cipher_queue.push_back(
            std::pair<PacketPtr, Tick>(pkt, finish_time)
        );
    }

    // if something is already in the cipher queue, it will
    // reschedule itself
    if (!cipherEvent.scheduled()) {
        // schedule for when the first item in the queue can cipher
        finish_time = finish_time < curTick() ? curTick() : finish_time;
        schedule(cipherEvent, finish_time);
    }

    return true;
}

void
CounterModeEncryption::cipherEngine()
{
    assert(!(cipher_queue.empty() && xor_queue.empty()));

    PacketPtr pkt;
    if (!cipher_queue.empty() && (xor_queue.empty() ||
        cipher_queue.front().second < xor_queue.front().second))
    {
        pkt = cipher_queue.front().first;
        cipher_queue.pop_front();
    } else {
        assert(!xor_queue.empty());
        pkt = xor_queue.front().first;
        xor_queue.pop_front();
    }

    AddrRangeList ranges = mem_port.getAddrRanges();
    assert(ranges.size() == 1);

    if (pkt->getAddr() >= ranges.front().end()) {
        handleCounterResponse(pkt);
    } else if (pkt->isWrite()) {
        // doo doo doo doo ~*^%*~ the data is now encrypted and the counter
        // is incremented! send write to memory
        mem_port.sendPacket(pkt);

        // store incremented encryption counter
        Addr ctr_addr = calculateCounterAddress(pkt->getAddr());
        RequestPtr req = std::make_shared<Request>(ctr_addr, BLOCK_SIZE, 0, 0);
        PacketPtr counter_pkt = Packet::createWrite(req);

        // send counter request to memory
        counter_pkt->allocate();

        if (use_metadata_cache) {
            metadata_request_port.sendPacket(counter_pkt);
        } else {
            mem_port.sendPacket(counter_pkt);
        }
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
    if (!(cipher_queue.empty() && xor_queue.empty()) &&
        !cipherEvent.scheduled())
    {
        Tick next_tick;
        if (!cipher_queue.empty() && (xor_queue.empty() ||
            cipher_queue.front().second < xor_queue.front().second))
        {
            next_tick = cipher_queue.front().second;
        } else {
            assert(!xor_queue.empty());
            next_tick = xor_queue.front().second;
        }

        next_tick = next_tick < curTick() ? curTick() : next_tick;
        schedule(cipherEvent, next_tick);
    }
}

bool
CounterModeEncryption::parallelReadAndWrite(PacketPtr pkt)
{
    bool found = false;

    // check if we are currently trying to write this data to memory
    // if so, get state from pending packet as it is more up-to-date
    // (traverse back to front to get most recent version if multiple
    // pending writes)
    // our counter is now useless to us... we found plain-text data
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

            found = true;
        }
    }

    for (auto it = awaiting_counter.rbegin();
         it != awaiting_counter.rend();
         ++it)
    {
        if ((*it)->getAddr() == pkt->getAddr() &&
            (*it)->getSize() == pkt->getSize())
        {
            // set data to packet from pending write
            uint8_t data[pkt->getSize()]; // 64B (word size)
            (*it)->writeData(data);
            pkt->setData(data);

            if (pkt->needsResponse()) {
                pkt->makeResponse();
                found_reads.push_back(pkt);

                // respond to processor in same clock cycle
                if (!parallelReadRespondEvent.scheduled()) {
                    schedule(parallelReadRespondEvent, curTick());
                }
            }

            found = true;
        }
    }

    if (found) {
        if (pending_reads.find(pkt->getAddr()) != pending_reads.end()) {
            pending_reads[pkt->getAddr()]--;

            if (pending_reads[pkt->getAddr()] == 0) {
                pending_reads.erase(pkt->getAddr());
            }
        } else if (counter_fetched.find(pkt->getAddr()) !=
                   counter_fetched.end())
        {
            counter_fetched[pkt->getAddr()]--;

            if (counter_fetched[pkt->getAddr()] == 0) {
                counter_fetched.erase(pkt->getAddr());
            }
        }
    }

    return found;
}

void
CounterModeEncryption::respondParallelRead()
{
    assert(!found_reads.empty());

    PacketPtr pkt = found_reads.front();
    found_reads.pop_front();

    cpu_port.sendPacket(pkt);

    if (!found_reads.empty() && !parallelReadRespondEvent.scheduled()) {
        schedule(parallelReadRespondEvent, curTick());
    }
}

void
CounterModeEncryption::respondMetadataCache()
{
    assert(!metadata_response_queue.empty());
    PacketPtr to_send = metadata_response_queue.front();
    metadata_response_port.sendPacket(to_send);
    metadata_response_queue.pop_front();

    // do this again if the queue is not empty
    if (!metadata_response_queue.empty() &&
        !metadataRespondEvent.scheduled())
    {
        schedule(metadataRespondEvent, curTick());
    }
}
// port function definitions
bool
CounterModeEncryption::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    if (!parent->handleRequest(pkt)) {
        need_retry++;
        return false;
    }

    return true;
}

void
CounterModeEncryption::CpuSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingResp(pkt)) {
        // this shouldn't happen, if so we need to implement recvRespRetry
        assert(false);

        blocked_packets.push_back(pkt);
    }

    if (!parent->pending_cipher.empty()) {
        // first, serve the packets that were blocked by the encryption counter
        PacketPtr blocked_enc_pkt = parent->pending_cipher.front();
        assert(parent->initiateCipher(blocked_enc_pkt));
        parent->pending_cipher.pop_front();
    } else if (!parent->mem_port.blocked_responses.empty()) {
        // serve the memory responses next
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
CounterModeEncryption::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    assert(getAddrRanges().size() == 1);
    if (pkt->getAddr() > getAddrRanges().front().end()) {
        // this is an encryption counter
        if (parent->use_metadata_cache) {
            parent->metadata_response_port.sendPacket(pkt);
        } else {
            assert(parent->initiateCipher(pkt));
        }
    } else if (!parent->handleResponse(pkt)) {
        blocked_responses.push_back(pkt); // data
    }

    return true;
}

void
CounterModeEncryption::MemSidePort::recvReqRetry()
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
CounterModeEncryption::MemSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
    }
}

bool
CounterModeEncryption::MetadataRequestPort::recvTimingResp(PacketPtr pkt)
{
    return parent->initiateCipher(pkt);
}

void
CounterModeEncryption::MetadataRequestPort::recvReqRetry()
{
    assert(!blocked_packets.empty());

    do {
        PacketPtr pkt = blocked_packets.front();
        if (sendTimingReq(pkt)) {
            blocked_packets.pop_front();
        } else {
            return;
        }
    } while (!blocked_packets.empty());
}

void
CounterModeEncryption::MetadataRequestPort::sendPacket(PacketPtr pkt)
{
    assert(pkt->isRequest());
    if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
    }
}

bool
CounterModeEncryption::MetadataResponsePort::recvTimingReq(PacketPtr pkt)
{
    assert(pkt->isRequest());
    if (pkt->isRead() || pkt->isWrite()) {
        parent->mem_port.sendPacket(pkt);
    } else {
        if (pkt->needsResponse()) {
            pkt->makeResponse();
            parent->metadata_response_queue.push_back(pkt);

            if (!parent->metadataRespondEvent.scheduled()) {
                // note, response cannot happen in the same call stack
                // so that the cache can finish managing its state
                parent->schedule(parent->metadataRespondEvent, curTick());
            }
        } else {
            delete pkt;
        }
    }

    return true;
}

void
CounterModeEncryption::MetadataResponsePort::sendPacket(PacketPtr pkt)
{
    assert(pkt->isResponse());
    if (!sendTimingResp(pkt)) {
        blocked_packets.push_back(pkt);
        need_retry++;
    }
}

// stats function definition
CounterModeEncryption::CounterModeEncryptionStats::
CounterModeEncryptionStats(CounterModeEncryption &s)
    : statistics::Group(&s), s(s),
      ADD_STAT(requests_processed, statistics::units::Count::get(),
               "number of handled requests from the processor side"),
      ADD_STAT(responses_processed, statistics::units::Count::get(),
               "number of memory responses that we've handled")
{
}

void
CounterModeEncryption::CounterModeEncryptionStats::regStats()
{
    statistics::Group::regStats();
}

}; // namespace gem5::memory

gem5::memory::CounterModeEncryption *
gem5::CounterModeEncryptionParams::create() const
{
    return new gem5::memory::CounterModeEncryption(this);
}
