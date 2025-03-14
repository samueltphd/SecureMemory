# Copyright (c) 2012, 2014, 2017-2019, 2021 Arm Limited
# All rights reserved
#
# The license below extends only to copyright in the software and shall
# not be construed as granting a license to any other intellectual
# property including but not limited to intellectual property relating
# to a hardware implementation of the functionality of the software
# licensed hereunder.  You may use the software subject to the license
# terms below provided that you ensure that this notice is replicated
# unmodified and in its entirety in all distributions of the software,
# modified or unmodified, in source code or in binary form.
#
# Copyright (c) 2002-2005 The Regents of The University of Michigan
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: Samuel Thomas, Brown University (2025)


from m5.params import *
from m5.SimObject import SimObject


class DirectEncryption(SimObject):
    type = "DirectEncryption"
    cxx_header = "mem/secure_memory/direct_encryption.hh"
    cxx_class = "gem5::memory::DirectEncryption"

    # declare ports
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")
    mem_side = RequestPort("Mem side port, sends requests for data")

    # latency is configurable
    latency = Param.UInt64(53, "Encryption latency")


class CounterModeEncryption(SimObject):
    type = "CounterModeEncryption"
    cxx_header = "mem/secure_memory/counter_mode_encryption.hh"
    cxx_class = "gem5::memory::CounterModeEncryption"

    # declare ports
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")
    mem_side = RequestPort("Mem side port, sends requests for data")
    metadata_request_port = RequestPort(
        "Sends requests to the \
            metadata cache for metadata"
    )
    metadata_response_port = ResponsePort(
        "Sends metadata responses \
            from memory to the metadata cache"
    )

    # latency is configurable
    latency = Param.UInt64(53, "Encryption latency")

    # arity is configurable
    arity = Param.UInt64(64, "Counter arity")

    # use cache?
    cache = Param.Bool(True, "Use the metadata cache?")


class MAC(SimObject):
    type = "MAC"
    cxx_header = "mem/secure_memory/mac.hh"
    cxx_class = "gem5::memory::MAC"

    # declare ports
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")
    mem_side = RequestPort("Mem side port, sends requests for data")
    metadata_request_port = RequestPort(
        "Sends requests to the \
            metadata cache for metadata"
    )
    metadata_response_port = ResponsePort(
        "Sends metadata responses \
            from memory to the metadata cache"
    )

    # latency is configurable
    latency = Param.UInt64(53, "Encryption latency")
    hash_latency = Param.UInt64(2, "Hashing latency")

    # arity is configurable
    counter_arity = Param.UInt64(64, "Counter arity")
    mac_arity = Param.UInt64(8, "MAC arity")

    # use cache?
    cache = Param.Bool(True, "Use the metadata cache?")
    cache_mac = Param.Bool(False, "Store HMACs in metadata cache?")


class IntegrityTree(SimObject):
    type = "IntegrityTree"
    cxx_header = "mem/secure_memory/integrity_tree.hh"
    cxx_class = "gem5::memory::IntegrityTree"

    # declare ports
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")
    mem_side = RequestPort("Mem side port, sends requests for data")
    metadata_request_port = RequestPort(
        "Sends requests to the \
            metadata cache for metadata"
    )
    metadata_response_port = ResponsePort(
        "Sends metadata responses \
            from memory to the metadata cache"
    )

    # latency is configurable
    latency = Param.UInt64(53, "Encryption latency")
    hash_latency = Param.UInt64(2, "Hashing latency")

    # arity is configurable
    tree_arity = Param.UInt64(8, "Tree arity")
    counter_arity = Param.UInt64(64, "Counter arity")
    mac_arity = Param.UInt64(8, "MAC arity")

    # use cache?
    cache = Param.Bool(True, "Use the metadata cache?")
    cache_mac = Param.Bool(False, "Store HMACs in metadata cache?")

    # when to fetch parent
    eager_fetch = Param.Bool(
        True,
        "Should parent nodes be fetched as \
            soon as a miss is detected?",
    )

    # what do we protect?
    bonsai = Param.Bool(True, "BMT or standard merkle tree")
