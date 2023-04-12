/*
 *    Copyright (c) 2023, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file includes implementation of the MUD Manager.
 */

#ifndef OTBR_MUD_MANAGER_HPP_
#define OTBR_MUD_MANAGER_HPP_

#include <string>
#include <iostream>
#include <ostream>
#include <fstream>

using std::fstream;

// #include "../../third_party/cpp-httplib/repo/httplib.h"

namespace otbr {
    namespace MUD {
        class MudManager {
            public:
                /**
                 * This constructor creates a MUD Manager Object.
                 *
                 * @param[in] aNetifName  The Thread network interface name.
                 *
                 */
                MudManager(void);

                /**
                 * This destructor destroys a MUD Manager Object.
                 *
                 */
                ~MudManager(void);

                /**
                 * Retrieve a MUD File from a server
                 * 
                 * @returns A pointer to the MUD File Content
                 * 
                */
               int RetrieveFileFromServer(std::ostringstream *target, const char* url);

               fstream RetrieveFileFromServerToFile(const char* url);

               int ParseMUDFile(void);

                /**
                 * Verify the signature included in the MUD File.
                 * 
                 * @returns 0 when signature is valid, 1 when signature is invalid and -1 when no signature is available in the MUD file.
                */
               int VerifyFileSignature(void);

               int ImplementMUDfile(void);

               /**
                 * Retrieve a MUD File from a server
                 * 
                 * @returns A pointer to the MUD File Content
                 * 
                */
               std::string GetFileContents(void);


               /**
                * Validate a MUD URL according to the specification
                * 
                * @returns 0 when the URL is following specification, 1 otherwise
               */
               int Validate(const char *url);

               /**
                * Parse the MUD File Contents
               */
            //    char *Parse(char *url);
        };
    }
}

#endif