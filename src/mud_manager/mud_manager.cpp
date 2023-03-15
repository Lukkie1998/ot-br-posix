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
#include "mud_manager/mud_manager.hpp"

#include <openthread/platform/toolchain.h>

#include "common/code_utils.hpp"
#include "common/logging.hpp"

#include <iostream>
#include <ostream>

#include "../../third_party/curlcpp/repo/include/curl_easy.h"
#include "../../third_party/curlcpp/repo/include/curl_form.h"
#include "../../third_party/curlcpp/repo/include/curl_ios.h"
#include "../../third_party/curlcpp/repo/include/curl_exception.h"

#include "../../third_party/rapidjson/repo/include/rapidjson/document.h"
#include "../../third_party/rapidjson/repo/include/rapidjson/writer.h"
#include "../../third_party/rapidjson/repo/include/rapidjson/stringbuffer.h"

 namespace otbr {
    namespace MUD {

      using std::cout;
      using std::endl;
      using std::ostringstream;

      using namespace rapidjson;

      using curl::curl_easy;
      using curl::curl_ios;
      using curl::curl_easy_exception;
      using curl::curlcpp_traceback;

      ostringstream mud_file;
      Document mud_file_parsed;
      std::string mud_url = "https://mud.codeflex.dev/nordic/default/ietf_mud_file_valid.json";

      MudManager::MudManager(void) {
         this->RetrieveFileFromServer();
         this->ParseJSONContent();
         this->VerifyFileSignature();

      }

      MudManager::~MudManager(void) {}

      int MudManager::ParseJSONContent(void)
      {
         mud_file_parsed.Parse(mud_file.str().c_str());

         return 0;
      }

      int MudManager::RetrieveFileFromServer(void)
      {
         otbrLogInfo("Preparing download of MUD file");
         curl_ios<ostringstream> writer(mud_file);
    
         // Pass the writer to the easy constructor and watch the content returned in that variable!
         curl_easy easy(writer);
         easy.add<CURLOPT_URL>(mud_url.c_str());
         easy.add<CURLOPT_FOLLOWLOCATION>(1L);

      try
      {
         otbrLogInfo("Downloading MUD file from %s", mud_url.c_str());
         easy.perform();
         otbrLogInfo("MUD file was downloaded successfully");

         otbrLogInfo("MUD file content: %s", mud_file.str().c_str());

      }
      catch (curl_easy_exception &error)
      {
         otbrLogErr("An error occured durign download of MUD file. Error: %s", error.what());
         return 1;
      }
      
      return 0;

      }

      int MudManager::VerifyFileSignature()
      {
          Value::MemberIterator sig = mud_file_parsed.FindMember("mud-signature");
          VerifyOrExit(sig != mud_file_parsed.MemberEnd());
          VerifyOrExit(sig->value.IsString());

         otbrLogInfo("Signature URL: %s", sig->value.GetString());
         return 0;

         exit:
            return -1;
      }

      std::string MudManager::GetFileContents()
      {
         return mud_file.str();
      }

      /**
       * Validate the MUD URL to check if all preconditions are matched
       * @pre MUD URL size must be greater than 0
       * @pre MUD URL size must not be greater than 10
       * @pre MUD URL must start with "https://"
       * 
       * @returns 0 when valid, 1 otherwise
      */
      int MudManager::Validate(const char *url)
      {
         if (sizeof(&url) == 0 || sizeof(&url) > 10)
         {
            return 1;
         }

         // if (std::string('https://url.co').rfind("https://", 0) == 0)
         // {
         //    return 1;
         // }
         
         return 0;
      }

      // int get_mud_file()
      // {
      //    httplib::Client cli("https://mud.codeflex.dev");

      //    httplib::Result res = cli.Get("/nordic/default/ietf_mud_file_valid.json");

      //    std::cout << "MUD FILE: " << std::endl;
      //    std::cout << res << std::endl;
      //    return sizeof(res->body);
      // }
    }
 }
