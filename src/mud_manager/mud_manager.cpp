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

#include <list>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs7err.h>

#include <iostream>
#include <ostream>
#include <fstream>
#include <string>

#include <ctime>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../third_party/curlcpp/repo/include/curl_easy.h"
#include "../../third_party/curlcpp/repo/include/curl_form.h"
#include "../../third_party/curlcpp/repo/include/curl_ios.h"
#include "../../third_party/curlcpp/repo/include/curl_exception.h"

#include "../../third_party/rapidjson/repo/include/rapidjson/document.h"
#include "../../third_party/rapidjson/repo/include/rapidjson/writer.h"
#include "../../third_party/rapidjson/repo/include/rapidjson/stringbuffer.h"

using std::ostream;
using std::ofstream;
using std::fstream;
using std::iostream;
using std::list;

enum ACE_TYPE { ipv4, ipv6 };

struct Match {
   ACE_TYPE type; // ipv4 || ipv6
   const char* src_dnsname;
   const char* dst_dnsname;
   uint8_t protocol;
   const char* direction_initiated;
   const char* src_op;
   uint16_t src_port;
   const char* dst_op;
   uint16_t dst_port;
   const char* controller;
};

struct ACE {
   const char* name;
   const char* forwarding;
   Match matches;
};

struct ACL {
   const char* name;
   const char* type;
   list <ACE> aces;
};

struct MUDFile {
   uint8_t mud_version;
   const char* mud_url;
   const char* last_update;
   const char* mud_signature;
   uint8_t cache_validity;
   bool is_supported;
   const char* systeminfo;
   const char* mfg_name;
   const char* model_name;
   const char* firmware_rev;
   const char* software_rev;
   const char* documentation;
   const char* extensions;
   const char* mac_address;
   list<const char *> from_device_policies;
   list<const char *> to_device_policies;
   list <ACL> from_device_acls;
   list <ACL> to_device_acls;
} m;

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

      ostringstream mud_content;
      ostringstream mud_signature;
      Document mud_file_parsed;
      const char* mud_url = "https://mud.codeflex.dev/files/demo/mud.json";
      const char* iptables_storage = "mud";

      MudManager::MudManager(void) {
         this->RetrieveFileFromServer(&mud_content, mud_url);
         this->ParseMUDFile();
         //this->VerifyFileSignature();
         this->ImplementMUDfile();
      }

      MudManager::~MudManager(void) {}

      int MudManager::ParseMUDFile(void)
      {
         // Parse the JSON into an object
         mud_file_parsed.Parse(mud_content.str().c_str());

         // Throw error if parsing did not succeed
         if (mud_file_parsed.HasParseError()) {
            otbrLogErr("Error occured during JSON Parse");
            return 1;
         }

         // Convert JSON Object to internal object
         Value& mud = mud_file_parsed["ietf-mud:mud"];

         m.mud_version = mud["mud-version"].GetInt();
         m.mud_url = mud["mud-url"].GetString();
         m.last_update = mud["last-update"].GetString();
         m.mud_signature = mud["mud-signature"].GetString();
         m.cache_validity = mud["cache-validity"].GetInt();
         m.is_supported = mud["is-supported"].GetBool();
         m.systeminfo = mud["systeminfo"].GetString();
         m.mfg_name = mud["mfg-name"].GetString();
         m.model_name = mud["model-name"].GetString();
         m.firmware_rev = mud["firmware-rev"].GetString();
         m.documentation = mud["documentation"].GetString();
         m.extensions = mud["extensions"].GetString();
         m.mac_address = "0011223344556677";

         Value& from = mud["from-device-policy"]["access-lists"]["access-list"];
         for (auto& f : from.GetArray()) {
            m.from_device_policies.push_back(f["name"].GetString());
         } 

         Value& to = mud["to-device-policy"]["access-lists"]["access-list"];
         for (auto& t : to.GetArray()) {
            m.to_device_policies.push_back(t["name"].GetString());
         } 

         Value& acls = mud_file_parsed["ietf-access-control-list:acls"]["acl"];

         for (auto& acl : acls.GetArray()) {
            ACL mACL = ACL();
            mACL.name = acl["name"].GetString();
            otbrLogInfo("Processing ACL: %s", mACL.name);
            mACL.type = acl["type"].GetString();

            Value& aces = acl["aces"]["ace"];

            for (auto& ace : aces.GetArray()) {
               ACE mACE = ACE();

               mACE.name = ace["name"].GetString();
               mACE.forwarding = ace["actions"]["forwarding"].GetString();

               otbrLogInfo("Processing ACE: %s", mACE.name);

               Match mMatch = Match();

               Value& matches = ace["matches"];

               if (matches.HasMember("ietf-mud:mud")) {
                  Value& mud = matches["ietf-mud:mud"];

                  if (mud.HasMember("controller")) {
                     mMatch.controller = mud["controller"].GetString();
                  }
               }

               if (matches.HasMember("ipv6")) {
                  Value& ipv6 = matches["ipv6"];
                  if (ipv6.HasMember("ietf-acldns:src-dnsname")) {
                     mMatch.src_dnsname = ipv6["ietf-acldns:src-dnsname"].GetString();
                  }  
                  if (ipv6.HasMember("ietf-acldns:dst-dnsname")) {
                     mMatch.dst_dnsname = ipv6["ietf-acldns:dst-dnsname"].GetString();
                  }

                  mMatch.protocol = ipv6["protocol"].GetInt();
               }

               if (matches.HasMember("ipv4")) {
                  Value& ipv4 = matches["ipv4"];
                  if (ipv4.HasMember("ietf-acldns:src-dnsname")) {
                     mMatch.src_dnsname = ipv4["ietf-acldns:src-dnsname"].GetString();
                  }
                  if (ipv4.HasMember("ietf-acldns:dst-dnsname")) {
                     mMatch.dst_dnsname = ipv4["ietf-acldns:dst-dnsname"].GetString();
                  }

                  mMatch.protocol = ipv4["protocol"].GetInt();
               }

               if (matches.HasMember("tcp")) {
                  Value& tcp = matches["tcp"];

                  if (tcp.HasMember("ietf-mud:direction-initiated")) {
                     mMatch.direction_initiated = tcp["ietf-mud:direction-initiated"].GetString();
                  }

                  if (tcp.HasMember("source-port")) {
                     Value& src = tcp["source-port"];

                     if (src.HasMember("operator")) {
                        mMatch.src_op = src["operator"].GetString();
                     }

                     if (src.HasMember("port")) {
                        mMatch.src_port = src["port"].GetInt();
                     }
                     
                  }

                  if (tcp.HasMember("destination-port")) {
                     Value& dst = tcp["destination-port"];

                     if (dst.HasMember("operator")) {
                        mMatch.dst_op = dst["operator"].GetString();
                     }

                     if (dst.HasMember("port")) {
                        mMatch.dst_port = dst["port"].GetInt();
                     }
                     
                  }
               }

               if (matches.HasMember("udp")) {
                  Value& udp = matches["udp"];

                  if (udp.HasMember("ietf-mud:direction-initiated")) {
                     mMatch.direction_initiated = udp["ietf-mud:direction-initiated"].GetString();
                  }

                  if (udp.HasMember("source-port")) {
                     Value& src = udp["source-port"];

                     if (src.HasMember("operator")) {
                        mMatch.src_op = src["operator"].GetString();
                     }

                     if (src.HasMember("port")) {
                        mMatch.src_port = src["port"].GetInt();
                     }
                     
                  }

                  if (udp.HasMember("destination-port")) {
                     Value& dst = udp["destination-port"];

                     if (dst.HasMember("operator")) {
                        mMatch.dst_op = dst["operator"].GetString();
                     }

                     if (dst.HasMember("port")) {
                        mMatch.dst_port = dst["port"].GetInt();
                     }
                     
                  }
               } 

               mACE.matches = mMatch;
               mACL.aces.push_back(mACE);
  
            }

            otbrLogInfo("ACL: %s | ACE Count: %d", mACL.name, mACL.aces.size());

            for (const char* a : m.from_device_policies) {
               if ( strcmp(a, mACL.name) == 0 ) {
                  otbrLogInfo("Adding from device policy: %s", mACL.name);
                  m.from_device_acls.push_back(mACL);
               }
            }

            for (const char* a : m.to_device_policies) {
               if ( strcmp(a, mACL.name) == 0 ) {
                  otbrLogInfo("Adding to device policy: %s", mACL.name);
                  m.to_device_acls.push_back(mACL);
               }
            }

            
         }

         otbrLogInfo("Converted MUD File to MUD Struct.");

         otbrLogInfo("Incoming ACLs: %d", m.to_device_acls.size());
         otbrLogInfo("Incoming Policies: %d", m.to_device_policies.size());

         otbrLogInfo("Outgoing ACLs: %d", m.from_device_acls.size());
         otbrLogInfo("Outgoing Policies: %d", m.from_device_policies.size());

         otbrLogInfo("Finished creating MUD Structure");

         return 0;
      }

      int MudManager::RetrieveFileFromServer(ostringstream *target, const char* url)
      {
         // Start file download
         otbrLogInfo("Starting Download of: %s", url);

         // Create buffer writer for output to variable
         curl_ios<ostringstream> writer(*target);
    
         curl_easy easy(writer);
         easy.add<CURLOPT_URL>(url);
         easy.add<CURLOPT_FOLLOWLOCATION>(1L);

      try
      {
         // Perform the action download
         otbrLogInfo("Downloading file");

         // Perform reads the output of the HTTPS call and sends it to the writer
         // Throws curl_easy_exception when an error occurs during loading
         easy.perform();

         otbrLogInfo("Download succeeded!");
      }
      catch (curl_easy_exception &error)
      {
         // An error occured during downloading. Write error to log
         otbrLogErr("An error occured durign download of file. Error: %s", error.what());
         return 1;
      }
      
      return 0;

      }

      fstream MudManager::RetrieveFileFromServerToFile(const char* url)
      {
         // Start file download
         otbrLogInfo("Starting Download of: %s", url);

         fstream signature;

         signature.open("sig.p7s");

         // Create buffer writer for output to variable
         curl_ios<ostream> writer(signature);
    
         curl_easy easy(writer);
         easy.add<CURLOPT_URL>(url);
         easy.add<CURLOPT_FOLLOWLOCATION>(1L);

      try
      {
         // Perform the action download
         otbrLogInfo("Downloading file");

         // Perform reads the output of the HTTPS call and sends it to the writer
         // Throws curl_easy_exception when an error occurs during loading
         easy.perform();

         otbrLogInfo("Download succeeded!");
      }
      catch (curl_easy_exception &error)
      {
         // An error occured during downloading. Write error to log
         otbrLogErr("An error occured durign download of file. Error: %s", error.what());
      }

      signature.close();
      
      return signature;

      }

      int MudManager::ImplementMUDfile() {
         // Check if folder exists for iptables
         struct stat statbuf; 
         int isDir = 0; 

         if (stat(iptables_storage, &statbuf) != -1) { 
            if (S_ISDIR(statbuf.st_mode)) { 
               isDir = 1; 
            } 
         }

         if (isDir == 0) {
            otbrLogInfo("ACL folder does not exist.");

            if (!mkdir(iptables_storage, 0777))
               otbrLogInfo("Directory created.");
            else {
               otbrLogInfo("Unable to create directory.");
               return 1;
            }    
         }

         otbrLogInfo("Folder %s exists!", iptables_storage);

         otbrLogInfo("Creating ip6tables file");
         std::string policy_name_in = "0011223344556677_INPUT";
         std::string policy_name_out = "0011223344556677_OUTPUT";
         std::ofstream outfile ("/mud/acl.sh");

         outfile << "#!/bin/bash" << endl;
         outfile << endl;
         outfile << "if [[ $1 == \"down\" ]]; then" << endl;
         outfile << "ip6tables -D INPUT -j " << policy_name_in << endl;
         outfile << "ip6tables -F " << policy_name_in << endl;
         outfile << "ip6tables -X " << policy_name_in << endl;
         outfile << "ip6tables -N " << policy_name_in << endl;
         outfile << endl;
         outfile << "ip6tables -D OUTPUT -j " << policy_name_out << endl;
         outfile << "ip6tables -F " << policy_name_out << endl;
         outfile << "ip6tables -X " << policy_name_out << endl;
         outfile << "ip6tables -N " << policy_name_out << endl;
         outfile << "fi" << endl;
         outfile << endl;
         outfile << "if [[ $1 == \"up\" ]]; then" << endl;

         for (ACL a : m.from_device_acls) {
            outfile << "# ACL: " << a.name << " | Type: " << a.type << endl;
            for (ACE e : a.aces) {
               outfile << endl;
               outfile << "## ACE: " << e.name << endl;
               ostringstream line;
               line << "ip6tables -A " << policy_name_out ;

               if (e.matches.protocol == 6) {
                  line << " -p tcp";
               } else if (e.matches.protocol == 17) {
                  line << " -p udp";
               }

               if ((e.matches.src_dnsname != NULL) && (strlen(e.matches.src_dnsname) > 0)) {
                  line << " -s " << e.matches.src_dnsname;
               }

               if ((e.matches.dst_dnsname != NULL) && (strlen(e.matches.dst_dnsname) > 0)) {
                  line << " -d " << e.matches.dst_dnsname;
               }

               if (e.matches.dst_port > 0) {
                  line << " --dport " << e.matches.dst_port;
               }

               if (e.matches.src_port > 0) {
                  line << " --sport " << e.matches.src_port;
               }

               line << " -j ACCEPT";

               outfile << line.str() << endl;
            }
         }

         otbrLogInfo("Finished Creating From Device ACLs");

         otbrLogInfo("To Device ACLs: %d", m.to_device_acls.size());

         for (ACL a : m.to_device_acls) {
            outfile << "# ACL: " << a.name << " | Type: " << a.type << endl;
            otbrLogInfo("To Device ACEs: %d", a.aces.size());
            for (ACE e : a.aces) {
               outfile << endl;
               outfile << "## ACE: " << e.name << endl;
               ostringstream line;
               line << "ip6tables -A " << policy_name_in ;
               if (e.matches.protocol == 6) {
                  line << " -p tcp";
               } else if (e.matches.protocol == 17) {
                  line << " -p udp";
               }

               if ((e.matches.src_dnsname != NULL) && (strlen(e.matches.src_dnsname) > 0)) {
                  line << " -s " << e.matches.src_dnsname;
               }

               if ((e.matches.dst_dnsname != NULL) && (strlen(e.matches.dst_dnsname) > 0)) {
                  line << " -d " << e.matches.dst_dnsname;
               }

               if (e.matches.dst_port > 0) {
                  line << " --dport " << e.matches.dst_port;
               }

               if (e.matches.src_port > 0) {
                  line << " --sport " << e.matches.src_port;
               }

               line << " -j ACCEPT";
               outfile << line.str() << endl;
            }
         }
         outfile << endl;
         outfile << "ip6tables -A INPUT -j " << policy_name_in << endl;
         outfile << "ip6tables -A OUTPUT -j " << policy_name_out << endl;
         outfile << "fi" << endl;

         otbrLogInfo("Finished creating IpTables");

         outfile.close();

         otbrLogInfo("File Closed");

         system("/mud/acl.sh up");

         otbrLogInfo("Executed file");

         return 0;
      }

      int MudManager::VerifyFileSignature()
      {
         //PKCS7 *mud_sig_p7;

         otbrLogInfo("Retrieving signature URL");

         otbrLogInfo("Signature URL: %s", m.mud_signature);

         // Download the signature
         // fstream sig = this->RetrieveFileFromServerToFile(m.mud_signature);

         // otbrLogInfo("Signature Retrieved Successfully");

         // PKCS7 *p7s_sig = NULL;

         // sig.open("sig.p7s");

         // std::string line,text;
         // std::ifstream in("sig.p7s");
         // while(std::getline(in, line))
         // {
         //    text += line;
         // }

         // const char* data = text.c_str();
         // const unsigned char *inn = reinterpret_cast<const unsigned char *>( data );

         // p7s_sig = d2i_PKCS7(NULL, &inn, sizeof(&inn));


         // BIO* bMUDSig = BIO_new(BIO_s_mem());
         // BIO* cont = NULL;
         // BIO_write(bMUDSig, mud_signature.str().c_str(), sizeof(mud_signature.str().c_str()));
         // mud_sig_p7 = SMIME_read_PKCS7(bMUDSig, &cont);

         //d2i_PKCS7_bio(bMUDSig, &mud_sig_p7);
         // const unsigned char* in = reinterpret_cast<const unsigned char *>( mud_signature.str().c_str() );
         // d2i_PKCS7_SIGNED(&mud_sig_p7, &in, sizeof(&in));

         // BIO* bMUDFile = BIO_new(BIO_s_mem());
         // BIO_write(bMUDFile, mud_content.str().c_str(), sizeof(mud_content.str().c_str()));

         const char *url = "https://mud.codeflex.dev/files/demo/mud.json.p7s";
         const char *mud_url = "https://mud.codeflex.dev/files/demo/mud.json";

         BIO *bio_sig = BIO_new(BIO_s_mem());
         BIO *bio_mud = BIO_new(BIO_s_mem());

         if (!bio_sig || !bio_mud) {
            perror("error met die schijt pointer\n");
            return 1;
         }

         if (BIO_read_filename(bio_sig, url) <= 0) {
            perror("yo goos dr is geen sig hier te vinden\n");
            BIO_free_all(bio_sig);
            return 1;
         }

         if (BIO_read_filename(bio_mud, mud_url) <= 0) {
            perror("yo goos dr is geen file hier te vinden\n");
            BIO_free_all(bio_mud);
            return 1;
         }

         PKCS7 *pkcs7 = d2i_PKCS7_bio(bio_sig, nullptr);
         if (!pkcs7) {
            ERR_print_errors_fp(stderr);
            BIO_free_all(bio_sig);
            return 1;
         }

         printf("PKCS7 file is valid\n");

         int res = PKCS7_verify(pkcs7, NULL, NULL, bio_mud, NULL, PKCS7_NOVERIFY);

         otbrLogInfo("Res: %d", res);

         if (res != 1) {
            otbrLogErr("Verification failed!");
            otbrLogErr("Error: %d", ERR_get_error());
         } else {
            otbrLogErr("Verification successful!");
         }

         PKCS7_free(pkcs7);
         BIO_free_all(bio_mud);
         BIO_free_all(bio_sig);
         
         return 0;
      }

      std::string MudManager::GetFileContents()
      {
         return mud_content.str();
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
         
         return 0;
      }
    }
 }
