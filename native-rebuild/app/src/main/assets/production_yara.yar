import "hash"
// Linux/Moose yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015-2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
private rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule moose_1
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2015/04/21"
        Description = "Linux/Moose malware"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/05/Dissecting-LinuxMoose.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s0 = "Status: OK"
        $s1 = "--scrypt"
        $s2 = "stratum+tcp://"
        $s3 = "cmd.so"
        $s4 = "/Challenge"
        $s7 = "processor"
        $s9 = "cpu model"
        $s21 = "password is wrong"
        $s22 = "password:"
        $s23 = "uthentication failed"
        $s24 = "sh"
        $s25 = "ps"
        $s26 = "echo -n -e "
        $s27 = "chmod"
        $s28 = "elan2"
        $s29 = "elan3"
        $s30 = "chmod: not found"
        $s31 = "cat /proc/cpuinfo"
        $s32 = "/proc/%s/cmdline"
        $s33 = "kill %s"

    condition:
        is_elf and all of them
}

rule moose_2
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2016/10/02"
        Description = "Linux/Moose malware active since September 2015"
        Reference   = "http://www.welivesecurity.com/2016/11/02/linuxmoose-still-breathing/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "Modules are loaded"
        $s2 = "--scrypt"
        $s3 = "http://"
        $s4 = "https://"
        $s5 = "processor "
        $s6 = "cpu model "
        $s7 = "Host: www.challpok.cn"
        $s8 = "Cookie: PHPSESSID=%s; nhash=%s; chash=%s"
        $s9 = "fail!"
        $s10 = "H3lL0WoRlD"
        $s11 = "crondd"
        $s12 = "cat /proc/cpuinfo"
        $s13 = "Set-Cookie: PHPSESSID="
        $s14 = "Set-Cookie: LP="
        $s15 = "Set-Cookie: WL="
        $s16 = "Set-Cookie: CP="
        $s17 = "Loading modules..."
        $s18 = "-nobg"

    condition:
        is_elf and 5 of them
}

/*
Copyright (c) 2020 ReversingLabs

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
Source: https://github.com/reversinglabs/reversinglabs-yara-rules/blob/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84/yara/trojan/Linux.Trojan.AcidRain.yara
*/
rule Linux_Trojan_AcidRain : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ACIDRAIN"
        description         = "Yara rule that detects AcidRain trojan."

        tc_detection_type   = "Trojan"
        tc_detection_name   = "AcidRain"
        tc_detection_factor = 5

    strings:

        $destroy_files_using_ioctls = {
            55 89 E5 57 BF ?? ?? ?? ?? 56 53 81 EC ?? ?? ?? ?? 89 7C 24 ?? 8B 45 ?? 89 04 24 E8
            ?? ?? ?? ?? 85 C0 89 C3 78 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ??
            8B 85 ?? ?? ?? ?? 25 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 ?? 81 C4 ?? ?? ?? ?? 5B 5E 5F 5D
            C3 8D 45 ?? BE ?? ?? ?? ?? 89 44 24 ?? 89 74 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 4D ??
            8B 55 ?? C7 45 ?? ?? ?? ?? ?? 85 C9 89 55 ?? 74 ?? 8D 75 ?? 8D B6 ?? ?? ?? ?? 8D BF
            ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 74 24 ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? B8 ?? ??
            ?? ?? 89 74 24 ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 01 D0 39 45
            ?? 89 45 ?? 77 ?? 81 FA ?? ?? ?? ?? BF ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 8B 45 ?? C7 45
            ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 75 ?? EB ?? 31 C9 89 4C 24 ?? 8B 45 ?? 89
            1C 24 89 44 24 ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 7C 24 ?? 89 1C 24 89 44 24 ?? E8
            ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 01 D0 39 45 ?? 89 45 ?? 76 ?? B8 ?? ?? ?? ?? 89 74 24
            ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 74 24 ?? 89 44 24 ?? 89 1C
            24 E8 ?? ?? ?? ?? 80 7D ?? ?? 75 ?? A1 ?? ?? ?? ?? 89 7D ?? 89 45 ?? 8B 45 ?? 89 45
            ?? 8D 45 ?? 89 44 24 ?? B8 ?? ?? ?? ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 55 ??
            8B 45 ?? 01 D0 39 45 ?? 89 45 ?? 77 ?? 8D 74 26 ?? 8D BC 27 ?? ?? ?? ?? 31 FF 89 1C
            24 E8 ?? ?? ?? ?? 31 C0 89 44 24 ?? 89 7C 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 75 ?? C7
            45 ?? ?? ?? ?? ?? 85 F6 74 ?? 8D 75 ?? 8D 76 ?? B9 ?? ?? ?? ?? 89 74 24 ?? 89 4C 24
            ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 01 D0 39 45 ?? 89 45 ?? 77 ?? 89 1C 24
            E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 5B 5E 5F 5D C3
        }

        $destroy_files_using_overwrite = {
            55 89 E5 83 EC ?? 89 5D ?? 8B 5D ?? 8D 45 ?? 89 75 ?? 89 7D ?? C7 45 ?? ?? ?? ?? ??
            C7 45 ?? ?? ?? ?? ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 5D ?? 8B 75
            ?? 8B 7D ?? 89 EC 5D C3
        }

        $redundant_reboot_attempts = {
            C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ??
            ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F
            84 ?? ?? ?? ?? 8D B6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 0F
            84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 8D 76 ?? 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 04
            24 E8 ?? ?? ?? ?? 31 D2 83 C4 ?? 89 D0 59 5B 5E 5F 5D 8D 61 ?? C3
        }

    condition:
        uint32(0) == 0x464C457F and
        (
            $destroy_files_using_ioctls
        ) and
        (
            $destroy_files_using_overwrite
        ) and
        (
            $redundant_reboot_attempts
        )
}
// KANAF_EXACT_HASH_RULES

rule Kanaf_Android_Exact_0 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.Kamran; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "016c602caf1731d2d53e7f93dd41c04b26778a65c5c27e64a2f0c2c8d5fb87e0"
}

rule Kanaf_Android_Exact_1 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0215fd18f0db2cd8cb52ff16ace70ef38b7f0ca54c7ad5979562e9787463e6dd"
}

rule Kanaf_Android_Exact_2 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "021afbc4c9ae7c4bc7499dd38c9858ba7b717d99596a41dcd5d371c93a52c2b4"
}

rule Kanaf_Android_Exact_3 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "04ce3c28a1bdd079a8d6707ea2c4b526a6ee735935dce194ce1d1f4ecc2b58ed"
}

rule Kanaf_Android_Exact_4 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
}

rule Kanaf_Android_Exact_5 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "067d5dbbd24f988f0c945a08556dec3a1c789398ae46842038ea96a9b2384427"
}

rule Kanaf_Android_Exact_6 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0757de1fd165f72a084f955dc3fe45480a92b18b6153e116d1992586ca8ccd02"
}

rule Kanaf_Android_Exact_7 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0900cc145471e3a723ed9dfb6fdc04448e08ab2d3a67eeaeb959def9e6a55fd6"
}

rule Kanaf_Android_Exact_8 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0b2fc80d5cefaffb3ec4aac13a61ac972e8aa097d03cbffc7ec8ee6a72ea45d9"
}

rule Kanaf_Android_Exact_9 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0c7afefe507ace767217dd91bdb68b06947ca668559f025425baae2afb4fff6c"
}

rule Kanaf_Android_Exact_10 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0cb41557841ff6f314c398250a165706e0b18f93674a7c12f4489018a1661673"
}

rule Kanaf_Android_Exact_11 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
}

rule Kanaf_Android_Exact_12 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
}

rule Kanaf_Android_Exact_13 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
}

rule Kanaf_Android_Exact_14 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
}

rule Kanaf_Android_Exact_15 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1499dca989bc4e3f93a50ba1c07a9760101afec0634c45f335f44d7b1f09eaef"
}

rule Kanaf_Android_Exact_16 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "162f8c6bafe0c343c37f173344c4f6880eaec0aea7b491565db874366b161784"
}

rule Kanaf_Android_Exact_17 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "17a16f08108e25af1c8b058adbaca2cada6a93c2d38c9854148f9e9caac76ac3"
}

rule Kanaf_Android_Exact_18 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1896a802cf7fb5c6a329a683c00de63715d3f802a3688bbe5d83605c89ccb651"
}

rule Kanaf_Android_Exact_19 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "19df327e7c0ffe8bd883f044c3906424cefe893d50a0d5386e8445668d2dd1e4"
}

rule Kanaf_Android_Exact_20 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1b916c486ec621fb66bd4521dddad5df69bd35c4b76a980c0b924babf566cb84"
}

rule Kanaf_Android_Exact_21 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1d126e5904dde3b46175a4aae89eec1fb8a6b80e35b1f473878e5dd288f8aae6"
}

rule Kanaf_Android_Exact_22 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1e2c03876cb0a4dfb588be0de5bffd11aff57d556dbfb8a92793470ab3c66038"
}

rule Kanaf_Android_Exact_23 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1f744fcc5b503328e8707c93f36904d17d2a71db3aa948803c98a5d54160b878"
}

rule Kanaf_Android_Exact_24 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "2014f0655875b62b563cc030eb5f57537625e377efa6ffbda35acd07017c673d"
}

rule Kanaf_Android_Exact_25 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "20505a62147fa01fd4e66fd9568725189899456083e17d9a895aeb8274290139"
}

rule Kanaf_Android_Exact_26 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
}

rule Kanaf_Android_Exact_27 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "24e3d017c22fe89c63334a3c7f26b8dafaafaf16830d0ea2f8bc9d6eb42f77cd"
}

rule Kanaf_Android_Exact_28 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "299ae5afdf4338e1e5d68656c67719346277deae20d9d013079244302040db7e"
}

rule Kanaf_Android_Exact_29 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "2ae44078807edae58fb6d383f86e6e5db62262fd7b830d7f430702bc56b5c055"
}

rule Kanaf_Android_Exact_30 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "2fdb7c4430660cb49547ac2828a631810d4e3d245a6501ce00825faa169cb7d0"
}

rule Kanaf_Android_Exact_31 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "303c6c469b00b6bf5b11fa06235c9b256bb8e7ad253787580143f78447bc6f2c"
}

rule Kanaf_Android_Exact_32 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "30b3126ef94c934fe09c6be6e2e5634ba6973e41bac18b32001a21875aad4d5f"
}

rule Kanaf_Android_Exact_33 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "35f52cb5085cc58e8d005d249bfcaa17244f1be3147780e1ac64990006db2ccc"
}

rule Kanaf_Android_Exact_34 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "370ddbbe0cf73436d2a7f288f9c91a2860a8c52393afcc8593648b117a29444e"
}

rule Kanaf_Android_Exact_35 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "3986dd1000b0da18c2f317793eb8d6739ad524d33cc568c1b23df1464f946d35"
}

rule Kanaf_Android_Exact_36 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "3fd5f5238a4098e8f3f748ca2dfbd80effadf7fe9462a35b23cfb0925b2366f6"
}

rule Kanaf_Android_Exact_37 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "40f13c6b1a5a750cc41af5f401d1772c38406c59c178dd22ad25d6513a6158bf"
}

rule Kanaf_Android_Exact_38 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "42c20ef7913d596a475c108c0ed372995ec04b5a710b0f51cfc749e409bbc625"
}

rule Kanaf_Android_Exact_39 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "42f28501f3e6be38c0ce4ff2a5bfa2dfe3c56f99ed81804de54cba3bc26a5025"
}

rule Kanaf_Android_Exact_40 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "442ab0a1b7cf99bce8f4d347f3eba2076c15533a3e1b045e944e3452b40e22fb"
}

rule Kanaf_Android_Exact_41 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "468eed1131e4b562ae32ff2734d9feb37c9b8e2097df05431867279614c8502a"
}

rule Kanaf_Android_Exact_42 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "4732c4d8e51a7bed9cfaf0d69868b0e72175a658175d219cc9d04cffa1dacf3c"
}

rule Kanaf_Android_Exact_43 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "47430361b57ffdb0384353178e5a46af50595a4adb7474fa19951c7fb7a2868f"
}

rule Kanaf_Android_Exact_44 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "49dc374870b2eada245cd6daa162defc60d05b2fc9578caea5f06107821e65b1"
}

rule Kanaf_Android_Exact_45 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.BadBazaar; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "4b524358dc37e7ffda77573bcee1c8ef9d3183f5cb67e5b19ae7e172bd60163f"
}

rule Kanaf_Android_Exact_46 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.GravityRAT; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "4ebdfa738ef74945f6165e337050889dfa0aad61115b738672bbeda648a59dab"
}

rule Kanaf_Android_Exact_47 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "4ec51c329e8dab681bc6fb89d8c25021ed2ad9949bd16391a838bde8e56540fd"
}

rule Kanaf_Android_Exact_48 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
}

rule Kanaf_Android_Exact_49 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "506e9bc94341137bdf835baa7ace980d4c9125583dd6b108d6225a07b09e78bf"
}

rule Kanaf_Android_Exact_50 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.BadBazaar; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "52ff338f0f85c32678e7f614f0ce9ceeeea9e7d9cf4ddc3abb4446a2935949f2"
}

rule Kanaf_Android_Exact_51 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "545b228aeb9e2163fa028d6ff5604e50c82779f8e9ca914b2167dd4f62440322"
}

rule Kanaf_Android_Exact_52 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.BadBazaar; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "549d726fe2b775cfdd1304c2d689dfd779731336a3143225dc3c095440f69ed0"
}

rule Kanaf_Android_Exact_53 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "55dd05f02ead336c99d491fa7a9945cf8f113215c5147710874be68fde519cd5"
}

rule Kanaf_Android_Exact_54 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5665544a8a3a1e7a7a9cfc4863bc53e829b8546fe9a7133ae15545df1667d429"
}

rule Kanaf_Android_Exact_55 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5672e8d711be744869e811ebbf90b511abf025eb1dfe2372d2e60ac4b825d3d0"
}

rule Kanaf_Android_Exact_56 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "56f139c3ac9b525bd11b02aba838d6f3f705aa2a8e681c196ff3b9684de598b6"
}

rule Kanaf_Android_Exact_57 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "585f7408c9a8e3d55fe30982d2b305b065e0eea83d8a2aac091af74aace3b015"
}

rule Kanaf_Android_Exact_58 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.BadBazaar; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "58ccc0f239241cbcd023a5eb0800786a20df9303854e6365ac66b99038c76d72"
}

rule Kanaf_Android_Exact_59 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5a4e3c5130d1c3511f35e476055f267c775265326b9ae42562cc4d959508effc"
}

rule Kanaf_Android_Exact_60 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
}

rule Kanaf_Android_Exact_61 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5c7bd08e05a26c4392c7c7c953259da78f1c760e8bcfca368f03f4d249a0ed3c"
}

rule Kanaf_Android_Exact_62 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5d5547cfe902188803301152433ceedbbf31b6f7be97141078e97d5f3c986fb4"
}

rule Kanaf_Android_Exact_63 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.GhostSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5e1cfa57771084629c2b08757f38d67f0ad28faa412090f1c6ef3fa0fd893bb3"
}

rule Kanaf_Android_Exact_64 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6290d860b12c4981180f1acba8277dcd6ff7c50b811c267b80044f32126f8055"
}

rule Kanaf_Android_Exact_65 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "64b2a100e8ca305d7362eeb4858694156d676989b8c6d6d8d01cdebe84dafc7b"
}

rule Kanaf_Android_Exact_66 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "65052115e9048ee0627d23a37dedb10c1d012c800035b7215ed76054b3ec27f6"
}

rule Kanaf_Android_Exact_67 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "65ad85202c229b138c60233c756d0953a8b0538f43e82728fc809d7345c55004"
}

rule Kanaf_Android_Exact_68 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "675bbfc32a37470a8a6804cd58a88645e7857456d7a756b020f53e41fe5e9b5a"
}

rule Kanaf_Android_Exact_69 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6a3f0bf6739ee69012b4c2b61e43a2ce7c7d9ee145b4efe0395961e08e3beac7"
}

rule Kanaf_Android_Exact_70 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
}

rule Kanaf_Android_Exact_71 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6a886a1183662f98ea593aaa6297fe6ed41af28d864f90bc69005fc58de25059"
}

rule Kanaf_Android_Exact_72 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6b326aced129c2c81dfb32fd9313363df64ba3c219038df47ba8064d8e8249f5"
}

rule Kanaf_Android_Exact_73 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6d6c5d583f415ef2496657c5418a4c7a62f0fe6a42ccdb54035c9a82d5ab3c89"
}

rule Kanaf_Android_Exact_74 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "6e3eea7fb31b8e81026021307247f6eecc5b7f97f35e900796f4786746cde3b8"
}

rule Kanaf_Android_Exact_75 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "70a44a185497df02ab80b94ec0731ea361ac54858b064c5f44a72272768a30b1"
}

rule Kanaf_Android_Exact_76 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "72419339f73fc6e62774c70085b75b3440d3268db2baa9946153d0e06445506b"
}

rule Kanaf_Android_Exact_77 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "750886cf50faa37df1b9eb4ae48af1758d35badf8269242e310ec4db1ac1d6e5"
}

rule Kanaf_Android_Exact_78 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "752d6e53a9b54783a5a37b5a2c8bc10eeeaa7af734d3f562297d4431fb5921bf"
}

rule Kanaf_Android_Exact_79 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "7aac86b914b56baebf002e4f4ab93f5145be77fe99fcba8bb2845b1058bb203e"
}

rule Kanaf_Android_Exact_80 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "80acf871a81bf657e632dd7699e7bdfa32aba9485a804fd7de39659cd5c21d89"
}

rule Kanaf_Android_Exact_81 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "81f41a2d788eb728385c6689b6664848791a10d153db3e057eb20e9d80b9ff60"
}

rule Kanaf_Android_Exact_82 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "89ea177e5043876829228a5b5f736b43b8215480ab646592be808d2708f8c9b0"
}

rule Kanaf_Android_Exact_83 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "8aa945db3e63ae8fbfae761d0490d4804799f89d285c8d92625bd2a4e14ff5d0"
}

rule Kanaf_Android_Exact_84 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "8ac3f67b558e06323e6745cc4d661a56b974cfbb7c6c07a877b84400a897eced"
}

rule Kanaf_Android_Exact_85 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
}

rule Kanaf_Android_Exact_86 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "8f8ce7916a849f58dd74069a1028a19732fc4c454b7fff84b40d4ac07d1edb7e"
}

rule Kanaf_Android_Exact_87 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "9115408ab7227f30cb6d3f785c208377b31da208171def1c3ec4d81c6f833585"
}

rule Kanaf_Android_Exact_88 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "914b290675a688bb63ff147104b170afffd1c20e602ede16c45e40d03381ea7d"
}

rule Kanaf_Android_Exact_89 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "92e857fb3abad1b193dfeb61141b46f017aae585483aef09aff01e085e2bfb4a"
}

rule Kanaf_Android_Exact_90 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "95d906dca5a3be5cf066268662b3c953860e54e9cdcfcd427faf0aaa9cb62bad"
}

rule Kanaf_Android_Exact_91 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "97c1ede53312b5efc3f9e929cdcef4fee9ae54ed9123a256df85c1ac901922f5"
}

rule Kanaf_Android_Exact_92 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "98b7488b1a18cb0c5e360c06f0c94d19a5230b7b15d0616856354fb64929b388"
}

rule Kanaf_Android_Exact_93 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
}

rule Kanaf_Android_Exact_94 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
}

rule Kanaf_Android_Exact_95 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "9eb13898532f4521961c5a5a1382cd0b96dfe40196371628b1792678b900b6db"
}

rule Kanaf_Android_Exact_96 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "a4e74f74e675a08fdf8e0b55d5da59af8f1c67a2820c97ba6c6790b29589663d"
}

rule Kanaf_Android_Exact_97 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "a5ff50af0df415ead7646107e6501961ada8bfbe1cd49284e3d14f55e7d88784"
}

rule Kanaf_Android_Exact_98 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "a60c98cd3e6f26c3f7e77c95fe6a801d664f7cfa1d062f6e3b6fe5afcd3d563f"
}

rule Kanaf_Android_Exact_99 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "a6a6667d99d6d8dced329ce6e77c172a3b6c20cc67b18938b82fa0c1401c47d5"
}

rule Kanaf_Android_Exact_100 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "abeebf4e464dd814ea1c6d0cb8700d9025d0eaac6311a92004970f4a93099a66"
}

rule Kanaf_Android_Exact_101 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
}

rule Kanaf_Android_Exact_102 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b08172118a9909a63c4714ff6b08cd659e68129c1b3ade8b250b76800c75b138"
}

rule Kanaf_Android_Exact_103 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
}

rule Kanaf_Android_Exact_104 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
}

rule Kanaf_Android_Exact_105 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b68a028741e90336952daa06f00150855f109197f6e0ef36fb1a8ca6d8d18f11"
}

rule Kanaf_Android_Exact_106 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b696f443fa40dbbb775ade3645c9e7ab0976dc14d9b36d5ab0851ab39a20999e"
}

rule Kanaf_Android_Exact_107 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "b97ca5648baa5a79a6950951cf1d2691d0318b2425c4582759537fedaa1d24c7"
}

rule Kanaf_Android_Exact_108 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "ba9aeb87025ba26e7a54fe38f97bf28b72b1dac069e9fa6624a195a599c4b0ae"
}

rule Kanaf_Android_Exact_109 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "bb75c4b61de2bca0ad5477e9882bded6dbcea6731844d863145d3806a6035fcb"
}

rule Kanaf_Android_Exact_110 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "bd1b03b7a268e9c13b24bc7fc1b21ef76c0bd834ff8f04d6e0b8e8d6fa5a20b9"
}

rule Kanaf_Android_Exact_111 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c06f8c3fd23ae7124cc06eb63c0411418715bf99d3c9fa66525790b2b4c61858"
}

rule Kanaf_Android_Exact_112 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c547fc04afad7538be1c638019867145dabf630afc2eba1ece7f972892598a65"
}

rule Kanaf_Android_Exact_113 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c65298b6cd5a1769c747a0c7fb589ffa12fdf832b64787283953eaa57b65bc1c"
}

rule Kanaf_Android_Exact_114 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c6e590ec2408301c3f4b4942605ebfde3d9df6d677062669135686fd8af54ca9"
}

rule Kanaf_Android_Exact_115 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "cace16a3ef7594ac9881a5a3baa3426b30a4d8c5f0f5caf378946f6ca72a4868"
}

rule Kanaf_Android_Exact_116 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.GravityRAT; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "caf0a39318cfc1e65eae773a28de62ce08b7cf1b9d4264e843576165411e2a84"
}

rule Kanaf_Android_Exact_117 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d076268a34eb62ba17aaf3cfb244998bd3a1a9a4c1ca98d21944d94da30f42a8"
}

rule Kanaf_Android_Exact_118 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d1cbbe8e5a146e221aa452370017614edf1d58bd19e0eca9da12127b2cd53bbd"
}

rule Kanaf_Android_Exact_119 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d3d7af119747d8730fa85c1284f4c6de9ecb6cdec9b713a077e1ac964778eed3"
}

rule Kanaf_Android_Exact_120 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d6140ef329f2a8f141a05055b1d583a40dc9f5b26b00c63c72c7ebd82fa3c7ec"
}

rule Kanaf_Android_Exact_121 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d7629f3c272e6866e43cd6726d73d33074d571373c13f06f668892d84f7e8065"
}

rule Kanaf_Android_Exact_122 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d9a4c822126c5bab3b13a90af558770e27c34a7cca7736cdbf94c89a5ad49c8a"
}

rule Kanaf_Android_Exact_123 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "da9641b884ef1ee3ac513feeb71c237c7e54f3e32a8dea1ece524fcb94aa78ab"
}

rule Kanaf_Android_Exact_124 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.BadBazaar; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "daf3d2cb6f1bbb7c8d1cfb5fc0db23afc304a622ebb24aa940228be691bcda2d"
}

rule Kanaf_Android_Exact_125 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.PromptSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "db7a1c352c7d1ac75e0ba31b71cf4b0e3304a22b8d0d636fa80b5d5095be1e00"
}

rule Kanaf_Android_Exact_126 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "dc55df39a7824a455690022b373875d3eb7680c1b961efe38d73c7fa2e57d6bc"
}

rule Kanaf_Android_Exact_127 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "ddb91e692d0276684ac1a8af5f9ce5215fe53175c5918ce76906d45cfc2c7a03"
}

rule Kanaf_Android_Exact_128 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "ddd9e5cfa9e1ddd8d849baef2b487a1608d1695f44c70f246c101de1275887dd"
}

rule Kanaf_Android_Exact_129 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.ProSpyToSpyCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e18683bc061e888f158c9a3a7478615df2d7daae1952a072d7f549cd1c1e326a"
}

rule Kanaf_Android_Exact_130 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e19a7c8e4994ea4ed680136c9e3a6fff7b82c72f5743952821a446b6cb830f06"
}

rule Kanaf_Android_Exact_131 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
}

rule Kanaf_Android_Exact_132 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.GhostSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
}

rule Kanaf_Android_Exact_133 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e64fec26d12bc1249b8b7b821de192ba41a964012ce83b739ab0a52d34dc429a"
}

rule Kanaf_Android_Exact_134 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e6b2455737d046bf531d914d312da19fd5adbdefd41ba8357257a2575a1b4a91"
}

rule Kanaf_Android_Exact_135 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.GravityRAT; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "e9edf3dce24f4e5057f56a3a68c8f4bc3528158e4431be64c031b7a738b312ab"
}

rule Kanaf_Android_Exact_136 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "eb59536769bc8e429a1138812f4a00bd0f03f7196ef9a2c4db85a385777a1bca"
}

rule Kanaf_Android_Exact_137 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "ed2f076e3eac0b0d65b19ddaaa5b2150051a8cab4675d9fd3dafb88271c37fb4"
}

rule Kanaf_Android_Exact_138 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f06823da615963c38db0bf45ca6fdf802c1b6c8ae87ec99ea183d947294d65c0"
}

rule Kanaf_Android_Exact_139 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
}

rule Kanaf_Android_Exact_140 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f35683d7d60b339a603eb10fab78b575ae5ad4ad99b2d46dab5ea3f4ac9ffbbc"
}

rule Kanaf_Android_Exact_141 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.AridSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f4ddfd426440829bcbbbe789cb0c18fa3a23798eb5643f1c88b7986390b3d648"
}

rule Kanaf_Android_Exact_142 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
}

rule Kanaf_Android_Exact_143 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f56170fc141e2fce7449a01af9bda7b22b8909b6c8eaf698e5a149e3da75eeac"
}

rule Kanaf_Android_Exact_144 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.NGate; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f636a7a0c57061536c0c7ad6f02d9e3b1b1b91189b9bb8e6fc763d31e940c2b5"
}

rule Kanaf_Android_Exact_145 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.HamsterKombatCampaign; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f63e78eba957ea52cae2b79ee6028ac663dcb3accd5932573144658167522b8a"
}

rule Kanaf_Android_Exact_146 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "f6985f72cf17e68bda67f7ce3f8d1ff3f940cb872d78514d28d78549aa84664e"
}

rule Kanaf_Android_Exact_147 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "fd6cae8556aaf14a95e700e9626e61e4a032c1c00414f336865dc95b7aecd3f2"
}

rule Kanaf_Android_Exact_148 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.CallPhantom; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "ff60dfe9aa3bbda4049d1c14f732f19b90d2ac547aae98fff5dc159213286e83"
}
