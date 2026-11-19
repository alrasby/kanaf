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
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "04ce3c28a1bdd079a8d6707ea2c4b526a6ee735935dce194ce1d1f4ecc2b58ed"
}

rule Kanaf_Android_Exact_1 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0757de1fd165f72a084f955dc3fe45480a92b18b6153e116d1992586ca8ccd02"
}

rule Kanaf_Android_Exact_2 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "0c7afefe507ace767217dd91bdb68b06947ca668559f025425baae2afb4fff6c"
}

rule Kanaf_Android_Exact_3 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1e2c03876cb0a4dfb588be0de5bffd11aff57d556dbfb8a92793470ab3c66038"
}

rule Kanaf_Android_Exact_4 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "1f744fcc5b503328e8707c93f36904d17d2a71db3aa948803c98a5d54160b878"
}

rule Kanaf_Android_Exact_5 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "2014f0655875b62b563cc030eb5f57537625e377efa6ffbda35acd07017c673d"
}

rule Kanaf_Android_Exact_6 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "2ae44078807edae58fb6d383f86e6e5db62262fd7b830d7f430702bc56b5c055"
}

rule Kanaf_Android_Exact_7 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "2fdb7c4430660cb49547ac2828a631810d4e3d245a6501ce00825faa169cb7d0"
}

rule Kanaf_Android_Exact_8 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "35f52cb5085cc58e8d005d249bfcaa17244f1be3147780e1ac64990006db2ccc"
}

rule Kanaf_Android_Exact_9 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "40f13c6b1a5a750cc41af5f401d1772c38406c59c178dd22ad25d6513a6158bf"
}

rule Kanaf_Android_Exact_10 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "42c20ef7913d596a475c108c0ed372995ec04b5a710b0f51cfc749e409bbc625"
}

rule Kanaf_Android_Exact_11 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "4732c4d8e51a7bed9cfaf0d69868b0e72175a658175d219cc9d04cffa1dacf3c"
}

rule Kanaf_Android_Exact_12 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "55dd05f02ead336c99d491fa7a9945cf8f113215c5147710874be68fde519cd5"
}

rule Kanaf_Android_Exact_13 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5672e8d711be744869e811ebbf90b511abf025eb1dfe2372d2e60ac4b825d3d0"
}

rule Kanaf_Android_Exact_14 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "5d5547cfe902188803301152433ceedbbf31b6f7be97141078e97d5f3c986fb4"
}

rule Kanaf_Android_Exact_15 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "64b2a100e8ca305d7362eeb4858694156d676989b8c6d6d8d01cdebe84dafc7b"
}

rule Kanaf_Android_Exact_16 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "65ad85202c229b138c60233c756d0953a8b0538f43e82728fc809d7345c55004"
}

rule Kanaf_Android_Exact_17 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "81f41a2d788eb728385c6689b6664848791a10d153db3e057eb20e9d80b9ff60"
}

rule Kanaf_Android_Exact_18 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "8f8ce7916a849f58dd74069a1028a19732fc4c454b7fff84b40d4ac07d1edb7e"
}

rule Kanaf_Android_Exact_19 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "9115408ab7227f30cb6d3f785c208377b31da208171def1c3ec4d81c6f833585"
}

rule Kanaf_Android_Exact_20 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "97c1ede53312b5efc3f9e929cdcef4fee9ae54ed9123a256df85c1ac901922f5"
}

rule Kanaf_Android_Exact_21 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "9eb13898532f4521961c5a5a1382cd0b96dfe40196371628b1792678b900b6db"
}

rule Kanaf_Android_Exact_22 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "ba9aeb87025ba26e7a54fe38f97bf28b72b1dac069e9fa6624a195a599c4b0ae"
}

rule Kanaf_Android_Exact_23 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "bb75c4b61de2bca0ad5477e9882bded6dbcea6731844d863145d3806a6035fcb"
}

rule Kanaf_Android_Exact_24 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "bd1b03b7a268e9c13b24bc7fc1b21ef76c0bd834ff8f04d6e0b8e8d6fa5a20b9"
}

rule Kanaf_Android_Exact_25 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c06f8c3fd23ae7124cc06eb63c0411418715bf99d3c9fa66525790b2b4c61858"
}

rule Kanaf_Android_Exact_26 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.VajraSpy; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c547fc04afad7538be1c638019867145dabf630afc2eba1ece7f972892598a65"
}

rule Kanaf_Android_Exact_27 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "c65298b6cd5a1769c747a0c7fb589ffa12fdf832b64787283953eaa57b65bc1c"
}

rule Kanaf_Android_Exact_28 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "d3d7af119747d8730fa85c1284f4c6de9ecb6cdec9b713a077e1ac964778eed3"
}

rule Kanaf_Android_Exact_29 {
 meta:
  author = "ESET Research; Kanaf format conversion"
  license = "BSD-2-Clause"
  description = "Android.SpyLoan; exact file only"
  source = "https://github.com/eset/malware-ioc/tree/8921a81d245cce3f9b7a199b123d221ed8f1fe33"
 condition:
  hash.sha256(0, filesize) == "da9641b884ef1ee3ac513feeb71c237c7e54f3e32a8dea1ece524fcb94aa78ab"
}
