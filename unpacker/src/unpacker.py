from dump_parser import EmotetDumpFileParser, SimplePEFileParser
from configuration import *
from titan_engine.teSdk import *
import time
import base64
import shutil
import yara
import glob
import os

"""
    Emotet unpacking module:
        Dynamic unpacker using TitanEngine framework.
"""

__author__ = "d00rt - @D00RT_RM"

__version__ = "1.0.0"
__maintainer__ = "d00rt - @D00RT_RM"
__email__ = "d00rt.fake@gmail.com"
__status__ = "Testing"


DIST_TO_RETN            = 0x100

class deEmotet():

    def __init__(self, gui=True, debug=False):
        self.CbOnInitialize     = fInitializeDbg(self.OnInitialize)

        self.CbOnDbgInit        = fBreakPoint(self.OnDbgInit)
        self.CbOnCallEAX        = fBreakPoint(self.OnCallEAX)
        self.CbOnCallEDX        = fBreakPoint(self.OnCallEDX)
        self.CbOnCallECX        = fBreakPoint(self.OnCallECX)
        self.CbOnCallEBX        = fBreakPoint(self.OnCallEBX)
        self.CbOnCallESP        = fBreakPoint(self.OnCallESP)
        self.CbOnCallEBP        = fBreakPoint(self.OnCallEBP)
        self.CbOnCallESI        = fBreakPoint(self.OnCallESI)
        self.CbOnCallEDI        = fBreakPoint(self.OnCallEDI)

        self.CbOnWipp           = fBreakPoint(self.OnWipp)

        self.wild               = c_ubyte(0xcc)
        self.layer2_base_addr   = 0
        self.counter            = 0
        self.debug_log          = debug

        self.gui                = gui
        self.unpacked           = False
        self.UNPACKING_RESULT   = None

        if self.gui:
            TE.EngineCreateUnpackerWindow("[ d00rt!deEmotet ]", "d00rt!deEmotet 2018/12/12", "d00rt!deEmotet 2018-11-30",
                                      "d00rt - @D00RT_RM", self.CbOnInitialize)
        
        self.log("Emotet unpacker v1.0.0 2018-12-10")
        self.log("d00rt (@D00RT_RM) / https://github.com/d00rt")

    def log(self, message):
        if not self.debug_log:
            return

        if self.gui:
            TE.EngineAddUnpackerWindowLogMessage(message)
        else:
            print message

    def write(self):
        if self.emotet_dump_parser.PE_LAYER_2:
            filename_layer_2 = os.path.join(DIR_LAYER_2, '.'.join([os.path.basename(self.Input), FILE_LAYER_2]))
            self.emotet_dump_parser.write(filename_layer_2, None)
            self.log("[+] Layer 2 extracted to: {0}".format(filename_layer_2))
        else:
            self.log("[!] Could not extract the Layer 2")

        if self.emotet_dump_parser.PE_PAYLOAD:
            filename_payload = os.path.join(DIR_PAYLOAD, '.'.join([os.path.basename(self.Input), FILE_PAYLOAD]))
            self.emotet_dump_parser.write(None, filename_payload)
            self.log("[+] Broken Payload extracted to: {0}".format(filename_payload))
        else:
            self.log("[!] Could not extract the Broken Payload")

        if self.emotet_dump_parser.RSA_CONFIG:
            filename_rsa = os.path.join(DIR_STATIC_CONFIG,'.'.join([os.path.basename(self.Input), FILE_RSA]))
            self.emotet_dump_parser.write_static_config(filename_rsa, None)
            self.log("[+] For RSA results check: {0}".format(os.path.join(FOLDER_STATIC_CONFIG, FILE_RSA)))
        else:
            self.log("[!] RSA key not found. Can not write its results.")

        if self.emotet_dump_parser.IPS_CONFIG:
            filename_ips = os.path.join(DIR_STATIC_CONFIG,'.'.join([os.path.basename(self.Input), FILE_IPS]))
            self.emotet_dump_parser.write_static_config(None, filename_ips)
            self.log("[+] For C&C results check: {0}".format(os.path.join(FOLDER_STATIC_CONFIG, FILE_IPS)))
        else:
            self.log("[!] C&C ips not found. Can not write its results.")

        if self.unpacked:
            filename_unpacked = os.path.join(DIR_UNPACKED_FILES, '.'.join([os.path.basename(self.Input), FILE_EMOTET]))
            self.emotet_dump_parser.PE_PAYLOAD.write(filename_unpacked)
            self.log("[+] Emotet payload unpacked: {0}".format(filename_unpacked))
        else:
            self.log("[!] Could not unpack the file.")

    def _parse_dump(self, dump, match_rsa, match_code):
        if not match_rsa:
            self.log("[!] New RSA key detected (New botnet). Update {0} file =)".format(FILE_YARA_RSA))
        if not match_code:
            self.log("[!] Payload yara rule doesn't match, could be:")
            self.log("        1) Provided file is a new emotet-payload file")
            self.log("           so, emotet gang knows about this packer...")
            self.log("        2) Provided file could be an old emotet version.")
            self.log("        3) This packer is not good enough for your intell-team")

        self.emotet_dump_parser = EmotetDumpFileParser(dumpfilename=dump)
        self.emotet_dump_parser.parse()
        self.emotet_dump_parser.get_static_config(match_rsa, match_code)

        if self.emotet_dump_parser.RSA_CONFIG:
            self.log("[+] {0} RSA keys found.".format(len(self.emotet_dump_parser.RSA_CONFIG)))
        else:
            self.log("[+] RSA keys not found.")

        if self.emotet_dump_parser.IPS_CONFIG:
            self.log("[+] {0} C&C found.".format(len(self.emotet_dump_parser.IPS_CONFIG)))
        else:
            self.log("[+] C&C not found.")

        if self.emotet_dump_parser.unhook():
            self.unpacked = True
            self.log("[+] Emotet payload correctly unpacked.")

        else:
            self.log("[!] Emotet payload can not be unpacked.")

        self.UNPACKING_RESULT = (self.unpacked, self.emotet_dump_parser.RSA_CONFIG, self.emotet_dump_parser.IPS_CONFIG, match_rsa, match_code)

        if self.gui:
            self.write()

    def OnWipp(self):
        matches = False

        if not TE.RemoveAllBreakPoints(UE_OPTION_REMOVEALL):
            self.log("[!] Can not delete the BPs")

        TE.DumpRegions(self.Info.contents.hProcess, DIR_DUMPS, False)
        rules_rsa = yara.compile(FILE_YARA_RSA)
        rules_code = yara.compile(FILE_YARA_CODE)

        for file in glob.glob(os.path.join(DIR_DUMPS, '*')):
            m_code = rules_code.match(filepath=file)
            m_rsa = rules_rsa.match(filepath=file)
 
            if m_code or m_rsa:
                matches = True
                self.log("[+] Yara match: ")
                for m in m_code + m_rsa:
                    self.log("        - {0}".format(m.rule))

                self._parse_dump(file, m_rsa, m_code)
            else:
                os.remove(file)

        if not matches:
            self.log("[!] Not Yara matches!")

        TE.StopDebug()
        self.log("[+] Stop Debug")

    def set_decrypt_fn_bp(self, call_addr):
        # BE CAREFUL
        # If this point is never reached, the binary will be executed
        # So if it is a malware but doesn't match with Emotet it will run
        # Execute the packer in a secure environment.
        #
        # I don't know how to deal with this using TitanEngine, any
        # suggestion is welcome
        if not TE.RemoveAllBreakPoints(UE_OPTION_REMOVEALL):
            self.log("[!] Can not delete the BPs")

        self.layer2_base_addr = call_addr & 0xFFFF0000
        pat = (c_ubyte * 15)(0x8B, 0x45, 0xCC, 0x83, 0xC0, 0x01, 0x3D, 0xFF, 0x00, 0x00, 0x00, 0x89, 0x45, 0xCC, 0xCC)

        loc = TE.Find(self.layer2_base_addr, self.SizeOfImg, byref(pat), len(pat), byref(self.wild))
        
        aux_loc = loc
        
        while aux_loc:
            loc = aux_loc
            aux_loc = TE.Find(loc + 1, self.SizeOfImg, byref(pat), len(pat), byref(self.wild))

        if not loc:
            self.log("[!] Could not locate decrypt function pattern.")
            TE.StopDebug()
            self.log("[+] Stop Debug")
            return

        # I'm sure that the pat is in a less address from where the first match was
        top = loc

        pat = (c_ubyte * 3)(0x55, 0x89, 0xE5)
        loc = TE.Find(loc - DIST_TO_RETN, DIST_TO_RETN, byref(pat), len(pat), byref(self.wild))

        aux_loc = loc
        while loc and loc < top:
            aux_loc = loc
            dist = aux_loc - loc
            loc = TE.Find(loc + 1 , DIST_TO_RETN - dist - 1, byref(pat), len(pat), byref(self.wild))

        loc = aux_loc
        self.log("[+] Function location: {0:X}".format(loc))
        # TODO
        # Think on a better way to do it
        pat = (c_ubyte * 1)(0xC3)
        loc = TE.Find(loc, DIST_TO_RETN, byref(pat), len(pat), byref(self.wild))

        if not TE.SetBPX(loc, UE_BREAKPOINT, self.CbOnWipp):
        #self.Dr = c_ulong(0)
        #TE.GetUnusedHardwareBreakPointRegister(byref(self.Dr))
        #if not TE.SetHardwareBreakPoint(loc, self.Dr, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, self.CbOnWipp):
            self.log("[!] Could not set-up 'pre per' breakpoint.")
            TE.StopDebug()
            self.log("[+] Stop Debug")
            return

        # self.log("[+] Breakpoint 'pre per' set-up {0:X}".format(loc))

    def _check_valid_call(self, addr):
        if addr & 0xFF000000 > 0x70000000 or addr & 0xFFFF0000 == self.Base & 0xFFFF0000:
            return False
        return True

    def OnCallEAX(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_EAX)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] EAX " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallECX(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_ECX)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] ECX " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallEDX(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_EDX)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] EDX " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallEBX(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_EBX)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] EBX " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallESP(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_ESP)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] ESP " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallEBP(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_EBP)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] EBP " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallESI(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_ESI)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] ESI " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def OnCallEDI(self):
        self.counter -= 1
        layer2_oep = TE.GetContextData(UE_EDI)
        if not self._check_valid_call(layer2_oep):
              return

        self.log("[+] EDI " + hex(layer2_oep))
        self.set_decrypt_fn_bp(layer2_oep)

    def set_call_bp(self, reg):
        REG_BP = {
            0: self.CbOnCallEAX,
            1: self.CbOnCallECX,
            2: self.CbOnCallEDX,
            3: self.CbOnCallEBX,
            4: self.CbOnCallESP,
            5: self.CbOnCallEBP,
            6: self.CbOnCallESI,
            7: self.CbOnCallEDI,
        }

        bp_num = 0

        pat = (c_ubyte * 2)(0xFF, 0xD0 + reg)
        loc = TE.Find(self.Base, self.SizeOfImg, byref(pat), len(pat), byref(self.wild))
        if loc == 0:
            return bp_num

        while loc > self.lo and loc < self.hi:
            aux_loc = loc
            dist = aux_loc - loc

            if not TE.SetBPX(loc, UE_SINGLESHOOT, REG_BP[reg]):
                return bp_num

            bp_num += 1

            self.counter += 1

            loc = TE.Find(loc, self.SizeOfImg - dist, byref(pat), len(pat), byref(self.wild))
        return bp_num

    def OnDbgInit(self):
        total_bp = 0
        self.counter = 0

        self.Base = TE.GetDebuggedFileBaseAddress()
        self.lo += self.Base
        self.hi += self.Base

        total_bp += self.set_call_bp(0) #EAX
        total_bp += self.set_call_bp(1) #ECX
        total_bp += self.set_call_bp(2) #EDX
        total_bp += self.set_call_bp(3) #EBX
        total_bp += self.set_call_bp(4) #ESP
        total_bp += self.set_call_bp(5) #EBP
        total_bp += self.set_call_bp(6) #ESI
        total_bp += self.set_call_bp(7) #EDI

        if total_bp == 0:
            TE.StopDebug()
            self.log("[+] Stop Debug")
            return

    def OnInitialize(self, pOriginal, pRealign=False, pCopyOvl=False):
        if not pOriginal: return

        self.Input  = pOriginal
        TE.SetBPXOptions(UE_BREAKPOINT_INT3)

        self.Validity = FILE_STATUS_INFO()

        if not TE.IsPE32FileValidEx(pOriginal, UE_DEPTH_DEEP, byref(self.Validity)) \
           or  self.Validity.OveralEvaluation != UE_RESULT_FILE_OK:
            self.log("[!] The file seems to be invalid.")
            return

        self.IsDLL = TE.IsFileDLL(pOriginal, 0)

        self.Info = TE.InitDebugEx(pOriginal, 0, 0, self.CbOnDbgInit)

        if self.Info:
            self.log("[+] Debugger initialized.")

            self.SizeOfImg  = TE.GetPE32Data(pOriginal, 0, UE_SIZEOFIMAGE)
            self.EP         = TE.GetPE32Data(pOriginal, 0, UE_OEP)

            self.SnapRange  = TE.GetPE32Data(pOriginal, 0, UE_SECTIONVIRTUALOFFSET)
            self.SnapSize   = self.EP - self.SnapRange

            self.lo = None
            pe_parser = SimplePEFileParser(filename=pOriginal)

            for r_a, r_s, v_a, v_s, n, c in pe_parser._get_section_header_content():
                if self.EP >= v_a and self.EP < v_a + v_s:
                    self.lo = v_a
                    self.hi = v_a + v_s
                    break

            if self.lo == None:
                self.log("[!] Could not get code section!")
                return

            TE.DebugLoop()
        else:
            self.log("[!] Could not initialize debugging!")

        if os.path.exists(DIR_DUMPS):
            shutil.rmtree(DIR_DUMPS)

        TE.StopDebug()
        self.log("[+] Exit Code: {0:X}.".format(TE.GetExitCode()))


    def unpack_file(self, filename):
        self.log("[+] Filename: {0}".format(filename))
        self.OnInitialize(filename)
        self.log("")
        return self.UNPACKING_RESULT

