# -*- coding: utf-8 -*-

PLUGIN_VERSION = '0.5.10'

# If True the starting address will be current function when making a sig for functions.
# SigMaker-x64 behavior is to look for 5 or more references before adding function start
FUNC_START_EA = True

# Can be set via Gui, this is just for a fallback default
PLUGIN_HOTKEY = 'Ctrl-Alt-S'


"""
    pySigMaker:

    Ported by: zoomgod - unknowncheats.me

    IDAPython port for most of the origional compiled SigMaker-x64 IDA
    plugin with some minor changes, bug-fix and new GUI.

    Credits to the origional author/contributors of SigMaker-x64
    https://github.com/ajkhoury/SigMaker-x64

    See readme for IDA/Python requirements
"""

import sys, pickle, os, shutil

PLUGIN_DIR, PLUGIN_FILENAME = sys.argv[0].rsplit('/', 1)
HOTKEY_CONFLICT = False
SIGMAKER_X64_PLUGINS = []

if PLUGIN_DIR.find('plugins') == -1:
    PLUGIN_DIR = ''
else:
    if os.path.exists('%s/sigmaker.dll' % PLUGIN_DIR):
        SIGMAKER_X64_PLUGINS.append('sigmaker.dll')

    if os.path.exists('%s/sigmaker64.dll' % PLUGIN_DIR):
        SIGMAKER_X64_PLUGINS.append('sigmaker64.dll')

    HOTKEY_CONFLICT = len(SIGMAKER_X64_PLUGINS) > 0

try:
    import tkinter  # Used to put sigs on clipboard
    from enum import unique, IntEnum
except:
    print('Python 3.8 > required, 3.8 recommended.')
    sys.exit(0)

# Gui
from PyQt5 import Qt, QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

import idc
import idaapi, ida_kernwin, ida_bytes
from idaapi import BADADDR

#added for v9 compatibility
from ida_pro import IDA_SDK_VERSION
import ida_nalt, ida_search

major, minor = divmod(IDA_SDK_VERSION, 100)
minor, build = divmod(minor, 10)

# Adds a Debug tab to dump QT object trees
GUI_DBG_ENABLED = True

@unique
class QueryTypes(IntEnum):
    QUERY_FIRST     = 0     # Return 1st match
    QUERY_COUNT     = 1     # Return count
    QUERY_UNIQUE    = 2     # Return True/False

@unique
class PatternType(IntEnum):
    PT_INVALID      = -1
    PT_DIRECT       = 0
    PT_FUNCTION     = 1
    PT_REFERENCE    = 2

@unique
class SigType(IntEnum):
    SIG_IDA         = 0
    SIG_CODE        = 1
    SIG_OLLY        = 2

@unique
class SigSelect(IntEnum):
    OPT_LENGTH      = 0
    OPT_OPCODES     = 1
    OPT_WILDCARDS   = 2

@unique
class LogOptions(IntEnum):
    LOG_RESULT      = 0
    LOG_DEBUG       = 1


def banner(hotkey):
    print('---------------------------------------------------------------------------------------------')
    print('   pySigMaker: zoomgod - unknowncheats.me')
    print('   v%s - hotkey: %s' % (PLUGIN_VERSION, hotkey))
    print('---------------------------------------------------------------------------------------------')

#
#
#  Utility functions
#
#
class QueryStruct:
    def __init__(self, major, idasig, pattern=b'', mask = b'', startea=BADADDR, endea=BADADDR):
        self.major = major
        self.idasig = idasig
        self.pattern = pattern
        self.mask = mask
        self.startea = startea
        self.endea = endea
        self.ea = BADADDR

        if self.startea == BADADDR:
            self.startea = idaapi.inf_get_min_ea()

        if self.endea == BADADDR:
            self.endea = idaapi.inf_get_max_ea()

def BinSearch(query) -> QueryStruct:
    """
    Searches for matching sequence of bytes based on a pattern and mask

    args:
        QueryStruct

    returns:
        QueryStruct with ea filled in
    """

    startea = query.startea
    if query.startea == BADADDR:
        query.startea = idaapi.inf_get_min_ea()

    endea = query.endea
    if query.startea == BADADDR:
        query.startea = idaapi.inf_get_max_ea()
    
    query.ea = BADADDR

    if query.major < 9:
        # this is to keep support for v7 working, v8 would land here as well but I never had it to test on.
        query.ea = idaapi.bin_search( query.startea, query.endea, query.pattern, query.mask,
            idaapi.BIN_SEARCH_FORWARD,
            idaapi.BIN_SEARCH_NOBREAK | idaapi.BIN_SEARCH_NOSHOW )
    else:
        # bin_search in 9.1 used to be bin_search3 in v7 so parameters changed
        patterns = ida_bytes.compiled_binpat_vec_t()
        encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B) 
    
        # The 'zero_ea' argument is used as a base address for the pattern
        ida_bytes.parse_binpat_str(patterns, 0, query.idasig, 16, encoding)
        #result = ida_bytes.bin_search(query.startea, query.endea, patterns, ida_search.SEARCH_DOWN | ida_search.SEARCH_REGEX)
        result = ida_bytes.bin_search(query.startea, query.endea, patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)
        
        if isinstance(result, tuple):
            query.ea = result[0]
        else:
            query.ea = result # Fallback for potential API variations

    return query

def MakeBin(ida_pattern, startea=BADADDR, endea=BADADDR) -> QueryStruct:
    """
        makeBin(ida_pattern)
        Returns QueryStruct with bin_search compatible pattern and mask from an IDA style pattern
    """
    global major

    patt = bytearray()
    mask = bytearray()

    for i in ida_pattern.split(' '):
        if i == '?':
            patt.append(0)
            mask.append(0)
        else:
            patt.append(int(i, 16))
            mask.append(1)

    return QueryStruct(major, ida_pattern, bytes(patt), bytes(mask), startea, endea)

def BinQuery(sig, flag = QueryTypes.QUERY_FIRST, startea=None, endea = None):

    global major

    """
    Args:
        sig : IDA style pattern string
        flag: One of QueryTypes enum members

    Return types:
        flag == QUERY_FIRST  returns ea, search stops when matches == 1
        flag == QUERY_COUNT  returns int, full search
        flag == QUERY_UNIQUE returns boolean, search stops when matches > 1
    """

    Result = []

    query = MakeBin(sig)

    query = BinSearch(query)
    while query.ea != BADADDR:

        Result.append(query.ea)

        if flag == QueryTypes.QUERY_UNIQUE and len(Result) > 1:
            break

        if flag == QueryTypes.QUERY_FIRST:
            return Result[0]

        query.startea = query.ea + 1
        ea = BinSearch(query)

    if flag == QueryTypes.QUERY_UNIQUE:
        return len(Result) == 1
    elif flag == QueryTypes.QUERY_COUNT:
        return len(Result)
    elif flag == QueryTypes.QUERY_FIRST:
        return BADADDR

    raise ValueError('Invalid flag passed')


#
#
#  Pattern converters
#
#
def Ida2Code(sig) -> str:
    """
    Ida2Code(sig)

    Convert an IDA sig to code pattern and mask

    Arg:
        sig: IDA style sig

    Returns:
        string, string
    """

    mask = ''
    patt = ''

    for entry in sig.split(' '):
        if entry == '?':
            patt = patt + '\\x00'
            mask = mask + '?'
        else:
            patt = patt + '\\x%s' % entry
            mask = mask + 'x'

    return patt, mask

def Ida2Olly(sig) -> str:
    """
    Ida2Olly(sig)

    Convert an IDA sig to an Olly Debugger compatible sig

    Arg:
        sig: IDA style sig

    Return:
        string
    """

    pattern = []

    for entry in sig.split(' '):
        if entry == '?':
            pattern.append('??')
        else:
            pattern.append(entry)

    return " ".join(pattern)

def Code2Ida(patt, mask=None) -> str:
    """
    Code2Ida(sig)

    Convert an code style sig to an IDA sig

    Note:  When no mask is supplied any \x00 in pattern become a wildcards.

    Arg:
        sig : required, code style sig
        mask: optional

    Return:
        string
    """

    pattern = []
    p = []

    # convert binary string or regular string into a list of ints
    # Since \ is an escape character in Python have to check
    # for varying strings
    if not type(patt) is type(b''):
        if type(patt) is type('') and patt.find('\\') > -1:
            p = [ int('0x%s' % x, 16) for x in patt.split('\\x')[1:] ]
        else:
            return ''
    else:
        # binary string, can just convert to list
        p = list(patt)

    if mask and len(mask) != len(p):
        return ''

    for i in range(len(p)):
        if mask:
            if mask[i] == 'x':
                pattern.append('%02X' % p[i])
            else:
                pattern.append('?')
        elif p[i] > 0:
            pattern.append('%02X' % p[i])
        else:
            pattern.append('?')

    return ' '.join(pattern)

def GetIdaSig(sig, mask = None) -> str:
    """
    GetIdaSig(sig)

    Converts Olly or Code style sigs to an IDA style sigs

    Arg:
        sig : required, olly or code style sig
        mask: optional, valid only for code sigs

    Return:
        string
    """

    # Only a code sig should be byte string
    if type(sig) is type(b''):
        return Code2Ida(sig, mask)

    if sig.find(' ') > -1:

        # an olly sig without wildcards would be same as an ida sig so this is safe
        if sig.find(' ?? ') > -1:
            return sig.replace('??', '?')

        # Olly sig with no wildcards or already an ida sig
        return sig

    # Only supported type left is code sigs as a string
    return Code2Ida(sig, mask)

def GetSigType(sig) -> SigType:

    if type(sig) is type(b'') or sig.find('\\') > -1:
        return SigType.SIG_CODE

    if sig.find(' ') > -1:
        if sig.find(' ?? ') > -1:
            return SigType.SIG_OLLY
        return SigType.SIG_IDA

    return SigType.SIG_CODE

#
#
#  SigMaker
#
#
class SigCreateStruct:
    def __init__(self):
        self.sig = []
        self.dwOrigStartAddress = BADADDR   #ea at cursor when started
        self.dwStartAddress = BADADDR
        self.dwCurrentAddress = BADADDR
        self.bUnique = False
        self.iOpCount = 0
        self.eType = PatternType.PT_INVALID

class SigMaker:
    """
    Public methods:
        AutoFunction()
        AutoAddress()
    """

    def __init__(self, plugin):
        self.__plugin = plugin
        self.Sigs = []

    def _reset(self):
        self.Sigs = []

    def _addBytesToSig(self, sigIndex, ea, size):

        for i in range(0, size):
            b = idaapi.get_byte( ea + i )
            self.Sigs[sigIndex].sig.append('%02X' % b)

    def _addWildcards(self, sigIndex, count):
        for i in range(0, count):
            self.Sigs[sigIndex].sig.append('?')

    def _getCurrentOpcodeSize(self, cmd) -> (int, int):

        count = 0

        for i in range(0, idaapi.UA_MAXOP):

            count = i
            if cmd.ops[i].type == idaapi.o_void:
                return 0, count

            if cmd.ops[i].offb != 0:
                return cmd.ops[i].offb, count

        return 0, count

    def _matchOperands(self, ea) -> bool:

        if idaapi.get_first_dref_from(ea) != BADADDR:
            return False
        elif not self.__plugin.Settings.bOnlyReliable:
            if idaapi.get_first_fcref_from(ea) != BADADDR:
                return False
        elif idaapi.get_first_cref_from(ea) != BADADDR:
            return False

        return True

    def _addInsToSig(self, cmd, sigIndex):

        size, count = self._getCurrentOpcodeSize(cmd)

        if size == 0:
            self._addBytesToSig(sigIndex, cmd.ea, cmd.size)
            return
        else:
            self._addBytesToSig(sigIndex, cmd.ea, size)

        if self._matchOperands(cmd.ea):
            self._addBytesToSig(sigIndex, cmd.ea + size, cmd.size - size)
        else:
            self._addWildcards(sigIndex, cmd.size - size)

    def _addToSig(self, sigIndex) -> bool:

        cmd = idaapi.insn_t()
        cmd.size = 0

        sig = self.Sigs[sigIndex]

        if not idaapi.can_decode(sig.dwCurrentAddress):
            return False

        count = idaapi.decode_insn(cmd, sig.dwCurrentAddress)

        if count == 0 or cmd.size == 0:
            return False

        if cmd.size < 5:
            self._addBytesToSig(sigIndex, sig.dwCurrentAddress, cmd.size)
        else:
            self._addInsToSig(cmd, sigIndex)

        sig.dwCurrentAddress = sig.dwCurrentAddress + cmd.size
        sig.iOpCount = sig.iOpCount + 1

        self.Sigs[sigIndex] = sig

        return True

    def _haveUniqueSig(self) -> bool:
        for i in range(0, len(self.Sigs)):
            if self.Sigs[i].bUnique:
                return True
        return False

    def _addRefs(self, startea) -> bool:

        self.__plugin.log('Adding references', LogOptions.LOG_DEBUG)

        if idaapi.get_func_num(startea) != -1:
            sig = SigCreateStruct()
            sig.dwStartAddress = startea
            sig.dwCurrentAddress = startea
            sig.eType = PatternType.PT_DIRECT
            self.Sigs.append(sig)
            self.__plugin.log('Added direct reference 0x%X' % startea, LogOptions.LOG_DEBUG)

        eaCurrent = idaapi.get_first_cref_to(startea)
        while eaCurrent != BADADDR:

            if eaCurrent != startea:
                sig = SigCreateStruct()
                sig.dwStartAddress = eaCurrent
                sig.dwCurrentAddress = eaCurrent
                sig.eType = PatternType.PT_REFERENCE
                self.Sigs.append(sig)
                self.__plugin.log('Added reference 0x%X' % eaCurrent, LogOptions.LOG_DEBUG)

            if self.__plugin.Settings.maxRefs > 0 and len(self.Sigs) >= self.__plugin.Settings.maxRefs:
                break

            eaCurrent = idaapi.get_next_cref_to(startea, eaCurrent)

        if len(self.Sigs) < 5:

            self.__plugin.log('Not enough references were found (%i so far), trying the function.' % len(self.Sigs), LogOptions.LOG_DEBUG)

            func = idaapi.get_func(startea)

            if not func or func.start_ea == BADADDR:
                self.__plugin.log('Selected address not in a valid function.', LogOptions.LOG_NORMAL)
                return False

            if func.start_ea != startea:

                eaCurrent = idaapi.get_first_cref_to(func.start_ea)

                while eaCurrent != BADADDR:

                    if eaCurrent != startea:
                        sig = SigCreateStruct()
                        sig.dwStartAddress = func.start_ea
                        sig.dwCurrentAddress = eaCurrent
                        sig.eType = PatternType.PT_FUNCTION
                        self.Sigs.append(sig)
                        self.__plugin.log('Added function 0x%X' % eaCurrent, LogOptions.LOG_DEBUG)

                    if self.__plugin.Settings.maxRefs > 0 and len(self.Sigs) >= self.__plugin.Settings.maxRefs:
                        break

                    eaCurrent = idaapi.get_next_cref_to(func.start_ea, eaCurrent)

        if not len(self.Sigs):
            self.__plugin.log('Automated signature generation failed, no references found.')
            return False

        self.__plugin.log('Added %i references.' % len(self.Sigs), LogOptions.LOG_DEBUG)

        return True

    def _chooseSig(self) -> bool:

        max = 9999
        selected = -1

        for sigIndex in range(0, len(self.Sigs)):

            sig = self.Sigs[sigIndex]

            # drop wildcards off end of sig
            while sig.sig[-1] == '?':
                sig.sig = sig.sig[:-1]

            if sig.bUnique:

                sigLen = len(sig.sig)

                if self.__plugin.Settings.SigSelect == SigSelect.OPT_LENGTH:
                    if sigLen < max or (sig.eType == PatternType.PT_DIRECT and max == sigLen):
                        max = sigLen
                        selected = sigIndex
                else:
                    if self.__plugin.Settings.SigSelect == SigSelect.OPT_OPCODES:
                        if sig.iOpCount < max or (sig.eType == PatternType.PT_DIRECT and max == sig.iOpCount):
                            max = sig.iOpCount
                            selected = sigIndex
                    else:
                        wildcards = ''.join(sig.sig).count('?')
                        if wildcards < max or sig.eType == PatternType.PT_DIRECT and max == wildcards:
                            selected = sigIndex
                            max = wildcards

        if selected == -1:
            self.__plugin.log('Failed to create signature.')
            return False

        sig = self.Sigs[selected]
        idaSig = ' '.join(sig.sig)
        strSig = ''

        if self.__plugin.Settings.SigType == SigType.SIG_CODE:
            patt, mask = Ida2Code(idaSig)
            strSig = patt + ' ' + mask
        elif self.__plugin.Settings.SigType == SigType.SIG_OLLY:
            strSig = Ida2Olly(idaSig)
        else:
            strSig = idaSig

        #
        # Testing sigs for now, may just leave it, it's quick
        #
        ea = BinQuery(idaSig, QueryTypes.QUERY_FIRST)

        txt = ''

        if sig.eType == PatternType.PT_DIRECT:
            txt = 'result: matches @ 0x%X, sig direct: %s' % (ea, strSig)
        elif sig.eType == PatternType.PT_FUNCTION:
            txt = 'result: matches @ 0x%X, sig function: (+0x%X) %s' % (ea, startea - sig.dwStartAddress, strSig)
        elif sig.eType == PatternType.PT_REFERENCE:
            txt = 'result: matches @ 0x%X, sig reference: %s' % (ea, strSig)

        self.__plugin.log(txt, LogOptions.LOG_RESULT)

        #
        # Qt has a clipboard widget but I didn't want to place a QT
        # requirement on using the class since it has nothing to do
        # with the Gui.  TKinter is included with Python.
        #
        r = tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(strSig)
        r.update()
        r.destroy()

        return True

    def AutoFunction(self) -> bool:
        """
            Generate shortest unique signature possible to current function
        """
        global major

        self._reset()

        startea = idc.get_screen_ea()
        if startea in [0, BADADDR]:
            self.__plugin.log('Current ea == BADADDR.')
            return False

        if FUNC_START_EA:
            # Get function start
            func = idaapi.get_func(startea)
            if not func or func.start_ea == BADADDR:
                self.__plugin.log('Must be in a function.')
                return False
            elif startea != func.start_ea:
                startea = func.start_ea
                self.__plugin.log('Using function: 0x%X' % startea, LogOptions.LOG_DEBUG)

        if not self._addRefs(startea):
            return False

        iCount = 0
        bHaveUniqueSig = False

        while not bHaveUniqueSig and len(self.Sigs):

            for sigIndex in range(0, len(self.Sigs)):

                if len(self.Sigs[sigIndex].sig) < self.__plugin.Settings.maxSigLength and self._addToSig(sigIndex):
                    if len(self.Sigs[sigIndex].sig) > 5:
                        self.Sigs[sigIndex].bUnique = BinQuery(' '.join(self.Sigs[sigIndex].sig), QueryTypes.QUERY_UNIQUE)
                else:
                    if sigIndex == 0:
                        self.Sigs = self.Sigs[1:]
                    elif sigIndex == len(self.Sigs) - 1:
                        self.Sigs = self.Sigs[:-1]
                    else:
                        self.Sigs = self.Sigs[:sigIndex] + self.Sigs[sigIndex+1:]

                    sigIndex = sigIndex - 1

            bHaveUniqueSig = self._haveUniqueSig()

        return self._chooseSig()

    def AutoAddress(self) -> bool:
        """
            Rather than create a sig from selection this
            gets current ea from screen and then creates
            the shortest sig possible.
        """

        global major

        self._reset()

        startea = idc.get_screen_ea()
        if startea in [0, BADADDR]:
            self.__plugin.log('Click on address you want sig for.')
            return False

        sig = SigCreateStruct()
        sig.dwStartAddress = startea
        sig.dwCurrentAddress = startea
        sig.eType = PatternType.PT_DIRECT

        self.Sigs.append(sig)

        while not self.Sigs[0].bUnique and len(self.Sigs[0].sig) < self.__plugin.Settings.maxSigLength:

            sigIndex = 0
            if self._addToSig(sigIndex):
                if len(self.Sigs[sigIndex].sig) > 5:
                    self.Sigs[sigIndex].bUnique = BinQuery(' '.join(self.Sigs[sigIndex].sig), QueryTypes.QUERY_UNIQUE)
            else:
                self.__plugin.log('Unable to create sig at selected address')
                return False

        self._chooseSig()

#
#
# QT debug utility class
#
#
class QTDebugHelper:

    def __init__(self, plugin):
        self.plugin = plugin
        self.fh = None
        self._logdir = idaapi.get_user_idadir()

    def _log(self, txt):
        if self.fh:
            self.fh.write('%s\n' % txt)

    def _getClassName(self, obj):
        cls = '%s' % (type(obj))
        return cls.split("'", 1)[1].split("'")[0]

    def _printDescription(self, obj, depth = 0):

        objName = obj.objectName()
        txt     = []

        if objName != '':
            txt.append('Name="{}"'.format(objName))

        try: 
            text = obj.text()
            if text != '':
                txt.append('Text="{}"'.format(text))
        except: 
            pass

        try: 
            winTitle = obj.windowTitle()
            if winTitle != '':
                txt.append('Title="{}"'.format(winTitle))
        except: 
            pass

        try:
            if obj.layout():
                txt.append('layout={}'.format(self._getClassName(obj.layout())))
        except:
            pass

        childCount = len(obj.children())
        if childCount:
            txt.append('children={}'.format(childCount))

        cls = self._getClassName(obj)

        self._log('{}{} {}'.format('\t' * depth, cls, ', '.join(txt)))

    def _dump(self, obj, depth=0):
        self._printDescription(obj, depth)
        for child in obj.children():
            self._dump(child, depth+1)

    def _dumpForm(self):
        fname = '%s\\QtFormDump.log' % self._logdir
        self.fh = open(fname, 'w')
        widget = self._getWidget(True)
        if widget:
            self._dump(widget)
        self.fh.close()
        self.fh = None
        print("Wrote: %s" % fname)
        os.startfile(fname)

    def _dumpAll(self):
        fname = '%s\\QtFormFullDump.log' % self._logdir
        self.fh = open(fname, 'w')
        widget = self._getWidget(False)
        if widget:
            self._dump(widget)
        self.fh.close()
        self.fh = None
        print("Wrote: %s" % fname)
        os.startfile(fname)

    def _pathToPlugin(self):

        fname = '%s\\PathToPlugin.log' % self._logdir
        self.fh = open(fname, 'w')

        w = []
        widget = self.plugin.widget
        while widget:
            w.append(widget)
            widget = widget.parent()

        w.reverse()
        for widget in w:
            self._printDescription(widget)

        self.fh.close()
        self.fh = None
        print("Wrote: %s" % fname)
        os.startfile(fname)

    def initDebugTab(self):

        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        dbgGuiDump = QtWidgets.QPushButton('Dump Form')
        dbgGuiDump.clicked.connect(self._dumpForm)

        dbgGuiDumpAll = QtWidgets.QPushButton('Dump Full')
        dbgGuiDumpAll.clicked.connect(self._dumpAll)

        dbgGuiContainer = QtWidgets.QPushButton('Path To Plugin')
        dbgGuiContainer.clicked.connect(self._pathToPlugin)
        
        
        layout.addWidget(dbgGuiDump)
        layout.addWidget(dbgGuiDumpAll)
        layout.addWidget(dbgGuiContainer)

        tab.setLayout(layout)
        self.plugin.tabControl.addTab(tab, 'Dbg Gui')

    def _getWidget(self, bWinTitle):

        parent = self.plugin.widget
        widget = None

        # follow parent tree
        while parent:
            if bWinTitle:
                if parent.windowTitle() == self.plugin.widget.windowTitle():
                    widget = parent
            else:
                widget = parent

            parent = parent.parent()

        return widget

#
#
# QT Gui
#
#
class PluginGui(idaapi.PluginForm):
    
    def __init__(self, plugin):

        global GUI_DBG_ENABLED

        idaapi.PluginForm.__init__(self)
        self.__plugin = plugin
        self.__parent = None

        self._QtDbgHelper = QTDebugHelper(self)

        self.closed = False

        self._root_widget = None
        self._output_window = None
        self._docked = False
        self._showed_banner = False

    #
    # IDA PluginForm overloaded methods
    #
    def Show(self, caption, options=None):
        if options:
            super().Show(caption, options)
            return
        # Floating window as default.
        super().Show(caption, idaapi.PluginForm.WOPN_DP_FLOATING)

    def OnCreate(self, form):
        self.widget = self.FormToPyQtWidget(form)
        self.PopulateForm()
        self.__parent = self.FormToPyQtWidget(form)
        # Parent widget isn't set until after this function returns, the timer deals with that
        QtCore.QTimer.singleShot(0, self._formState)

    #
    # Connected QT events
    #
    def _sigTypeIdaClick(self):
        self.__plugin.Settings.SigType = SigType.SIG_IDA
        self.__plugin.Settings.save()

    def _sigTypeCodeClick(self):
        self.__plugin.Settings.SigType = SigType.SIG_CODE
        self.__plugin.Settings.save()

    def _sigTypeOllyClick(self):
        self.__plugin.Settings.SigType = SigType.SIG_OLLY
        self.__plugin.Settings.save()

    def _sigTest(self):

        patt = self.patt.currentText()
        mask = self.mask.text()

        sig  = ''
        st = GetSigType(patt)

        if st == SigType.SIG_CODE:
            sig = GetIdaSig(patt, mask)
        else:
            sig = GetIdaSig(patt)
            mask = ''

        if not sig:
            self.__plugin.log('Invalid sig: "%s"' % sig)
            return

        self.__plugin.Settings.addHistory(patt, mask)
        self.__plugin.Settings.save()

        query = MakeBin(sig)
        result = BinSearch(query)

        #
        # Always logging tests to output
        #
        if result != BADADDR:
            self.__plugin.log('Sig matched @ 0x%X' % result.ea)
        else:
            self.__plugin.log('No match found')

    def _sigTestSelectChanged(self, index):

        mask = ''
        try:
            mask = self.__plugin.Settings.getHistory()[index][1]
        except:
            pass

        self.mask.setText(mask)

    def _sigCurrentFunction(self):
        self.__plugin.SigMaker.AutoFunction()

    def _sigAtCursor(self):
        self.__plugin.SigMaker.AutoAddress()

    def _logLevelChanged(self, index):
        self.__plugin.Settings.LogLevel = index
        self.__plugin.Settings.save()

    def _sigSelectChanged(self, index):
        self.__plugin.Settings.SigSelect = index
        self.__plugin.Settings.save()

    def _safeDataChecked(self, checkedState):
        #
        # Checkboxes can be tristate so passed arg is not a bool
        #
        if checkedState == QtCore.Qt.Unchecked:
            self.__plugin.Settings.bOnlyReliable = False
        else:
            self.__plugin.Settings.bOnlyReliable = True

        self.__plugin.Settings.save()

    def _dockSettingChanged(self, checkedState):
        if checkedState == QtCore.Qt.Unchecked:
            self.__plugin.Settings.bAutoDock = False
            self.__plugin.Settings.saveFormGeometry(True)
        else:
            self.__plugin.Settings.bAutoDock = True

        self.__plugin.Settings.save()
        self._formState(False)

    def _saveSettings(self):
        self.__plugin.Settings.save()
        self._formState(True)

    def _resetSettings(self):
        self.__plugin.Settings.reset(True)
        ida_kernwin.warning("IDA restart required due to settings reset")

    def _archiveSigmaker(self):

        global PLUGIN_DIR, HOTKEY_CONFLICT, SIGMAKER_X64_PLUGINS

        bDidMove = False

        for name in SIGMAKER_X64_PLUGINS:

            if not os.path.exists('%s/orig_sigmaker' % PLUGIN_DIR):
                self.__plugin.log('mkdir: %s/orig_sigmaker' % (PLUGIN_DIR))
                os.mkdir('%s/orig_sigmaker' % PLUGIN_DIR)

            if os.path.isfile('%s/%s' % (PLUGIN_DIR, name)):
                shutil.move('%s/%s' % (PLUGIN_DIR, name), '%s/orig_sigmaker/%s' % (PLUGIN_DIR, name))
                bDidMove = True
                self.__plugin.log('Moved: %s/%s to %s/orig_sigmaker/%s' % (PLUGIN_DIR, name, PLUGIN_DIR, name))

        if bDidMove:
            self.__plugin.log('SigMaker-x64 archived, restart IDA to unload it')
            HOTKEY_CONFLICT = False
            SIGMAKER_X64_PLUGINS = []
            self.archiveBtn.setEnabled(False)

    def _saveHotkey(self):
        hotkey = self.hotkeyTxt.text()
        if hotkey != self.__plugin.Settings.hotkey:
            self.__plugin.Settings.hotkey = hotkey
            self.__plugin.Settings.save()
            self.__plugin.log('\npySigMaker hotkey changed to %s, IDA restart needed.' % hotkey)

    def _defaultHotkey(self):
        global PLUGIN_HOTKEY
        self.hotkeyTxt.setText(PLUGIN_HOTKEY)
        if PLUGIN_HOTKEY != self.__plugin.Settings.hotkey:
            self.__plugin.Settings.hotkey = PLUGIN_HOTKEY
            self.__plugin.Settings.save()
            self.__plugin.log('\npySigMaker hotkey changed to %s (default), IDA restart needed.' % PLUGIN_HOTKEY)

    def _get_root_widget(self, plugin_widget):

            parent = plugin_widget
            widget = None

            # follow parent tree
            while parent:
                widget = parent
                parent = parent.parent()

            return widget

    def _find_widget_by_title(self, obj, titleName):
        """
            Locate widget by title
        """
        try: 
            titleName = obj.windowTitle()
            return obj
        except: 
            pass

        for child in obj.children():
            found = self._find_widget_by_name(child, name)
            if found:
                return found

        return None

    def _find_widget_by_name(self, obj, objName):
        """
            Locate widget by name
        """
        objName = obj.objectName()

        if objName == objName:
            return obj

        for child in obj.children():
            found = self._find_widget_by_name(child, name)
            if found:
                return found

        return None

    def _getWidget(self):
        widget, parent = None, self.widget
        while parent:
            if parent.windowTitle() == self.widget.windowTitle():
                widget = parent
            parent = parent.parent()
        return widget

    #
    # Save/Restore plugin form position and size.
    #
    def _formState(self, bSave=False):

        if not self._showed_banner:
            ida_kernwin.msg_clear()
            banner(self.__plugin.Settings.hotkey)

        if self.__plugin.Settings.bAutoDock:
            ida_kernwin.set_dock_pos("pySigMaker", "Output window", ida_kernwin.DP_RIGHT) 

        widget = self._getWidget()
        if not widget:
            self.__plugin.log('Failed to get form widget')
            return

        self.__plugin.Settings.setWidget(widget)

        if bSave:
            self.__plugin.Settings.saveFormGeometry()
            if self.__plugin.Settings.bAutoDock:
                widget.setMaximumSize(self.__plugin.Settings.w, self.__plugin.Settings.h)
            else:
                widget.resize(self.__plugin.Settings.w, self.__plugin.Settings.h)
        else:
            x, y, w, h = self.__plugin.Settings.getFormInfo()
            if self.__plugin.Settings.bAutoDock:
                if w > -1:
                    widget.setMaximumSize(w, h)
            else:
                widget.setMaximumSize(800, 800)
                widget.resize(self.__plugin.Settings.w, self.__plugin.Settings.h)

            self.patt.setCurrentText('')

            

    #
    # QT widget creation
    #
    def _getSigTypesBox(self):
        """ Sig type selector"""

        setting = self.__plugin.Settings.SigType

        grp = QtWidgets.QGroupBox("Sig Type")

        r1 = QtWidgets.QRadioButton(" IDA ")
        r2 = QtWidgets.QRadioButton(" Code ")
        r3 = QtWidgets.QRadioButton(" Olly ")

        r1.toggled.connect(self._sigTypeIdaClick)
        r2.toggled.connect(self._sigTypeCodeClick)
        r3.toggled.connect(self._sigTypeOllyClick)

        if setting == SigType.SIG_IDA:
            r1.setChecked(True)
        elif setting == SigType.SIG_CODE:
            r2.setChecked(True)
        elif setting == SigType.SIG_OLLY:
            r3.setChecked(True)

        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(r1)
        layout.addWidget(r2)
        layout.addWidget(r3)

        grp.setLayout(layout)

        return grp

    def _initSettings(self, layout):

        global HOTKEY_CONFLICT

        formLayout = QtWidgets.QFormLayout()
        #
        # Log to output window options
        #
        self.logOpt = QtWidgets.QComboBox()
        for s in ['Errors/Results', 'Debug']:
            self.logOpt.addItem(s)

        if self.__plugin.Settings.LogLevel > LogOptions.LOG_DEBUG:
            self.__plugin.Settings.LogLevel = LogOptions.LOG_DEBUG
        elif self.__plugin.Settings.LogLevel < LogOptions.LOG_RESULT:
            self.__plugin.Settings.LogLevel = LogOptions.LOG_RESULT

        self.logOpt.setCurrentIndex(self.__plugin.Settings.LogLevel)
        self.logOpt.currentIndexChanged.connect(self._logLevelChanged)

        #
        # Selecting sig from results options
        #
        self.sigSelectorOpt = QtWidgets.QComboBox()
        for s in ['Shortest Sig', 'Least Opcodes', 'Least Wildcards']:
            self.sigSelectorOpt.addItem(s)

        if self.__plugin.Settings.SigSelect > SigSelect.OPT_WILDCARDS:
            self.__plugin.Settings.SigSelect = SigSelect.OPT_WILDCARDS
        elif self.__plugin.Settings.SigSelect < SigSelect.OPT_LENGTH:
            self.__plugin.Settings.SigSelect = SigSelect.OPT_LENGTH

        self.sigSelectorOpt.setCurrentIndex(self.__plugin.Settings.SigSelect)
        self.sigSelectorOpt.currentIndexChanged.connect(self._sigSelectChanged)

        #
        # Reliable/Unreliable data option
        #
        self.safeData = QtWidgets.QCheckBox()
        self.safeData.setTristate(False)

        if self.__plugin.Settings.bOnlyReliable:
            self.safeData.setCheckState(QtCore.Qt.Checked)
        else:
            self.safeData.setCheckState(QtCore.Qt.Unchecked)

        self.safeData.stateChanged.connect(self._safeDataChecked)

        self.autoDock = QtWidgets.QCheckBox()
        self.autoDock.setTristate(False)

        if self.__plugin.Settings.bAutoDock:
            self.autoDock.setCheckState(QtCore.Qt.Checked)
        else:
            self.autoDock.setCheckState(QtCore.Qt.Unchecked)
        self.autoDock.stateChanged.connect(self._dockSettingChanged)

        if HOTKEY_CONFLICT:
            self.archiveBtn = QtWidgets.QPushButton('Archive SigMaker-x64')
            self.archiveBtn.clicked.connect(self._archiveSigmaker)

        formLayout.addRow('Output', self.logOpt)
        formLayout.addRow('Sig Choice', self.sigSelectorOpt)
        formLayout.addRow('Reliable Data Only', self.safeData)
        formLayout.addRow('Auto Dock', self.autoDock)
        layout.addLayout(formLayout)

        self.saveSettingsBtn = QtWidgets.QPushButton('Save Settings')
        self.saveSettingsBtn.clicked.connect(self._saveSettings)
        self.resetSettingsBtn = QtWidgets.QPushButton('Reset Settings')
        self.resetSettingsBtn.clicked.connect(self._resetSettings)
        
        layoutSettings = QtWidgets.QHBoxLayout()
        layoutSettings.addWidget(self.saveSettingsBtn)
        layoutSettings.addWidget(self.resetSettingsBtn)
        layout.addLayout(layoutSettings)
        

        layout2 = QtWidgets.QHBoxLayout()

        lbl = QtWidgets.QLabel('Hotkey:')

        self.hotkeyTxt = QtWidgets.QLineEdit()
        self.hotkeyTxt.setText(self.__plugin.Settings.hotkey)
        self.hotkeySetBtn = QtWidgets.QPushButton('Set')
        self.hotkeyRestoreBtn = QtWidgets.QPushButton('Default')
        self.hotkeySetBtn.clicked.connect(self._saveHotkey)
        self.hotkeyRestoreBtn.clicked.connect(self._defaultHotkey)

        layout2.addWidget(lbl)
        layout2.addWidget(self.hotkeyTxt)
        layout2.addWidget(self.hotkeySetBtn)
        layout2.addWidget(self.hotkeyRestoreBtn)

        layout.addLayout(layout2)

        if HOTKEY_CONFLICT:
            layout.addWidget(self.archiveBtn)

    def _initMainTab(self):

        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        btn1 = QtWidgets.QPushButton('  Sig for current function  ')
        btn2 = QtWidgets.QPushButton('  Sig at current cursor position  ')

        btn1.clicked.connect(self._sigCurrentFunction)
        btn2.clicked.connect(self._sigAtCursor)

        layout.addWidget(btn1)
        layout.addWidget(btn2)
        layout.addWidget(self._getSigTypesBox())

        tab.setLayout(layout)
        self.tabControl.addTab(tab, 'Create Sigs')

    def _initSigTest(self):

        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()

        # Need refs to patt and mask controls
        self.patt = QtWidgets.QComboBox()
        self.patt.setEditable(True)
        self.patt.setCurrentText("")

        self.mask = QtWidgets.QLineEdit()
        self.mask.setText("")

        self.patt.setInsertPolicy(QtWidgets.QComboBox.NoInsert)

        sigs = [ x[0] for x in self.__plugin.Settings.getHistory() ]
        self.patt.addItems(sigs)

        btn = QtWidgets.QPushButton(' Test ')
        btn.clicked.connect(self._sigTest)

        self.patt.currentIndexChanged.connect(self._sigTestSelectChanged)

        layout.addRow('Patt', self.patt)
        layout.addRow('Mask', self.mask)
        layout.addRow('', btn)

        tab.setLayout(layout)
        self.tabControl.addTab(tab, 'Test Sigs')

    def _initSettingsTab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        self._initSettings(layout)
        tab.setLayout(layout)
        self.tabControl.addTab(tab, 'Settings')

    def PopulateForm(self):

        layout = QtWidgets.QVBoxLayout()
        self.tabControl = QtWidgets.QTabWidget(self.widget)
        layout.addWidget(self.tabControl)
        self.widget.setLayout(layout)

        self._initMainTab()
        self._initSigTest()
        self._initSettingsTab()

        if self._QtDbgHelper:
           self._QtDbgHelper.initDebugTab()

        return


#
# Shared settings class
#
class PluginSettings:

    def __init__(self, plugin):

        global PLUGIN_HOTKEY

        self.__plugin     = plugin
        self.__loaded     = False
        self.__configName = idaapi.get_user_idadir() + '\\pySigMaker.config'
        self.__widget = None

        self.reset()

    def setWidget(self, widget):
        self.__widget = widget

    def reset(self, bSave = False):

        # 0 disables limit
        self.maxRefs = 0

        # False creates less reliable sigs IE: they break easier on updates
        self.bOnlyReliable = True

        # True causes form to auto dock to right of Output window
        self.bAutoDock = True

        # Controls how sig is selected from multiple unique sigs
        self.SigSelect = SigSelect.OPT_LENGTH

        # Type of sig to return
        self.SigType = SigType.SIG_IDA

        self.LogLevel = LogOptions.LOG_RESULT

        # Max sig length IE: 'E9 ?' is length of 2
        self.maxSigLength = 100

        # Sig test history, keeps last 10 tested sigs
        self._history = []

        # default hot key
        self.hotkey = PLUGIN_HOTKEY

        # form info
        self.x = -1
        self.y = -1
        self.w = -1
        self.h = -1

        if bSave:
            self.save()

    def saveFormGeometry(self, reset=False):
        if reset:
            self.x, self.y, self.w, self.h = -1, -1, -1, -1
        else:
            qrect = self.__widget.geometry()
            self.x, self.y, self.w, self.h = qrect.x(), qrect.y(), qrect.width(), qrect.height()

    def getFormInfo(self):
        return self.x, self.y, self.w, self.h

    def getHistory(self):
        return self._history

    def addHistory(self, sig, mask=''):

        # Move to front of list when used, limit history to last 10 entries
        hist = [[sig, mask]]

        for p, m in self._history:
            if p == sig:
                continue
            hist.append([p, m])
            if len(hist) == 10:
                break

        self._history = hist

    def load(self):

        if self.__loaded:
            return

        if not os.path.exists(self.__configName):
            self.__plugin.log('pySigMaker: Using defaults')
            return False

        if not os.path.isfile(self.__configName):
            self.__plugin.log('pySigMaker: Using defaults')
            return False


        d  = {}
        fh = None

        try:
            fh = open(self.__configName, 'rb')
            d = pickle.load(fh)
        except:
            self.__plugin.log('pySigMaker: Cfg corrupt, using defaults')

        if fh:
            fh.close()

        for k, v in d.items():
            if k in self.__dict__:
                self.__dict__[k] = v
                self.__plugin.log('cfg-load: {0} {1} {2}'.format(k, v, type(v)), LogOptions.LOG_DEBUG)

        self.__loaded = True
        return d != {}

    def save(self):

        d = {}
        for k, v in self.__dict__.items():
            if k.find('__') > -1:
                continue
            d[k] = v
            self.__plugin.log('cfg-save: {0} {1} {2}'.format(k, v, type(v)), LogOptions.LOG_DEBUG)

        fh = None

        try:
            fh = open(self.__configName, 'wb')
            pickle.dump(d, fh)
        except:
            self.__plugin.log('pySigMaker: Failed to save config')

        if fh:
            fh.close()

class SigMakerPlugin:

    def __init__(self):
        self.Settings = PluginSettings(self)
        self.Gui = PluginGui(self)
        self.SigMaker = SigMaker(self)
        self.Settings.load()

    def log(self, msg, log_level = LogOptions.LOG_RESULT):
        # Changed so error and output are always shown
        # LOG_DEBUG is the only one optional now.
        if log_level <= LogOptions.LOG_RESULT or log_level <= self.Settings.LogLevel:
            print(msg)

    def showGui(self):
        if not self.Gui or self.Gui.closed:
            self.Gui = PluginGui(self)
        self.Gui.Show('pySigMaker')


#
# IDA Plugin Loader
#

gsigmaker = SigMakerPlugin()

class sigmaker_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    #flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE

    comment = 'Create signatures for run time pattern matching.'
    help = ''
    wanted_name = 'pySigMaker'
    wanted_hotkey = gsigmaker.Settings.hotkey

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg=None):
        gsigmaker.showGui()       
        

    def term(self):
        global gsigmaker
        gsigmaker = None
        if hasattr(self, 'hook'):
            self.hook.unhook()

def PLUGIN_ENTRY():
    return sigmaker_t()
